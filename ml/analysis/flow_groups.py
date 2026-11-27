"""같은 명령 흐름을 가진 세션을 묶고, 그 묶음이 얼마나 많은 IP에서 왔는지(집중도)를 본다.

'캠페인 묶기'의 가벼운 형태: 정규화한 명령 시퀀스(ml/cluster.py의 normalize_session)가 같은 세션을 한 묶음으로 보고,
묶음마다 IP 수·최다 IP 점유율·기간·출처·ML 군집·같은 파일 해시/다운로드 서버 공유 여부를 계산한다.

사용법 (저장소 루트에서):
    python ml/analysis/flow_groups.py --data-dir data/dashboard [--out work/flow_groups]
        [--min-steps 3] [--min-sessions 2]

입력(읽기 전용): <data-dir>/ml.db (sessions, commands, ml_clusters, ml_meta),
                 <data-dir>/dashboard.db (hits, meta, sources, file_events)
출력: <out>/ 아래 flow_groups.csv, payload_links.csv, report.md, run_meta.json

해석 주의: 같은 명령 흐름은 '같은 흔적을 공유한다'는 뜻이지 같은 행위자라는 뜻이 아니다. 공개된 봇 스크립트를
여러 곳에서 쓸 수 있다. 집중도 라벨은 임계값 기반 힌트일 뿐이다. 로그의 명령은 문자열로만 다루며 실행하지 않는다.
리포트와 CSV에는 전체 IP를 쓰지 않고(a.b.x.x), URL은 hxxp로, 다운로드 서버 주소는 [.]로 바꿔 쓴다.
"""
import argparse
import csv
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from contextlib import closing
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.analysis.rule_combo_clusters import open_readonly  # noqa: E402
from ml.cluster import load_sessions, normalize_session  # noqa: E402

SEQ_SHOW = 200
FEW_IPS_MAX = 5          # IP가 이 이하이거나
FEW_TOP_SHARE = 0.5      # 최다 IP 점유율이 이 이상이면 '소수 IP 반복'
SPREAD_MIN_IPS = 20      # IP가 이 이상이고
SPREAD_TOP_SHARE = 0.2   # 최다 IP 점유율이 이 미만이면 '분산'

FEW, SPREAD, MIXED = "few_ips", "distributed", "mixed"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "0.0.0.0"}


def mask_ip(ip):
    parts = str(ip or "").split(".")
    return f"{parts[0]}.{parts[1]}.x.x" if len(parts) == 4 else "?"


def defang_text(text):
    return re.sub(r"(?i)http", lambda m: "hxxp" if m.group(0).islower() else "HXXP", text)


def defang_host(host):
    return host.replace(".", "[.]")


def clip(text, n=SEQ_SHOW):
    return text if len(text) <= n else text[:n] + "…"


def concentration(n_ips, top_share):
    if n_ips <= FEW_IPS_MAX or top_share >= FEW_TOP_SHARE:
        return FEW
    if n_ips >= SPREAD_MIN_IPS and top_share < SPREAD_TOP_SHARE:
        return SPREAD
    return MIXED


# ---------- 읽기 ----------

def has_table(con, schema, name):
    return bool(con.execute(f"SELECT 1 FROM {schema}.sqlite_master WHERE name = ?", (name,)).fetchone())


def load_rows(con):
    """세션마다 정규화 시퀀스·IP·시작일·군집·탐지 규칙·파일 해시·다운로드 서버를 모은다."""
    cmds = load_sessions(con)
    clusters = {(s, sid): int(c) for s, sid, c in con.execute("SELECT source, session_id, cluster_id FROM ml_clusters")}
    hits = defaultdict(set)
    for s, sid, rid in con.execute("SELECT source, session_id, rule_id FROM dash.hits"):
        hits[(s, sid)].add(rid)
    hashes, hosts = defaultdict(set), defaultdict(set)
    has_files = has_table(con, "dash", "file_events")
    if has_files:
        for s, sid, url, sh in con.execute("SELECT source, session_id, url, shasum FROM dash.file_events"):
            if sh:
                hashes[(s, sid)].add(sh)
            if url:
                host = urlparse(url if "://" in url else "http://" + url).hostname
                if host and host not in LOCAL_HOSTS:
                    hosts[(s, sid)].add(host)
    rows = []
    for key, s in cmds.items():
        rows.append({
            "source": key[0], "session_id": key[1], "protocol": s["protocol"], "ip": s["src_ip"],
            "day": (s["ts"][0] or "")[:10], "seq": normalize_session(s["cmds"]),
            "cluster": clusters.get(key), "rules": hits.get(key, set()),
            "hashes": hashes.get(key, set()), "hosts": hosts.get(key, set()),
        })
    return rows, has_files


def load_meta(con, data_dir, has_files):
    ml_meta = dict(con.execute("SELECT key, value FROM ml_meta").fetchall())
    dash_meta = dict(con.execute("SELECT key, value FROM dash.meta").fetchall())
    sources = [dict(zip(("source", "has_raw_logs", "first_event", "last_event"), r)) for r in con.execute(
        "SELECT source, has_raw_logs, first_event, last_event FROM dash.sources ORDER BY source")]
    return {"data_dir": str(Path(data_dir).resolve()), "ml": ml_meta,
            "dashboard": {k: dash_meta.get(k) for k in ("built_at", "rules_sha256", "rules_commit")},
            "sources": sources, "has_file_events": has_files,
            "note": "원본 로그가 없는 출처(has_raw_logs=0)는 파일·서버 정보가 비어 있어 두 출처를 같은 기준으로 비교할 수 없다."}


# ---------- 분석 ----------

def analyze(rows, min_steps=3, min_sessions=2):
    groups = defaultdict(list)
    skipped_short = 0
    for r in rows:
        if len(r["seq"]) < min_steps:
            skipped_short += 1
            continue
        groups[(r["protocol"], r["seq"])].append(r)

    out = []
    for (proto, seq), rs in groups.items():
        if len(rs) < min_sessions:
            continue
        ips = Counter(r["ip"] for r in rs if r["ip"])
        top_ip, top_n = ips.most_common(1)[0] if ips else (None, 0)
        share = top_n / len(rs)
        days = sorted({r["day"] for r in rs if r["day"]})
        rule_count = Counter(x for r in rs for x in r["rules"])
        out.append({
            "group_id": sha256(repr((proto, seq)).encode("utf-8")).hexdigest()[:10],
            "protocol": proto, "sessions": len(rs), "ips": len(ips), "top_ip": mask_ip(top_ip),
            "top_ip_share": round(share, 3), "days": len(days),
            "first_day": days[0] if days else "", "last_day": days[-1] if days else "",
            "sources": ";".join(f"{k}:{v}" for k, v in sorted(Counter(r["source"] for r in rs).items())),
            "clusters": ";".join(f"{k}:{v}" for k, v in Counter(r["cluster"] for r in rs).most_common(3)),
            "rules": ",".join(sorted(x for x, n in rule_count.items() if n >= len(rs) / 2)),
            "hashes": len({h for r in rs for h in r["hashes"]}),
            "servers": len({h for r in rs for h in r["hosts"]}),
            "payload_sessions": sum(1 for r in rs if r["hashes"] or r["hosts"]),
            "concentration": concentration(len(ips), share),
            "flow": clip(defang_text(" ; ".join(seq))),
            # 화면(IOC 페이지는 차단 목록용이라 IP를 가리지 않는다)에서만 쓴다. CSV·리포트에는 쓰지 않는다.
            "top_ip_raw": top_ip, "ips_raw": sorted(ips),
        })
    out.sort(key=lambda g: (-g["sessions"], g["group_id"]))

    # 같은 파일 해시·다운로드 서버를 공유한 세션 묶음 (명령 흐름이 달라도 연결된다)
    by_trace = defaultdict(list)
    for r in rows:
        for h in r["hashes"]:
            by_trace[("hash", h)].append(r)
        for h in r["hosts"]:
            by_trace[("server", h)].append(r)
    seq_to_gid = {}
    for (proto, seq), rs in groups.items():
        if len(rs) >= min_sessions:
            seq_to_gid[(proto, seq)] = sha256(repr((proto, seq)).encode("utf-8")).hexdigest()[:10]
    links = []
    for (kind, value), rs in by_trace.items():
        n_ips = len({r["ip"] for r in rs if r["ip"]})
        if n_ips < 2:
            continue
        gids = {seq_to_gid.get((r["protocol"], r["seq"])) for r in rs} - {None}
        days = sorted({r["day"] for r in rs if r["day"]})
        links.append({"kind": kind, "value": defang_host(value) if kind == "server" else value,
                      "sessions": len(rs), "ips": n_ips, "days": len(days),
                      "sources": ";".join(f"{k}:{v}" for k, v in sorted(Counter(r["source"] for r in rs).items())),
                      "flow_groups": len(gids)})
    links.sort(key=lambda x: (-x["ips"], -x["sessions"], x["kind"], x["value"]))

    in_groups = sum(g["sessions"] for g in out)
    summary = {
        "sessions_with_commands": len(rows), "skipped_short": skipped_short, "min_steps": min_steps,
        "min_sessions": min_sessions, "groups": len(out), "sessions_in_groups": in_groups,
        "by_concentration": {k: {"groups": sum(1 for g in out if g["concentration"] == k),
                                 "sessions": sum(g["sessions"] for g in out if g["concentration"] == k)}
                             for k in (FEW, SPREAD, MIXED)},
        "payload_links": len(links),
    }
    return out, links, summary


# ---------- 출력 ----------

LABEL = {FEW: "소수 IP 반복", SPREAD: "분산", MIXED: "중간"}
GROUP_FIELDS = ["group_id", "protocol", "sessions", "ips", "top_ip", "top_ip_share", "days", "first_day", "last_day",
                "sources", "clusters", "rules", "hashes", "servers", "payload_sessions", "concentration", "flow"]
LINK_FIELDS = ["kind", "value", "sessions", "ips", "days", "sources", "flow_groups"]


def cell(text):
    return str(text).replace("|", "/").replace("\n", " ")


def render_report(meta, summary, groups, links, generated_at, top=15):
    L = ["# 명령 흐름 묶음 × 집중도 (가벼운 캠페인 묶기)", "",
         f"- 생성: {generated_at} UTC · 데이터: `{meta['data_dir']}`",
         f"- ML 학습: {meta['ml'].get('trained_at', '?')} · 규칙 커밋: {meta['dashboard'].get('rules_commit', '?')}",
         "- 묶는 기준: 정규화한 명령 시퀀스(ml/cluster.py)가 같은 세션 (프로토콜 구분, "
         f"{summary['min_steps']}단계 이상, 묶음당 {summary['min_sessions']}세션 이상)", "",
         "## 읽는 법과 한계", "",
         "- **같은 흔적을 공유한다는 뜻이다. 같은 행위자라는 뜻이 아니다.** 공개 봇 스크립트는 여러 곳에서 쓰일 수 있다.",
         f"- 집중도 라벨은 힌트다: 소수 IP 반복 = IP {FEW_IPS_MAX}개 이하 또는 최다 IP 점유 {FEW_TOP_SHARE:.0%} 이상, "
         f"분산 = IP {SPREAD_MIN_IPS}개 이상이고 최다 IP 점유 {SPREAD_TOP_SHARE:.0%} 미만.",
         "- 정규화 때문에 숫자 등 일부 차이는 같은 흐름으로 본다. 한두 단계가 다른 변형은 별개 묶음이 된다.",
         "- 입력 관측이며 실행 성공이나 악성 여부를 판정하지 않는다. IP는 a.b.x.x로, URL은 hxxp로 표시했다.",
         f"- {meta['note']}", "",
         "## 요약", "",
         f"- 명령이 있는 세션 {summary['sessions_with_commands']:,}개 중 {summary['skipped_short']:,}개는 "
         f"{summary['min_steps']}단계 미만이라 제외했다.",
         f"- 묶음 {summary['groups']:,}개, 묶음에 속한 세션 {summary['sessions_in_groups']:,}개.", ""]
    L += ["| 집중도 | 묶음 수 | 세션 수 |", "|---|---:|---:|"]
    for k in (FEW, SPREAD, MIXED):
        v = summary["by_concentration"][k]
        L.append(f"| {LABEL[k]} | {v['groups']:,} | {v['sessions']:,} |")
    L += ["", f"## 큰 묶음 상위 {top}", "",
          "| # | 세션 | IP | 최다 IP 점유 | 기간(일) | 출처 | 군집 | 집중도 | 파일·서버 | 입력 흐름 |",
          "|---:|---:|---:|---:|---:|---|---|---|---|---|"]
    for i, g in enumerate(groups[:top], 1):
        L.append(f"| {i} | {g['sessions']:,} | {g['ips']:,} | {g['top_ip_share']:.0%} | {g['days']} | {cell(g['sources'])} | "
                 f"{cell(g['clusters'])} | {LABEL[g['concentration']]} | 해시 {g['hashes']} / 서버 {g['servers']} | "
                 f"{cell(clip(g['flow'], 110))} |")
    L += ["", "## 같은 파일 해시·다운로드 서버를 2개 이상 IP가 공유한 경우", ""]
    if not links:
        L.append("없음 (또는 이 데이터에는 파일·서버 정보가 없다).")
    else:
        L += ["| 종류 | 값 | 세션 | IP | 일수 | 출처 | 걸친 흐름 묶음 |", "|---|---|---:|---:|---:|---|---:|"]
        for x in links[:15]:
            L.append(f"| {x['kind']} | {cell(x['value'])} | {x['sessions']:,} | {x['ips']:,} | {x['days']} | "
                     f"{cell(x['sources'])} | {x['flow_groups']} |")
    L.append("")
    return "\n".join(L)


def write_all(out, meta, summary, groups, links, generated_at):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name, fields, data in (("flow_groups.csv", GROUP_FIELDS, groups), ("payload_links.csv", LINK_FIELDS, links)):
        with open(out / name, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(data)
    (out / "report.md").write_text(render_report(meta, summary, groups, links, generated_at), encoding="utf-8")
    (out / "run_meta.json").write_text(json.dumps({**meta, "summary": summary, "generated_at": generated_at},
                                                  ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", default="data/dashboard")
    p.add_argument("--out", default="work/flow_groups")
    p.add_argument("--min-steps", type=int, default=3, help="묶음 대상 최소 명령 단계 수 (기본 3)")
    p.add_argument("--min-sessions", type=int, default=2, help="결과에 싣는 묶음의 최소 세션 수 (기본 2)")
    a = p.parse_args(argv)
    data, out = Path(a.data_dir).resolve(), Path(a.out).resolve()
    if out == data or data in out.parents:
        sys.exit(f"출력 폴더({out})가 데이터 폴더({data}) 안에 있다. 원본을 보호하려고 중단한다")
    from datetime import datetime, timezone
    with closing(open_readonly(data)) as con:
        rows, has_files = load_rows(con)
        meta = load_meta(con, data, has_files)
    groups, links, summary = analyze(rows, a.min_steps, a.min_sessions)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    write_all(out, meta, summary, groups, links, generated_at)
    print(f"묶음 {summary['groups']:,}개, 파일·서버 공유 {summary['payload_links']}건 → {out}")


if __name__ == "__main__":
    main()
