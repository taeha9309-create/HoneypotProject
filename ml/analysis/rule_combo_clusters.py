"""같은 시그니처 규칙 조합을 가진 세션이 서로 다른 ML 군집에 나뉘는 사례를 찾아 명령 흐름을 비교한다.

사용법 (저장소 루트에서):
    python ml/analysis/rule_combo_clusters.py --data-dir data/dashboard [--out work/cross_cluster]
        [--ignore-rules B19] [--min-sessions 3]

입력(읽기 전용): <data-dir>/ml.db (ml_clusters, sessions, commands, ml_meta),
                 <data-dir>/dashboard.db (hits, meta, sources), <data-dir>/ml_out/cluster_summary.csv(있으면)
출력: <out>/ 아래 combo_clusters.csv, combo_comparison.csv, report.md, run_meta.json
      --ignore-rules를 주면 해당 규칙을 뺀 보조 분석을 *_ignoring_<규칙>.* 이름으로 함께 쓴다.

해석 주의: 같은 규칙 조합이 여러 군집에 나뉘었다는 것은 '확인할 후보'일 뿐이다. 군집 번호는 정답 라벨이 아니고,
이 도구는 새 공격 행동이라고 판정하지 않는다. 로그의 명령은 문자열로만 다루며 실행하지 않는다.
"""
import argparse
import csv
from collections import Counter, defaultdict
from contextlib import closing
from difflib import SequenceMatcher
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.cluster import load_sessions, normalize_session  # noqa: E402

NO_HITS = "(none)"                 # 이 분석의 규칙이 하나도 일치하지 않은 세션
ONLY_IGNORED = "(only-ignored)"    # 일치한 규칙이 모두 --ignore-rules 대상이라 비게 된 세션
SEQ_SHOW = 240                     # 리포트·CSV에 싣는 시퀀스 최대 길이
HIGH_OVERLAP = 0.8                 # 이 이상이면 '표현 차이 가능성', 미만이면 '행동 차이 가능성' (힌트일 뿐)

CASE_MULTI = "multi_cluster"                 # 실제 군집(>=0)이 2개 이상
CASE_ONE_PLUS_NOISE = "one_cluster_plus_noise"
CASE_ONE = "single_cluster"
CASE_NOISE_ONLY = "noise_only"


# ---------- 읽기 ----------

def open_readonly(data_dir):
    """ml.db를 읽기 전용으로 열고 dashboard.db를 같은 연결에 읽기 전용으로 붙인다."""
    data_dir = Path(data_dir).resolve()
    ml, dash = data_dir / "ml.db", data_dir / "dashboard.db"
    for p in (ml, dash):
        if not p.exists():
            raise FileNotFoundError(f"{p} 가 없다")
    con = sqlite3.connect(ml.as_uri() + "?mode=ro", uri=True)
    con.execute("ATTACH DATABASE ? AS dash", (dash.as_uri() + "?mode=ro",))
    con.execute("PRAGMA query_only = ON")
    return con


def load_rows(con):
    """ml_clusters 세션마다 (source, session_id, protocol, cluster_id, is_noise, 규칙 집합, 정규화 시퀀스, ip)."""
    hits = defaultdict(set)
    for source, sid, rule in con.execute("SELECT source, session_id, rule_id FROM dash.hits"):
        hits[(source, sid)].add(rule)
    cmds = load_sessions(con)
    rows = []
    for source, sid, protocol, cid, noise in con.execute(
            "SELECT source, session_id, protocol, cluster_id, is_noise FROM ml_clusters"):
        s = cmds.get((source, sid))
        rows.append({
            "source": source, "session_id": sid, "protocol": protocol, "cluster_id": int(cid),
            "is_noise": bool(noise) or cid == -1, "rules": frozenset(hits.get((source, sid), ())),
            "seq": normalize_session(s["cmds"]) if s else (), "ip": s["src_ip"] if s else None,
        })
    return rows


def load_meta(con, data_dir, rules_path):
    ml_meta = dict(con.execute("SELECT key, value FROM ml_meta").fetchall())
    dash_meta = dict(con.execute("SELECT key, value FROM dash.meta").fetchall())
    sources = [dict(zip(("source", "first_event", "last_event"), r))
               for r in con.execute("SELECT source, first_event, last_event FROM dash.sources ORDER BY source")]
    current = sha256(Path(rules_path).read_bytes()).hexdigest() if Path(rules_path).exists() else None
    return {
        "data_dir": str(Path(data_dir).resolve()),
        "ml": ml_meta,
        "dashboard": {k: dash_meta.get(k) for k in ("built_at", "rules_sha256", "rules_commit")},
        "sources": sources,
        "current_rules_sha256": current,
        "rules_match_db": current is not None and current == dash_meta.get("rules_sha256"),
        "note": "출처별 수집 기간이 다르고 마지막 날은 부분 수집일 수 있다. 이 분석은 기간 차이를 보정하지 않는다.",
    }


def load_representatives(data_dir):
    path = Path(data_dir) / "ml_out" / "cluster_summary.csv"
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        return {(r["protocol"], int(r["cluster_id"])): r["representative"] for r in csv.DictReader(f)}


# ---------- 분석 ----------

def combo_of(rules, ignore=frozenset()):
    kept = sorted(rules - ignore)
    if kept:
        return "+".join(kept)
    return ONLY_IGNORED if rules else NO_HITS


def clip(text, n=SEQ_SHOW):
    return text if len(text) <= n else text[:n] + "…"


def verbs(parts):
    return {p.split()[0] for p in parts if p.split()}


def analyze(rows, ignore=frozenset(), min_sessions=3, representatives=None):
    """(protocol, 규칙 조합) 단위로 군집 분포를 만들고, 실제 군집이 2개 이상인 조합의 군집 쌍을 비교한다."""
    representatives = representatives or {}
    cells = defaultdict(lambda: {"n": 0, "sources": Counter(), "ips": set(), "seqs": Counter(), "parts": set()})
    for r in rows:
        c = cells[(r["protocol"], combo_of(r["rules"], ignore), r["cluster_id"])]
        c["n"] += 1
        c["sources"][r["source"]] += 1
        if r["ip"]:
            c["ips"].add(r["ip"])
        c["seqs"][r["seq"]] += 1
        c["parts"].update(r["seq"])

    by_combo = defaultdict(list)
    for (proto, combo, cid), c in cells.items():
        by_combo[(proto, combo)].append((cid, c))

    cluster_rows, case_of = [], {}
    for (proto, combo), items in by_combo.items():
        real = [cid for cid, _ in items if cid >= 0]
        noise = sum(c["n"] for cid, c in items if cid < 0)
        if len(real) >= 2:
            case = CASE_MULTI
        elif len(real) == 1:
            case = CASE_ONE_PLUS_NOISE if noise else CASE_ONE
        else:
            case = CASE_NOISE_ONLY
        case_of[(proto, combo)] = case
        total = sum(c["n"] for _, c in items)
        for cid, c in sorted(items, key=lambda x: (x[0] < 0, -x[1]["n"])):
            top, top_n = c["seqs"].most_common(1)[0]
            cluster_rows.append({
                "protocol": proto, "rule_combo": combo, "case": case, "cluster_id": cid,
                "is_noise": int(cid < 0), "sessions": c["n"], "share_of_combo": round(c["n"] / total, 3),
                "seoul": c["sources"].get("seoul", 0), "syd": c["sources"].get("syd", 0),
                "other_sources": sum(v for k, v in c["sources"].items() if k not in ("seoul", "syd")),
                "ips": len(c["ips"]), "top_seq_share": round(top_n / c["n"], 3),
                "top_seq": clip(" ; ".join(top)),
                "cluster_representative": clip(representatives.get((proto, cid), "")),
            })

    pairs = []
    for (proto, combo), items in by_combo.items():
        if case_of[(proto, combo)] != CASE_MULTI:
            continue
        eligible = sorted(((cid, c) for cid, c in items if cid >= 0 and c["n"] >= min_sessions), key=lambda x: x[0])
        for i, (a, ca) in enumerate(eligible):
            for b, cb in eligible[i + 1:]:
                ta, tb = ca["seqs"].most_common(1)[0][0], cb["seqs"].most_common(1)[0][0]
                union = ca["parts"] | cb["parts"]
                jac = len(ca["parts"] & cb["parts"]) / len(union) if union else 1.0
                sim = SequenceMatcher(None, ta, tb, autojunk=False).ratio()
                va, vb = verbs(ca["parts"]), verbs(cb["parts"])
                same = ta == tb
                hint = ("대표 시퀀스 동일 — 차이는 일부 세션에서만 나타남, 확인 필요" if same else
                        "표현 차이 가능성 — 확인 필요" if min(jac, sim) >= HIGH_OVERLAP else
                        "행동 차이 가능성 — 확인 필요")
                pairs.append({
                    "protocol": proto, "rule_combo": combo, "cluster_a": a, "cluster_b": b,
                    "sessions_a": ca["n"], "sessions_b": cb["n"],
                    "top_seq_similarity": round(sim, 3), "command_set_jaccard": round(jac, 3),
                    "same_top_seq": int(same),
                    "only_in_a": " ".join(sorted(va - vb)[:10]), "only_in_b": " ".join(sorted(vb - va)[:10]),
                    "top_seq_a": clip(" ; ".join(ta)), "top_seq_b": clip(" ; ".join(tb)),
                    "review_hint": hint,
                })
    pairs.sort(key=lambda p: (p["protocol"], -(p["sessions_a"] + p["sessions_b"]), p["rule_combo"]))
    cluster_rows.sort(key=lambda r: (r["protocol"], r["case"] != CASE_MULTI, -sum(
        x["sessions"] for x in cluster_rows if x["protocol"] == r["protocol"] and x["rule_combo"] == r["rule_combo"]),
        r["rule_combo"], r["is_noise"], -r["sessions"]))

    n = len(rows)
    no_hit = sum(1 for r in rows if not r["rules"])
    summary = {
        "ml_sessions": n, "sessions_without_hits": no_hit,
        "with_hits": n - no_hit,
        "ignored_rules": sorted(ignore),
        "min_sessions": min_sessions,
        "cases": dict(Counter(case_of.values())),
        "combos": len(case_of),
        "sessions_in_multi_cluster_combos": sum(r["sessions"] for r in cluster_rows if r["case"] == CASE_MULTI),
        "no_hit_by_cluster": [
            {"protocol": r["protocol"], "cluster_id": r["cluster_id"], "sessions": r["sessions"]}
            for r in cluster_rows if r["rule_combo"] == NO_HITS],
    }
    return cluster_rows, pairs, summary


# ---------- 출력 ----------

def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def render_report(meta, summary, cluster_rows, pairs, title):
    L = [f"# {title}", "",
         "> **이 문서는 확인할 후보 목록이다.** 같은 규칙 조합이 다른 군집에 속했다고 해서 새로운 공격 행동이라는 뜻은 아니다. "
         "군집 번호는 이번 학습 실행에서만 의미가 있는 임시 번호이며 정답 라벨이 아니다. "
         "'시그니처 일치 비율'은 탐지 정확도가 아니다. 명령은 공격자가 입력한 문자열이며 실행하지 않았다.", "",
         "## 입력 버전", "",
         f"- 데이터 폴더: `{meta['data_dir']}`",
         f"- ML: 학습 {meta['ml'].get('trained_at')}, 파라미터 `{meta['ml'].get('params')}`, 정규화 버전 {meta['ml'].get('normalize_version')}, 출처 {meta['ml'].get('sources')}",
         f"- 시그니처 결과: rules commit `{meta['dashboard'].get('rules_commit')}`, rules sha256 `{str(meta['dashboard'].get('rules_sha256'))[:12]}…`, "
         f"현재 `rules.yaml`과 {'**일치**' if meta['rules_match_db'] else '**불일치 — 결과가 현재 규칙과 다를 수 있음**'}"]
    for s in meta["sources"]:
        L.append(f"- 수집 기간 {s['source']}: {s['first_event']} ~ {s['last_event']} (UTC, 마지막 날은 부분 수집일 수 있음)")
    L += ["", "## 요약", "",
          f"- ML 세션 {summary['ml_sessions']:,}개, 시그니처 일치 {summary['with_hits']:,}개, **시그니처 없음 {summary['sessions_without_hits']:,}개**",
          f"- 제외한 규칙: {', '.join(summary['ignored_rules']) or '없음'} · 비교 최소 세션 수: {summary['min_sessions']}",
          f"- (프로토콜, 규칙 조합) {summary['combos']}개 중 실제 군집 2개 이상에 걸친 조합 {summary['cases'].get(CASE_MULTI, 0)}개 "
          f"({summary['sessions_in_multi_cluster_combos']:,}세션)",
          f"- 실제 군집 1개 + 노이즈: {summary['cases'].get(CASE_ONE_PLUS_NOISE, 0)}개 조합 (별도 표시)", ""]
    if summary["no_hit_by_cluster"]:
        L += ["### 시그니처 없는 세션의 군집 분포", "", "| 프로토콜 | 군집 | 세션 |", "|---|---|---|"]
        L += [f"| {r['protocol']} | {r['cluster_id'] if r['cluster_id'] >= 0 else '노이즈(-1)'} | {r['sessions']} |"
              for r in summary["no_hit_by_cluster"]]
        L.append("")
    multi = [(p, c) for p, c in dict.fromkeys((r["protocol"], r["rule_combo"]) for r in cluster_rows
                                                 if r["case"] == CASE_MULTI)]
    L += ["## 다중 군집 사례", ""]
    if not multi:
        L += ["해당 없음.", ""]
    for proto, combo in multi:
        cl = [r for r in cluster_rows if r["protocol"] == proto and r["rule_combo"] == combo]
        L += [f"### {proto.upper()} · `{combo}` ({sum(r['sessions'] for r in cl):,}세션)", "",
              "| 군집 | 세션 | 서울 | 시드니 | IP | 대표 시퀀스(정규화, 최빈) |", "|---|---|---|---|---|---|"]
        for r in cl:
            name = "노이즈(-1)" if r["is_noise"] else str(r["cluster_id"])
            L.append(f"| {name} | {r['sessions']} | {r['seoul']} | {r['syd']} | {r['ips']} | `{r['top_seq'].replace('|', '/')}` "
                     f"({r['top_seq_share']:.0%}) |")
        pp = [p for p in pairs if p["protocol"] == proto and p["rule_combo"] == combo]
        if pp:
            L += ["", "| 군집 쌍 | 세션 | 시퀀스 유사도 | 명령 집합 Jaccard | A에만 있는 명령어 | B에만 있는 명령어 | 힌트 |",
                  "|---|---|---|---|---|---|---|"]
            for p in pp:
                only_a, only_b = (p[k].replace("|", "/") or "-" for k in ("only_in_a", "only_in_b"))
                L.append(f"| {p['cluster_a']} vs {p['cluster_b']} | {p['sessions_a']} / {p['sessions_b']} | {p['top_seq_similarity']} | "
                         f"{p['command_set_jaccard']} | {only_a} | {only_b} | {p['review_hint']} |")
        else:
            L += ["", f"_비교 대상 군집 쌍 없음 (군집별 {summary['min_sessions']}세션 미만)._"]
        L.append("")
    one = [(r["protocol"], r["rule_combo"]) for r in cluster_rows if r["case"] == CASE_ONE_PLUS_NOISE and not r["is_noise"]]
    if one:
        L += ["## 실제 군집 1개 + 노이즈 (참고)", "", "| 프로토콜 | 규칙 조합 | 군집 | 군집 세션 | 노이즈 세션 |", "|---|---|---|---|---|"]
        for proto, combo in one:
            cl = [r for r in cluster_rows if r["protocol"] == proto and r["rule_combo"] == combo]
            real = next(r for r in cl if not r["is_noise"])
            noise = sum(r["sessions"] for r in cl if r["is_noise"])
            L.append(f"| {proto} | `{combo}` | {real['cluster_id']} | {real['sessions']} | {noise} |")
        L.append("")
    L += ["## 해석 가이드", "",
          "- 힌트는 정규화한 명령 시퀀스의 겹침 정도만으로 만든 참고 문구다. 실제 행동 차이인지는 원문 세션을 사람이 확인해야 한다.",
          "- 규칙 조합이 같아도 군집이 나뉘는 흔한 이유: 명령 순서·개수·인자 차이, 같은 봇의 반복 횟수, 노이즈 경계. 위험도와 무관할 수 있다.",
          "- `B19`처럼 특이도가 낮은 규칙이 조합에 있으면 서로 무관한 세션이 한 조합으로 묶인다. 보조 분석(규칙 제외)과 함께 본다.", ""]
    return "\n".join(L)


def write_all(out_dir, suffix, meta, rows, ignore, min_sessions, representatives):
    cluster_rows, pairs, summary = analyze(rows, ignore, min_sessions, representatives)
    write_csv(out_dir / f"combo_clusters{suffix}.csv", cluster_rows, [
        "protocol", "rule_combo", "case", "cluster_id", "is_noise", "sessions", "share_of_combo", "seoul", "syd",
        "other_sources", "ips", "top_seq_share", "top_seq", "cluster_representative"])
    write_csv(out_dir / f"combo_comparison{suffix}.csv", pairs, [
        "protocol", "rule_combo", "cluster_a", "cluster_b", "sessions_a", "sessions_b", "top_seq_similarity",
        "command_set_jaccard", "same_top_seq", "only_in_a", "only_in_b", "top_seq_a", "top_seq_b", "review_hint"])
    title = "규칙 조합 × ML 군집 교차 분석" + (f" (규칙 제외: {', '.join(sorted(ignore))})" if ignore else "")
    (out_dir / f"report{suffix}.md").write_text(render_report(meta, summary, cluster_rows, pairs, title), encoding="utf-8")
    return summary


def main(argv=None):
    p = argparse.ArgumentParser(description="규칙 조합 × ML 군집 교차 분석 (읽기 전용)")
    p.add_argument("--data-dir", default="data/dashboard", help="ml.db, dashboard.db가 있는 폴더 (읽기 전용)")
    p.add_argument("--out", default="work/cross_cluster")
    p.add_argument("--rules", default=str(Path(__file__).resolve().parents[2] / "signatures/rules.yaml"),
                   help="버전 일치 확인용 (읽기만 함)")
    p.add_argument("--ignore-rules", default="B19", help="보조 분석에서 뺄 규칙(쉼표). 빈 문자열이면 보조 분석 생략")
    p.add_argument("--min-sessions", type=int, default=3, help="군집 쌍 비교에 필요한 군집별 최소 세션 수")
    args = p.parse_args(argv)

    data_dir, out_dir = Path(args.data_dir).resolve(), Path(args.out).resolve()
    if out_dir == data_dir or data_dir in out_dir.parents:
        p.error("--out은 원본 데이터 폴더 안에 둘 수 없다")
    out_dir.mkdir(parents=True, exist_ok=True)

    with closing(open_readonly(data_dir)) as con:
        rows = load_rows(con)
        meta = load_meta(con, data_dir, args.rules)
    reps = load_representatives(data_dir)

    summaries = {"all_rules": write_all(out_dir, "", meta, rows, frozenset(), args.min_sessions, reps)}
    ignore = frozenset(x.strip() for x in args.ignore_rules.split(",") if x.strip())
    if ignore:
        suffix = "_ignoring_" + "_".join(sorted(ignore))
        summaries[f"ignoring_{'+'.join(sorted(ignore))}"] = write_all(out_dir, suffix, meta, rows, ignore, args.min_sessions, reps)
    (out_dir / "run_meta.json").write_text(
        json.dumps({**meta, "summaries": summaries}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summaries, ensure_ascii=False, indent=2))
    print(f"출력: {out_dir}")


if __name__ == "__main__":
    main()
