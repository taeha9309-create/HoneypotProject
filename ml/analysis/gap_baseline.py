"""기준선 지표와 규칙 간극 추출 (읽기 전용).

사용법 (저장소 루트에서):
    python ml/analysis/gap_baseline.py --data-dir <dashboard 데이터 폴더> [--out <폴더>] [--weak B19]

입력(읽기 전용): <data-dir>/ml.db(sessions, commands, ml_clusters), <data-dir>/dashboard.db(hits, meta, sources)
출력: <out>/baseline.json (지표·실행 기록), <out>/gap_sessions.csv (규칙 간극 세션: 미적중 + 약한 규칙만 적중)

지표는 세션·고유 순서·IP 세 단위로 낸다. 커버리지(하나라도 적중)는 B19 같은 포괄 규칙 때문에 포화하므로 개선 지표로 쓰지
않는다(docs/adr/0001). 이 도구는 탐지 성능을 말하지 않는다. 공격자 입력은 문자열로만 다루며 실행하지 않는다.
"""
import argparse
import csv
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

WEAK_DEFAULT = ("B19",)  # 낮은 특이도 규칙(셸 진입 요청). 이것만 적중하면 구체화되지 않은 것으로 본다


def _pct(a, b):
    return round(a / b * 100, 1) if b else None


def classify(rules, weak=WEAK_DEFAULT):
    """한 세션(또는 순서)의 적중 규칙 집합 -> none / weak_only / specific."""
    if not rules:
        return "none"
    return "specific" if set(rules) - set(weak) else "weak_only"


def metrics(rows, weak=WEAK_DEFAULT):
    """rows: dict 목록(key, source, protocol, ip, seq(tuple), rules(set)).

    세션 단위, 고유 순서 단위(같은 순서의 규칙 합집합), IP 단위(그 IP 세션 중 하나라도)로 같은 분류를 센다.
    """
    sess = defaultdict(int)
    seq_rules = defaultdict(set)
    ip_rules = defaultdict(set)
    ip_class_any_specific = defaultdict(bool)
    for r in rows:
        c = classify(r["rules"], weak)
        sess[c] += 1
        seq_rules[r["seq"]] |= set(r["rules"])
        ip_rules[r["ip"]] |= set(r["rules"])
    seq_c, ip_c = defaultdict(int), defaultdict(int)
    for s, rs in seq_rules.items():
        seq_c[classify(rs, weak)] += 1
    for ip, rs in ip_rules.items():
        ip_c[classify(rs, weak)] += 1
    n, ns, ni = len(rows), len(seq_rules), len(ip_rules)

    def block(c, total):
        covered = c["weak_only"] + c["specific"]
        return {"total": total, "none": c["none"], "weak_only": c["weak_only"], "specific": c["specific"],
                "coverage_pct": _pct(covered, total), "specificity_pct": _pct(c["specific"], total)}
    return {"weak_rules": list(weak), "session": block(sess, n), "unique_seq": block(seq_c, ns), "ip": block(ip_c, ni)}


def load_rows(data_dir):
    """data-dir에서 명령 세션 행을 읽는다. 군집 배정이 있는 세션만 쓴다(ml_clusters = 분석 대상)."""
    from ml.cluster import load_sessions, normalize_session
    data_dir = Path(data_dir)
    con = sqlite3.connect("file:" + (data_dir / "ml.db").as_posix() + "?mode=ro", uri=True)
    con.execute("ATTACH DATABASE ? AS dash", ("file:" + (data_dir / "dashboard.db").as_posix() + "?mode=ro",))
    hits = defaultdict(set)
    for s, i, r in con.execute("SELECT source, session_id, rule_id FROM dash.hits"):
        hits[(s, i)].add(r)
    clusters = {(s, i): (p, c) for s, i, p, c in con.execute(
        "SELECT source, session_id, protocol, cluster_id FROM ml_clusters")}
    sess = load_sessions(con)
    rows = []
    for k, (proto, cid) in clusters.items():
        if k not in sess:
            continue
        rows.append({"key": k, "source": k[0], "protocol": proto, "ip": sess[k]["src_ip"],
                     "seq": tuple(normalize_session(sess[k]["cmds"])), "rules": hits.get(k, set()),
                     "cluster": cid, "start": sess[k]["ts"][0]})
    meta = dict(con.execute("SELECT key, value FROM dash.meta").fetchall())
    con.close()
    return rows, meta


def build(data_dir, weak=WEAK_DEFAULT):
    from ml.analysis.splits import env_record, sha256_file, source_config
    rows, meta = load_rows(data_dir)
    out = {"data_dir": str(data_dir), "rules_sha256": meta.get("rules_sha256"), "rules_commit": meta.get("rules_commit"),
           "input_sha256": {f: sha256_file(Path(data_dir) / f) for f in ("ml.db", "dashboard.db")},
           "env": env_record(), "source_config": source_config(data_dir),
           "all": metrics(rows, weak), "by_source": {}, "by_protocol": {}}
    for s in sorted({r["source"] for r in rows}):
        out["by_source"][s] = metrics([r for r in rows if r["source"] == s], weak)
    for p in sorted({r["protocol"] for r in rows}):
        out["by_protocol"][p] = metrics([r for r in rows if r["protocol"] == p], weak)
    return out, rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--weak", nargs="*", default=list(WEAK_DEFAULT))
    a = ap.parse_args()
    result, rows = build(a.data_dir, tuple(a.weak))
    print(json.dumps({k: result[k] for k in ("rules_sha256", "all", "by_source", "by_protocol")}, ensure_ascii=False, indent=2))
    if a.out:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "baseline.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        with open(out / "gap_sessions.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["source", "session_id", "protocol", "cluster_id", "start_ts", "rules", "normalized_seq"])
            for r in rows:
                if classify(r["rules"], tuple(a.weak)) != "specific":
                    w.writerow([*r["key"][:1], r["key"][1], r["protocol"], r["cluster"], r["start"],
                                ",".join(sorted(r["rules"])), " ; ".join(r["seq"])[:300]])


if __name__ == "__main__":
    main()
