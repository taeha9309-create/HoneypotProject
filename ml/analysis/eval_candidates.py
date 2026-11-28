"""Freeze an X06 development candidate and score X04/X06 on archived data.

Run with python -m ml.analysis.eval_candidates freeze|evaluate from the repository root.
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
from itertools import groupby
from pathlib import Path

from match_signatures import load_rules, match
from ml.analysis import busybox_context, splits
from ml.analysis.eval_rule_removal import DEV_END

X04 = Path("work/rule_candidates/candidates_frozen_20261125_x04.yaml")
BASELINE = Path("signatures/rules.yaml")


def verify(path, expected):
    if splits.sha256_file(path) != expected:
        raise ValueError(f"file does not match the frozen development input: {path.name}")


def freeze(args):
    from ml import cluster

    t3 = json.loads(args.t3.read_text(encoding="utf-8"))
    version = t3["ml_version"]
    verify(Path(cluster.__file__), version["cluster_py_sha256"])
    if (t3["split"], t3["variant"], t3["training_before_utc"]) != ("time", "full", splits.CUTOFF):
        raise ValueError("expected the T3 time/full training report")
    proposed = [item for item in t3["candidates"]["D_ml_cluster"] if item["family"] == "X06"]
    if not proposed or version["normalize_version"] != cluster.NORMALIZE_VERSION:
        raise ValueError("no compatible X06 training drafts")
    patterns = sorted({item["regex"] for item in proposed})
    for pattern in patterns:
        re.compile(pattern)
    manifest = {
        "scope": "candidate frozen for exploratory development validation; F remains unset",
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "development_start_utc": splits.CUTOFF,
        "development_end_exclusive_utc": DEV_END,
        "development_input_sha256": t3["input_sha256"],
        "normalizer": version,
        "baseline_rules_sha256": splits.sha256_file(BASELINE),
        "t3_report_sha256": splits.sha256_file(args.t3),
        "X04": {"sha256": splits.sha256_file(X04), "matcher": "existing frozen raw sequence"},
        "X06": {
            "name": "환경 탐침 관측",
            "protocol": "telnet",
            "regexes": patterns,
            "matcher": "fullmatch on newline-joined normalized sequence",
            "selection": "union of distinct D-arm T3 X06 draft patterns; no token widening",
            "breadth": "report full and incremental shares; acceptable ceiling remains open",
            "training_support_sessions": len({tuple(key) for item in proposed
                                              for key in item["support"]["session_keys"]}),
        },
    }
    with args.manifest.open("x", encoding="utf-8") as out:
        json.dump(manifest, out, ensure_ascii=False, indent=2)
        out.write("\n")


def archived_sessions(ml_path, start, end):
    from ml.cluster import TEST_IPS

    marks = ", ".join("?" for _ in TEST_IPS)
    with closing(splits.ro(ml_path)) as con:
        rows = con.execute(f"""
            SELECT s.source, s.session_id, s.src_ip, c.ts, c.command
            FROM sessions AS s JOIN commands AS c USING (source, session_id)
            WHERE s.excluded = 0 AND s.protocol = 'telnet' AND s.n_commands > 0
              AND s.start_ts >= ? AND s.start_ts < ? AND c.ts < ?
              AND (s.src_ip IS NULL OR s.src_ip NOT IN ({marks}))
            ORDER BY s.source, s.session_id, c.ts, c.rowid
            """, (start, end, end, *TEST_IPS))
        for (source, session, ip), group in groupby(rows, lambda row: row[:3]):
            yield (source, session), ip, [(row[3], row[4]) for row in group]


def candidate_metrics(records):
    """Records are (baseline rule IDs, candidate matched) pairs."""
    categories = Counter()
    overlaps = Counter()
    weak_count = 0
    for rules, found in records:
        weak_count += rules == {"B19"}
        if found:
            categories["matched"] += 1
            categories["new_coverage"] += not rules
            categories["b19_only_refined"] += rules == {"B19"}
            categories["already_specific"] += bool(rules - {"B19"})
            overlaps.update(rules)
    return {
        "population": len(records),
        "matches": categories["matched"],
        "match_rate": categories["matched"] / len(records) if records else None,
        "new_coverage": categories["new_coverage"],
        "b19_only_population": weak_count,
        "b19_only_refined": categories["b19_only_refined"],
        "b19_only_refined_rate": categories["b19_only_refined"] / weak_count if weak_count else None,
        "already_specific": categories["already_specific"],
        "overlap_by_rule": dict(overlaps),
    }


def evaluate(args):
    from ml import cluster

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    start, end = manifest["development_start_utc"], manifest["development_end_exclusive_utc"]
    if (start, end) != (splits.CUTOFF, DEV_END):
        raise ValueError("only the declared development window is supported")
    verify(X04, manifest["X04"]["sha256"])
    verify(BASELINE, manifest["baseline_rules_sha256"])
    verify(Path(cluster.__file__), manifest["normalizer"]["cluster_py_sha256"])
    ml_path = args.data_dir / "ml.db"
    dash_path = args.data_dir / "dashboard.db"
    for path in (ml_path, dash_path):
        verify(path, manifest["development_input_sha256"][path.name])
    with closing(splits.ro(dash_path)) as con:
        row = con.execute("SELECT value FROM meta WHERE key = 'rules_sha256'").fetchone()
        if not row or row[0] != manifest["baseline_rules_sha256"]:
            raise ValueError("archived baseline rule hash differs from the frozen baseline")
        hits = defaultdict(set)
        for source, session, rule in con.execute("SELECT source, session_id, rule_id FROM hits"):
            hits[source, session].add(rule)
    x04 = load_rules(X04)
    x06 = [re.compile(pattern) for pattern in manifest["X06"]["regexes"]]
    contexts = []
    x06_contexts = []
    populations = defaultdict(list)
    for key, ip, commands in archived_sessions(ml_path, start, end):
        seq = cluster.normalize_session([command for _, command in commands])
        rules = hits.get(key, set())
        x04_match = "X04" in match(x04, commands)
        x06_match = any(pattern.fullmatch("\n".join(seq)) for pattern in x06)
        contexts.append((seq, ip, rules))
        if x06_match:
            x06_contexts.append((seq, ip, rules))
        row = (rules, x04_match, x06_match)
        populations["all"].append(row)
        populations[key[0]].append(row)
    if not contexts:
        raise ValueError("no Telnet development sessions")
    return {
        "status": "exploratory development validation using previously inspected dates",
        "manifest_sha256": splits.sha256_file(args.manifest),
        "start_utc": start,
        "end_exclusive_utc": end,
        "protocol": "telnet",
        "busybox_context": busybox_context.summarize(contexts),
        "x06_match_context": busybox_context.summarize(x06_contexts),
        "results": {source: {
            "X04": candidate_metrics([(rules, a) for rules, a, _ in rows]),
            "X06": candidate_metrics([(rules, b) for rules, _, b in rows]),
            "X04_and_X06": sum(a and b for _, a, b in rows),
        } for source, rows in populations.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    lock = commands.add_parser("freeze")
    lock.add_argument("--t3", type=Path, required=True)
    lock.add_argument("--manifest", type=Path, required=True)
    validate = commands.add_parser("evaluate")
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--data-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "freeze":
        freeze(args)
    else:
        print(json.dumps(evaluate(args), ensure_ascii=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
