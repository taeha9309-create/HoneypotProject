"""Find recurrent rule-gap groups for human review in a built dashboard snapshot."""
import argparse
from collections import Counter, defaultdict
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path

from ml.analysis import gap_baseline, label_sample, rule_combo_clusters
from ml.analysis.rules_version import write_new

REPORT_NAME = "signature_review_groups.json"
SHELL_ENTRY = {"shell", "sh", "bash", "ash", "exit", "logout"}
MIN_GAP_SESSIONS = 3
MIN_REPEAT = 2
MIN_GAP_SHARE = 0.5


def scan(rows):
    grouped = defaultdict(list)
    skipped = Counter()
    for row in rows:
        gap = gap_baseline.classify(row["rules"])
        if row["is_noise"] or row["cluster_id"] < 0:
            skipped["noise_sessions"] += 1
            skipped["noise_gap_sessions"] += gap != "specific"
        elif not row["seq"]:
            skipped["empty_sequence_sessions"] += 1
        else:
            grouped[row["protocol"], row["cluster_id"]].append((row, gap))

    results = []
    for (protocol, cluster_id), members in grouped.items():
        gaps = [(row, kind) for row, kind in members if kind != "specific"]
        share = len(gaps) / len(members)
        if len(gaps) < MIN_GAP_SESSIONS or share < MIN_GAP_SHARE:
            skipped["below_gap_support_clusters"] += 1
            continue
        by_sequence = defaultdict(list)
        for row, kind in gaps:
            if any(command not in SHELL_ENTRY for command in row["seq"]):
                by_sequence[row["seq"]].append((row, kind))
        repeated = [(sequence, group) for sequence, group in by_sequence.items()
                    if len(group) >= MIN_REPEAT]
        if not repeated:
            skipped["no_repeated_non_shell_flow_clusters"] += 1
            continue
        repeated.sort(key=lambda item: (-len(item[1]), item[0]))
        support = [row for _, group in repeated for row, _ in group]
        ips = Counter(row["ip"] for row in support if row["ip"])
        split = Counter(kind for _, kind in gaps)
        flows = []
        for sequence, group in repeated[:3]:
            flows.append({
                "observed_flow": label_sample.safe_observation(sequence[:12]),
                "steps_omitted": max(0, len(sequence) - 12),
                "sessions": len(group),
                "ips": len({row["ip"] for row, _ in group if row["ip"]}),
            })
        results.append({
            "protocol": protocol,
            "cluster_id": cluster_id,
            "cluster_sessions": len(members),
            "gap_sessions": len(gaps),
            "gap_share": share,
            "without_rule": split["none"],
            "weak_rule_only": split["weak_only"],
            "recurrent_gap_sessions": len(support),
            "recurrent_flows": len(repeated),
            "recurrent_ips": len(ips),
            "top_ip_share_among_known_ips": max(ips.values()) / sum(ips.values()) if ips else None,
            "sources": dict(sorted(Counter(row["source"] for row in support).items())),
            "representative_flows": flows,
        })
    results.sort(key=lambda row: (-row["recurrent_gap_sessions"], -row["gap_share"],
                                  row["protocol"], row["cluster_id"]))
    return results, dict(sorted(skipped.items()))


def build(data_dir, rules):
    with closing(rule_combo_clusters.open_readonly(data_dir)) as con:
        meta = dict(con.execute("SELECT key, value FROM dash.meta"))
        recorded = meta.get("rules_sha256")
        if recorded != sha256(Path(rules).read_bytes()).hexdigest():
            raise ValueError("dashboard hit rules differ from the supplied rules file; refresh first")
        if not meta.get("built_at"):
            raise ValueError("dashboard build time is missing")
        model = con.execute("SELECT value FROM ml_meta WHERE key='trained_at'").fetchone()
        rows = rule_combo_clusters.load_rows(con)
    results, skipped = scan(rows)
    return {
        "status": "review targets only",
        "built_at_utc": meta["built_at"],
        "trained_at_utc": model[0] if model else None,
        "rules_sha256": recorded,
        "thresholds": {"weak_rules": list(gap_baseline.WEAK_DEFAULT),
                       "min_gap_sessions": MIN_GAP_SESSIONS,
                       "min_same_sequence_sessions": MIN_REPEAT,
                       "min_gap_share": MIN_GAP_SHARE},
        "scanned_clustered_and_noise_sessions": len(rows),
        "excluded": skipped,
        "groups": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--rules", default=Path("signatures/rules.yaml"), type=Path)
    parser.add_argument("--out", type=Path, help="default: put the report in the selected dashboard snapshot")
    args = parser.parse_args()
    try:
        report = build(args.data_dir, args.rules)
        write_new(args.out or args.data_dir / REPORT_NAME,
                  json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(f"검토 대상 군집 {len(report['groups'])}개")


if __name__ == "__main__":
    main()
