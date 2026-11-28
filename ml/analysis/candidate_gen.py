"""Draft X04/X06 detection patterns from a saved T2 time/full run.

Reads only pre-cutoff Telnet commands. Patterns match the complete normalized
command sequence joined with newlines. Training match shares describe breadth.
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from contextlib import closing
from dataclasses import dataclass
from itertools import groupby
from pathlib import Path

from ml.analysis import grouping, splits

MENU = ("enable", "system", "shell", "sh")
MENUS = (MENU, ("enable", "linuxshell", *MENU[1:]))
PROBES = ("busybox UNSTABLE", "/bin/busybox UNSTABLE")


@dataclass(frozen=True)
class TrainingSession:
    key: tuple
    ip: str | None
    days: tuple
    sequence: tuple
    cluster: int | None


def family_of(sequence):
    if sequence in MENUS:
        return "X04"
    if sequence and sequence[-1] in PROBES and sequence[:-1] in (*MENUS, ("sh",)):
        return "X06"
    return None


def sequence_regex(sequences):
    # Factor the common first token. Alternatives stay bounded to observed forms.
    by_first = defaultdict(list)
    for first, *tail in sorted(sequences):
        by_first[first].append(tuple(tail))
    branches = []
    for first, tails in by_first.items():
        suffix = ["".join(r"\n" + re.escape(token) for token in tail) for tail in tails]
        branch = suffix[0] if len(suffix) == 1 else "(?:" + "|".join(suffix) + ")"
        branches.append(re.escape(first) + branch)
    body = branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
    return r"\A" + body + r"\Z"


def draft_candidates(sessions, edit_threshold):
    labeled = [row for row in sessions if row.cluster is not None]
    sequences = sorted({row.sequence for row in labeled})
    exact = grouping.ExactGrouper().fit(sequences)
    edit = grouping.EditGrouper(edit_threshold).fit(sequences)
    methods = {exact.name: lambda row: exact.group_of[row.sequence],
               edit.name: lambda row: edit.group_of[row.sequence],
               grouping.ClusterGrouper.name: lambda row: row.cluster}
    population = Counter(row.sequence for row in sessions)
    report = {}
    for method, group_of in methods.items():
        groups = defaultdict(list)
        for row in labeled:
            family = family_of(row.sequence)
            group = group_of(row)
            if family is not None and group != -1:
                groups[family, group].append(row)
        report[method] = []
        for (family, group), support in sorted(groups.items()):
            regex = sequence_regex({row.sequence for row in support})
            pattern = re.compile(regex)
            matched = sum(count for seq, count in population.items()
                          if pattern.fullmatch("\n".join(seq)))
            report[method].append({
                "family": family,
                "group": group,
                "status": "proposed",
                "regex": regex,
                "support": {
                    "session_keys": sorted([list(row.key) for row in support]),
                    "sessions": len(support),
                    "unique_sequences": len({row.sequence for row in support}),
                    "ips": len({row.ip for row in support if row.ip}),
                    "activity_days_utc": sorted({day for row in support for day in row.days}),
                },
                "training_matches": {
                    "matched": matched,
                    "total": len(sessions),
                    "rate": matched / len(sessions),
                },
            })
    return report


def load_training_sessions(database):
    from ml.cluster import TEST_IPS, normalize_session

    placeholders = ", ".join("?" for _ in TEST_IPS)
    with closing(splits.ro(database)) as con:
        rows = con.execute(f"""
            SELECT s.source, s.session_id, s.src_ip, m.cluster_id, c.ts, c.command
            FROM sessions AS s JOIN commands AS c USING (source, session_id)
            LEFT JOIN ml_clusters AS m ON m.source = s.source
                AND m.session_id = s.session_id AND m.assigned_by = 'fit'
            WHERE s.protocol = 'telnet' AND s.excluded = 0 AND s.n_commands > 0
              AND s.start_ts < ? AND c.ts < ?
              AND (s.src_ip IS NULL OR s.src_ip NOT IN ({placeholders}))
            ORDER BY s.source, s.session_id, c.ts, c.rowid
            """, (splits.CUTOFF, splits.CUTOFF, *TEST_IPS))
        training = []
        for (source, session, ip, cluster), group in groupby(rows, lambda row: row[:4]):
            commands = [(row[4], row[5]) for row in group]
            sequence = normalize_session([command for _, command in commands])
            training.append(TrainingSession((source, session), ip,
                                            tuple(sorted({ts[:10] for ts, _ in commands})),
                                            sequence, cluster))
    return training


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads((args.run_dir / "grouping.json").read_text(encoding="utf-8"))
    if (metadata["split"], metadata["variant"]) != ("time", "full"):
        parser.error("the saved T2 time/full run is required")
    from ml import cluster
    version = metadata["ml_version"]
    if (version["cluster_py_sha256"] != splits.sha256_file(Path(cluster.__file__))
            or version["normalize_version"] != cluster.NORMALIZE_VERSION):
        parser.error("the saved T2 normalizer version does not match")
    data = load_training_sessions(args.run_dir / "ml_train.db")
    report = {
        "training_before_utc": splits.CUTOFF,
        "split": metadata["split"],
        "variant": metadata["variant"],
        "input_sha256": metadata["input_sha256"],
        "ml_version": version,
        "edit_threshold": metadata["edit_threshold"],
        "regex_input": "newline-joined normalized Telnet command sequence",
        "candidates": draft_candidates(data, metadata["edit_threshold"]),
    }
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
