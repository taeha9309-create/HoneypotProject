"""Exploratory E1 rule restoration using saved T2 assignments and verified labels.

Run from the repository root with python -m ml.analysis.eval_rule_removal.
"""
import argparse
import json
from collections import Counter, defaultdict
from contextlib import closing
from dataclasses import dataclass
from itertools import groupby
from pathlib import Path

import numpy as np

from ml.analysis import grouping, splits

RULES = ("B11", "B01", "B10", "B14", "B12", "B21", "B08", "B16", "B09")
ARMS = ("A_signatures_only", "B_exact", "C_edit", "D_ml_cluster")
VARIANTS = ("full", "drop_top_ip", "ip_cap1")
DEV_END = "2026-11-26T00:00:00"
METRICS = ("precision", "recall", "unseen_recall")


@dataclass(frozen=True)
class Sample:
    protocol: str
    sequence: tuple
    ip: str | None
    cluster: int
    rules: frozenset


def predictions(train, held, threshold):
    """Restore hidden labels by strict majority of training sequences in each group."""
    sequences = {row.sequence for row in train}
    exact = grouping.ExactGrouper().fit(sequences)
    edit = grouping.EditGrouper(threshold).fit(sequences)
    held_sequences = {row.sequence for row in held}
    exact_groups = {seq: exact.assign(seq)[1] for seq in held_sequences}
    edit_groups = {seq: edit.assign(seq)[1] for seq in held_sequences}
    assignments = (
        ({row: exact.group_of[row.sequence] for row in train},
         {row: exact_groups[row.sequence] for row in held}),
        ({row: edit.group_of[row.sequence] for row in train},
         {row: edit_groups[row.sequence] for row in held}),
        ({row: (row.protocol, row.cluster) for row in train if row.cluster != -1},
         {row: (row.protocol, row.cluster) for row in held if row.cluster != -1}),
    )
    result = {ARMS[0]: [frozenset()] * len(held)}
    targets = set(RULES)
    for arm, (train_groups, held_groups) in zip(ARMS[1:], assignments):
        group_sequences = defaultdict(lambda: defaultdict(set))
        for row, group in train_groups.items():
            group_sequences[group][row.sequence].update(row.rules & targets)
        restored = {}
        for group, sequences_in_group in group_sequences.items():
            votes = Counter(rule for rules in sequences_in_group.values() for rule in rules)
            restored[group] = frozenset(rule for rule, votes_for_rule in votes.items()
                                        if 2 * votes_for_rule > len(sequences_in_group))
        result[arm] = [restored.get(held_groups.get(row), frozenset()) for row in held]
    return result


def counts_by_unit(rows, predicted, unseen, unit):
    """Columns per arm/rule: TP, predicted, positive, unseen TP, unseen positive."""
    groups = {}
    for index, (row, prediction) in enumerate(zip(rows, predicted)):
        key = row.sequence if unit == "unique_seq" else row.ip
        if unit == "session" or (unit == "ip" and key is None):
            key = index
        if key not in groups:
            groups[key] = np.zeros((4, len(RULES)), dtype=bool)
        actual = np.array([rule in row.rules for rule in RULES])
        guess = np.array([rule in prediction for rule in RULES])
        novel = row.sequence in unseen
        groups[key] |= np.array([actual, guess, actual & novel, guess & novel])
    flags = np.array(list(groups.values()), dtype=bool).reshape(-1, 4, len(RULES))
    actual, guess, novel_actual, novel_guess = flags.transpose(1, 0, 2)
    return np.stack((actual & guess, guess, actual, novel_actual & novel_guess, novel_actual), axis=-1)


def rates(counts):
    numerator = counts[..., [0, 0, 3]]
    denominator = counts[..., [1, 2, 4]]
    return np.divide(numerator, denominator, out=np.full(numerator.shape, np.nan), where=denominator != 0)


def interval(values):
    valid = values[np.isfinite(values)]
    return {"low": float(np.quantile(valid, 0.025)) if len(valid) else None,
            "high": float(np.quantile(valid, 0.975)) if len(valid) else None,
            "defined_resamples": len(valid)}


def mean_defined(values, axis):
    n = np.isfinite(values).sum(axis=axis)
    return np.divide(np.nansum(values, axis=axis), n, out=np.full(n.shape, np.nan), where=n != 0)


def bootstrap(counts, replicates, seed):
    n = len(counts)
    if not n:
        return rates(np.zeros((replicates, *counts.shape[1:])))
    rng = np.random.default_rng(seed)
    weights = rng.multinomial(n, np.repeat(1 / n, n), size=replicates)
    totals = weights @ counts.reshape(n, -1).astype(float)
    return rates(totals.reshape(replicates, *counts.shape[1:]))


def evaluate(train, held, threshold, replicates, seed):
    predicted = predictions(train, held, threshold)
    unseen = {row.sequence for row in held} - {row.sequence for row in train}
    results = {}
    for unit in ("unique_seq", "session", "ip"):
        # Each array shares its group ordering across all arms.
        counts = np.stack([counts_by_unit(held, predicted[arm], unseen, unit) for arm in ARMS], axis=1)
        totals = counts.sum(axis=0)
        values = rates(totals)
        if unit == "session":
            # Cluster bootstrap: resample IP blocks, retaining all their sessions.
            idx = {}
            blocks = []
            for index, row in enumerate(held):
                key = row.ip if row.ip is not None else index
                if key not in idx:
                    idx[key] = len(blocks)
                    blocks.append(np.zeros(totals.shape, dtype=int))
                blocks[idx[key]] += counts[index]
            resampled = bootstrap(np.array(blocks).reshape(-1, *totals.shape), replicates, seed)
        else:
            resampled = bootstrap(counts, replicates, seed)
        macro = mean_defined(values, axis=1)
        macro_samples = mean_defined(resampled, axis=2)
        results[unit] = {}
        for index, arm in enumerate(ARMS):
            by_rule = {}
            for rank, rule in enumerate(RULES):
                by_rule[rule] = {
                    "counts": dict(zip(("tp", "predicted", "positive", "unseen_tp", "unseen_positive"),
                                       totals[index, rank].tolist())),
                    **{metric: {"value": finite(values[index, rank, col]),
                                "ci95": interval(resampled[:, index, rank, col])}
                       for col, metric in enumerate(METRICS)},
                }
            results[unit][arm] = {
                "rules": by_rule,
                "macro": {metric: {"value": finite(macro[index, col]),
                                   "defined_rules": int(np.isfinite(values[index, :, col]).sum()),
                                   "ci95": interval(macro_samples[:, index, col])}
                          for col, metric in enumerate(METRICS)},
            }
        results[unit]["D_minus_C_macro"] = {
            metric: {"value": finite(macro[3, col] - macro[2, col]),
                     "ci95": interval(macro_samples[:, 3, col] - macro_samples[:, 2, col])}
            for col, metric in enumerate(METRICS)
        }
    return results


def finite(value):
    return float(value) if np.isfinite(value) else None


def load_hits(path, expected_hash):
    if splits.sha256_file(path) != expected_hash:
        raise ValueError("dashboard.db must match the archived development snapshot")
    with closing(splits.ro(path)) as con:
        hits = defaultdict(set)
        marks = ", ".join("?" for _ in RULES)
        for source, session, rule in con.execute(
                f"SELECT source, session_id, rule_id FROM hits WHERE rule_id IN ({marks})", RULES):
            hits[source, session].add(rule)
        rules_hash = con.execute("SELECT value FROM meta WHERE key = 'rules_sha256'").fetchone()
    return hits, rules_hash[0] if rules_hash else None


def load_split(path, hits):
    from ml.cluster import normalize_session

    with closing(splits.ro(path)) as con:
        rows = con.execute("""
            SELECT s.source, s.session_id, s.protocol, s.src_ip, m.cluster_id, m.assigned_by, c.command
            FROM sessions AS s
            JOIN commands AS c USING (source, session_id)
            JOIN ml_clusters AS m USING (source, session_id)
            WHERE s.excluded = 0 AND s.start_ts < ? AND c.ts < ?
              AND m.assigned_by IN ('fit', 'assign')
            ORDER BY s.source, s.session_id, c.ts, c.rowid
            """, (DEV_END, DEV_END))
        parts = {"fit": [], "assign": []}
        for (source, session, protocol, ip, cluster, assignment), group in groupby(rows, lambda row: row[:6]):
            sequence = normalize_session([row[6] for row in group])
            parts[assignment].append(Sample(protocol, sequence, ip, cluster,
                                            frozenset(hits.get((source, session), ()))))
    return parts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--t2-dir", type=Path, required=True)
    parser.add_argument("--dashboard-db", type=Path, required=True)
    parser.add_argument("--replicates", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.replicates < 1:
        parser.error("replicates must be positive")

    from ml import cluster

    first = json.loads((args.t2_dir / "syd_to_seoul/full/syd_to_seoul/grouping.json").read_text(encoding="utf-8"))
    hashes = first["input_sha256"]
    run_version = splits.sha256_file(Path(cluster.__file__))
    hits, rules_hash = load_hits(args.dashboard_db, hashes["dashboard.db"])
    report = {
        "status": "exploratory development experiment",
        "development_commands_before_utc": DEV_END,
        "primary_split": "syd_to_seoul",
        "primary_unit": "unique_seq",
        "primary_variant": "full",
        "minimum_group_vote": "strict majority over distinct training sequences",
        "target_label_use": "training reference only for group votes; evaluation reference only for scoring",
        "A_signatures_only": "removed rule is absent and no replacement is generated",
        "restoration_method": "group-based proxy, distinct from deploying generated regexes",
        "macro": "unweighted mean of rules with a defined metric",
        "noise_and_unassigned": "retained in evaluation denominators, no restored rule",
        "unique_seq_and_ip": "any matching session makes the unit positive; missing IPs are singletons",
        "replicates": args.replicates,
        "seed": args.seed,
        "bootstrap": "percentile, unique sequence or IP blocks; undefined replicates omitted",
        "input_sha256": hashes,
        "rules_sha256": rules_hash,
        "runs": {},
    }
    for split in ("syd_to_seoul", "time", "seoul_to_syd"):
        report["runs"][split] = {}
        for variant in VARIANTS:
            run = args.t2_dir / split / variant / split
            metadata = json.loads((run / "grouping.json").read_text(encoding="utf-8"))
            version = metadata["ml_version"]
            if ((split, variant) != (metadata["split"], metadata["variant"])
                    or metadata["input_sha256"] != hashes
                    or version["cluster_py_sha256"] != run_version
                    or version["normalize_version"] != cluster.NORMALIZE_VERSION):
                raise ValueError(f"incompatible T2 metadata for {split}/{variant}")
            parts = load_split(run / "ml_train.db", hits)
            report["runs"][split][variant] = {
                "ml_version": version,
                "fit_ip_cap": metadata["split_info"]["variant"]["fit_ip_cap"],
                "edit_threshold": metadata["edit_threshold"],
                "train_sessions": len(parts["fit"]),
                "held_sessions": len(parts["assign"]),
                "metrics": evaluate(parts["fit"], parts["assign"], metadata["edit_threshold"],
                                    args.replicates, args.seed),
            }
    print(json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
