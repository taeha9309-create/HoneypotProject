"""Evaluate E1 rule restoration on a post-freeze Telnet database copy."""
import argparse
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
from importlib import metadata
from itertools import groupby
import json
from pathlib import Path

from match_signatures import event_time, load_rules, match
from ml.analysis import eval_candidates, eval_rule_removal, forward_eval, splits
from ml.analysis.rules_version import write_new


def model_labels(sequences, model_path):
    """Apply the same frozen transforms and HDBSCAN mapping as cluster.assign."""
    from ml import cluster

    if not sequences:
        return []
    model = cluster.joblib.load(model_path)
    if model["normalize_version"] != cluster.NORMALIZE_VERSION:
        raise ValueError("frozen model normalization version differs from the current normalizer")
    docs = [cluster.as_doc(sequence) for sequence in sequences]
    transformed = model["vectorizer"].transform(docs)
    vectors = cluster.l2_normalize(model["svd"].transform(transformed))
    labels, _ = cluster.approximate_predict(model["clusterer"], vectors)
    return [int(model["label_order"][int(label)]) for label in labels]


def training_samples(database, known_keys, training_end, baseline):
    from ml import cluster

    with closing(splits.ro(database)) as con:
        rows = con.execute("""
            SELECT s.source, s.session_id, s.src_ip, m.cluster_id, s.start_ts, c.ts, c.command
            FROM sessions AS s JOIN commands AS c USING (source, session_id)
            JOIN ml_clusters AS m USING (source, session_id)
            WHERE s.protocol = 'telnet' AND m.protocol = 'telnet'
              AND s.excluded = 0 AND m.assigned_by = 'fit'
            ORDER BY s.source, s.session_id, c.ts, c.rowid
        """)
        samples = []
        for (source, sid, ip, label, start), group in groupby(rows, lambda row: row[:5]):
            began = event_time(start)
            commands = [(row[5], row[6]) for row in group]
            if ((source, sid) not in known_keys or ip in cluster.TEST_IPS or began is None
                    or began >= training_end
                    or any((ts := event_time(raw)) is None or not began <= ts < training_end
                           for raw, _ in commands)):
                raise ValueError("frozen training assignment is outside the archived training population")
            seq = cluster.normalize_session([command for _, command in commands])
            samples.append(eval_rule_removal.Sample("telnet", seq, ip, label,
                                                     frozenset(match(baseline, commands))))
    if not samples:
        raise ValueError("frozen training database has no Telnet fit assignments")
    return samples


def check_settings(plan, receipt, now):
    start, end, sources = forward_eval.check_window(plan, receipt, now)
    section = plan["e1"]
    training_end = forward_eval.utc(section["training_end_exclusive_utc"], "training_end_exclusive_utc")
    if training_end > forward_eval.utc(plan["frozen_at_utc"], "frozen_at_utc"):
        raise ValueError("training window overlaps post-freeze evaluation")
    threshold = section["edit_threshold"]
    if (type(threshold) not in {int, float} or not 0 < threshold <= 1
            or type(section["replicates"]) is not int or section["replicates"] < 1
            or type(section["seed"]) is not int or section["seed"] < 0):
        raise ValueError("freeze requires a valid edit threshold, bootstrap count and seed")
    return start, end, sources, training_end, section


def evaluate(args, now=None):
    from ml import cluster

    plan = json.loads(args.freeze.read_text(encoding="utf-8"))
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    start, end, sources, training_end, settings = check_settings(
        plan, receipt, now or datetime.now(timezone.utc))
    files = (
        (args.baseline, settings["baseline_rules_sha256"]),
        (args.training_db, settings["training_db_sha256"]),
        (args.development_db, settings["development_db_sha256"]),
        (args.telnet_model, settings["telnet_model_sha256"]),
        (Path(cluster.__file__), settings["cluster_py_sha256"]),
    )
    if any(receipt["database_sha256"] == expected for _, expected in files):
        raise ValueError("new batch must differ from the archived development and training inputs")
    for path, expected in files:
        eval_candidates.verify(path, expected)
    eval_candidates.verify(args.new_db, receipt["database_sha256"])
    if (settings["normalize_version"] != cluster.NORMALIZE_VERSION
            or settings["hdbscan"] != metadata.version("hdbscan")
            or settings["scikit_learn"] != metadata.version("scikit-learn")):
        raise ValueError("frozen model environment does not match")

    with closing(splits.ro(args.development_db)) as con:
        known = set(con.execute("SELECT source, session_id FROM sessions"))
    baseline = load_rules(args.baseline)
    train = training_samples(args.training_db, known, training_end, baseline)
    excluded = Counter()
    eligible = []
    with closing(splits.ro(args.new_db)) as con:
        for source, ip, commands in forward_eval.forward_sessions(
                con, known, start, end, sources, cluster.TEST_IPS, excluded):
            sequence = cluster.normalize_session([command for _, command in commands])
            eligible.append((source, ip, sequence, frozenset(match(baseline, commands))))
    eval_candidates.verify(args.telnet_model, settings["telnet_model_sha256"])
    labels = model_labels([row[2] for row in eligible], args.telnet_model)
    populations = {source: [] for source in sorted(sources)}
    for label, (source, ip, sequence, truth) in zip(labels, eligible, strict=True):
        populations[source].append(eval_rule_removal.Sample("telnet", sequence, ip, label, truth))
    for path, expected in files:
        eval_candidates.verify(path, expected)
    eval_candidates.verify(args.new_db, receipt["database_sha256"])

    threshold, count, seed = (settings[key] for key in ("edit_threshold", "replicates", "seed"))
    total = [row for items in populations.values() for row in items]
    reasons = []
    if end - start < timedelta(days=plan["min_days"]):
        reasons.append("collection shorter than frozen minimum")
    if len(total) < plan["min_telnet_sessions"]:
        reasons.append("eligible sessions below frozen minimum")
    return {
        "scope": "post-freeze E1 Telnet rule restoration",
        "status": "no_eligible_sessions" if not total else "pilot" if reasons else "evaluated",
        "pilot_reasons": reasons,
        "freeze_sha256": splits.sha256_file(args.freeze),
        "receipt_sha256": splits.sha256_file(args.receipt),
        "database_sha256": receipt["database_sha256"],
        "training_sessions": len(train),
        "threshold": threshold, "bootstrap_replicates": count, "seed": seed,
        "rules": eval_rule_removal.RULES,
        "exclusions": dict(excluded),
        "populations": {source: {
            "sessions": len(samples),
            "noise": sum(row.cluster == -1 for row in samples),
            "metrics": eval_rule_removal.evaluate(train, samples, threshold, count, seed),
        } for source, samples in {"all": total, **populations}.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("freeze", "receipt", "training-db", "development-db", "new-db", "telnet-model", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=eval_candidates.BASELINE)
    args = parser.parse_args()
    try:
        report = evaluate(args)
        write_new(args.out, json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n")
        print(f"{report['status']}: {report['populations']['all']['sessions']} Telnet sessions")
    except (ValueError, FileExistsError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
