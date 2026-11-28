"""Export approved rules as a separate bundle and compare them on archived data."""
import argparse
import json
import os
import re
import tempfile
from contextlib import closing
from pathlib import Path

import yaml

from match_signatures import load_rules, match
from ml.analysis import candidate_registry, eval_candidates, label_sample, splits
from ml.analysis.eval_rule_removal import DEV_END


def approved_version(candidate, baseline, version):
    if candidate["status"] != "approved":
        raise ValueError("only approved candidates may be exported")
    if not re.fullmatch(r"v[0-9]{3,}", version):
        raise ValueError("use a version such as v001")
    eval_candidates.verify(baseline, candidate["baseline_rules_sha256"])
    baseline_rules = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    if candidate["id"] in {rule["id"] for rule in baseline_rules}:
        raise ValueError("candidate ID already exists in the baseline")
    return {
        "version": version,
        "format": "honeypot archived rule bundle v1",
        "baseline_rules_sha256": candidate["baseline_rules_sha256"],
        "baseline_rules": baseline_rules,
        "added_rule": {key: candidate[key] for key in
                       ("id", "name", "protocol", "normalized_sequence_patterns")},
        "review": {key: candidate[key] for key in ("reviewer", "decided_utc", "reason")},
        "change_summary": "Add one protocol-scoped normalized session rule; preserve baseline definitions.",
        "freeze_sha256": candidate["freeze_sha256"],
        "normalizer": candidate["normalizer"],
        "development_input_sha256": candidate["development_input_sha256"],
    }


def write_new(path, text):
    """Publish a complete new file, without overwriting concurrent or existing output."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                     dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(text)
            stream.close()
            os.link(temp, path)
        finally:
            temp.unlink(missing_ok=True)


def mask_ip(ip):
    if not ip:
        return None
    parts = ip.split(".")
    if len(parts) == 4 and all(part.isascii() and part.isdecimal() and int(part) < 256 for part in parts):
        return ".".join(parts[:2]) + ".x.x"
    return "[가림]"


def comparison(rows, rule_id):
    total = len(rows)
    old_covered = sum(bool(old) for old, _ in rows)
    new_covered = sum(bool(new) for _, new in rows)
    old_specific = sum(bool(old - {"B19"}) for old, _ in rows)
    new_specific = sum(bool(new - {"B19"}) for _, new in rows)
    lost = sum(len(old - new) for old, new in rows)
    return {
        "population": total,
        "coverage_before": old_covered / total if total else None,
        "coverage_after": new_covered / total if total else None,
        "specificity_before": old_specific / total if total else None,
        "specificity_after": new_specific / total if total else None,
        "lost_rule_hits": lost,
        "sessions_with_lost_rule_hits": sum(bool(old - new) for old, new in rows),
        "candidate": eval_candidates.candidate_metrics([(old, rule_id in new) for old, new in rows]),
    }


def evaluate(candidate, data_dir, baseline):
    from ml import cluster

    eval_candidates.verify(baseline, candidate["baseline_rules_sha256"])
    eval_candidates.verify(Path(cluster.__file__), candidate["normalizer"]["cluster_py_sha256"])
    if candidate["protocol"] != "telnet":
        raise ValueError("this archived candidate reader supports Telnet candidates")
    ml_path = data_dir / "ml.db"
    eval_candidates.verify(ml_path, candidate["development_input_sha256"]["ml.db"])
    rules = load_rules(baseline)
    rule_id = candidate["id"]
    if any(rule["id"] == rule_id for rule in rules):
        raise ValueError("candidate ID already exists in the baseline")
    patterns = [re.compile(raw) for raw in candidate["normalized_sequence_patterns"]]
    rows = []
    evidence = []
    for key, ip, commands in eval_candidates.archived_sessions(ml_path, splits.CUTOFF, DEV_END):
        old = set(match(rules, commands))
        normalized = cluster.normalize_session([command for _, command in commands])
        found = any(regex.fullmatch("\n".join(normalized)) for regex in patterns)
        new = old | {rule_id} if found else old
        rows.append((old, new))
        if found:
            evidence.append({"source_session": list(key), "masked_ip": mask_ip(ip),
                             "first_command_utc": commands[0][0],
                             "observed_input": label_sample.safe_observation(normalized)})
    return {
        "scope": "archived Telnet development window; exploratory",
        "candidate_id": rule_id,
        "start_utc": splits.CUTOFF,
        "end_exclusive_utc": DEV_END,
        "baseline_rules_sha256": candidate["baseline_rules_sha256"],
        "input_ml_db_sha256": candidate["development_input_sha256"]["ml.db"],
        "metrics": comparison(rows, rule_id),
        "related_sessions": evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=eval_candidates.BASELINE)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("review", "export"):
        command = commands.add_parser(action)
        command.add_argument("--registry", type=Path, required=True)
        command.add_argument("--candidate", required=True)
        if action == "export":
            command.add_argument("--version", required=True)
        else:
            command.add_argument("--data-dir", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("--bundle", type=Path, required=True)
    compare.add_argument("--data-dir", type=Path, required=True)
    compare.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "compare":
            bundle = yaml.safe_load(args.bundle.read_text(encoding="utf-8"))
            if bundle["format"] != "honeypot archived rule bundle v1":
                raise ValueError("unexpected rules bundle format")
            if bundle["baseline_rules"] != yaml.safe_load(args.baseline.read_text(encoding="utf-8")):
                raise ValueError("bundle baseline definitions differ from the supplied baseline")
            candidate = {**bundle["added_rule"], **{key: bundle[key] for key in
                         ("baseline_rules_sha256", "normalizer", "development_input_sha256")}}
            result = evaluate(candidate, args.data_dir, args.baseline)
            result["version"] = bundle["version"]
            result["rules_sha256"] = splits.sha256_file(args.bundle)
        else:
            if not args.registry.is_file():
                raise ValueError("registry does not exist")
            with closing(candidate_registry.open_registry(args.registry)) as conn:
                candidate = candidate_registry.read_candidate(conn, args.candidate)
            if args.action == "export":
                bundle = approved_version(candidate, args.baseline, args.version)
                write_new(args.out, yaml.safe_dump(bundle, allow_unicode=True, sort_keys=False))
                print(f"{bundle['baseline_rules_sha256']} -> {splits.sha256_file(args.out)}")
                return
            result = evaluate(candidate, args.data_dir, args.baseline)
            result["candidate_status"] = candidate["status"]
            result["purpose"] = "review preview only"
        write_new(args.out, json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(result["metrics"], ensure_ascii=True))
    except (ValueError, FileExistsError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
