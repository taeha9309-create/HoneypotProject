"""Measure locally how broadly a grounded signature draft would match.

Input steps are labels from the redacted review vocabulary. This evaluates a
contiguous label sequence, without generating regexes or changing rules.
"""
import argparse
from collections import Counter, defaultdict
from contextlib import closing
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from ml.analysis import (eval_candidates, label_sample, rule_combo_clusters,
                         signature_proposal, signature_review_groups)
from ml.analysis.rules_version import write_new

REPORT_NAME = "signature_proposal_validation.json"
SNAPSHOT_KEYS = ("rules_sha256", "built_at_utc", "trained_at_utc")


@dataclass(frozen=True)
class Session:
    source: str
    protocol: str
    cluster_id: int | None
    ip: str | None
    observed: tuple
    rules: frozenset


def load_snapshot(data_dir, rules, scan_report):
    """Read the full matching protocol population, including unassigned sessions."""
    from ml import cluster

    with closing(rule_combo_clusters.open_readonly(data_dir)) as con:
        meta = dict(con.execute("SELECT key, value FROM dash.meta"))
        trained = con.execute("SELECT value FROM ml_meta WHERE key='trained_at'").fetchone()
        identity = {"rules_sha256": meta.get("rules_sha256"), "built_at_utc": meta.get("built_at"),
                    "trained_at_utc": trained[0] if trained else None}
        if (not identity["built_at_utc"]
                or identity["rules_sha256"] != sha256(Path(rules).read_bytes()).hexdigest()
                or any(scan_report[key] != identity[key] for key in SNAPSHOT_KEYS)):
            raise ValueError("review report and dashboard snapshot differ; rebuild first")
        hits = defaultdict(set)
        for source, sid, rule in con.execute("SELECT source, session_id, rule_id FROM dash.hits"):
            hits[(source, sid)].add(rule)
        labels = {(source, sid): (proto, cid) for source, sid, proto, cid in con.execute(
            "SELECT source, session_id, protocol, cluster_id FROM ml_clusters")}
        observations = {}
        rows = []
        for key, session in cluster.load_sessions(con).items():
            protocol = session["protocol"]
            if protocol not in ("ssh", "telnet"):
                continue
            seq = cluster.normalize_session(session["cmds"])
            if seq not in observations:
                observations[seq] = tuple(label_sample.safe_observation(seq).splitlines())
            labeled_protocol, cid = labels.get(key, (protocol, None))
            if labeled_protocol != protocol:
                raise ValueError("session protocol differs from its clustering assignment")
            rows.append(Session(key[0], protocol, cid, session["src_ip"], observations[seq],
                                frozenset(hits.get(key, ()))))
        return rows, identity


def evaluate(steps, group, sessions):
    if (not isinstance(steps, list) or not 2 <= len(steps) <= 8
            or any(not isinstance(step, str) or not signature_proposal.safe_step(step)
                   or step == signature_proposal.UNKNOWN or step.endswith(signature_proposal.OMITTED_ARGUMENTS)
                   for step in steps)):
        raise ValueError("draft must have supported, fully observed steps")
    if group["protocol"] not in ("ssh", "telnet") or type(group["cluster_id"]) is not int or group["cluster_id"] < 0:
        raise ValueError("draft origin must be a non-noise cluster")
    sequence = tuple(steps)
    origin = group["cluster_id"]
    by_scope = {"all": [], "origin_cluster": [], "outside_cluster": []}
    by_source = defaultdict(list)
    matched_ips = Counter()
    for row in sessions:
        if row.protocol != group["protocol"]:
            continue
        found = any(row.observed[i:i + len(sequence)] == sequence
                    for i in range(len(row.observed) - len(sequence) + 1))
        pair = (row.rules, found)
        by_scope["all"].append(pair)
        by_scope["origin_cluster" if row.cluster_id == origin else "outside_cluster"].append(pair)
        by_source[row.source].append(pair)
        if found and row.ip:
            matched_ips[row.ip] += 1
    if not by_scope["origin_cluster"]:
        raise ValueError("origin cluster is absent from the snapshot")
    summary = {name: eval_candidates.candidate_metrics(rows) for name, rows in by_scope.items()}
    flags = []
    if not summary["all"]["matches"]:
        flags.append("no_matches")
    if summary["outside_cluster"]["matches"]:
        flags.append("matches_outside_cluster")
    if summary["all"]["already_specific"]:
        flags.append("overlaps_specific_rules")
    if len(matched_ips) == 1:
        flags.append("single_known_ip")
    return {
        "method": "contiguous sequence of redacted labels, same protocol",
        "scope": "same snapshot as discovery; descriptive review only",
        **summary,
        "sources": {source: eval_candidates.candidate_metrics(rows) for source, rows in sorted(by_source.items())},
        "distinct_matched_ips": len(matched_ips),
        "top_known_ip_share": max(matched_ips.values()) / sum(matched_ips.values()) if matched_ips else None,
        "flags": flags,
    }


def build(data_dir, rules, scan_report, provider=signature_proposal.demo_provider):
    rows, identity = load_snapshot(data_dir, rules, scan_report)
    entries = []
    duplicates = defaultdict(list)
    for group in scan_report["groups"]:
        proposal = signature_proposal.review(group, provider)
        entry = {"protocol": group["protocol"], "cluster_id": group["cluster_id"], "proposal": proposal,
                 "validation": None, "same_draft_other_clusters": []}
        if proposal["decision"] == "propose":
            steps = proposal["draft_steps"]
            entry["validation"] = evaluate(steps, group, rows)
            duplicates[(entry["protocol"], tuple(steps))].append(entry)
        entries.append(entry)
    for related in duplicates.values():
        ids = sorted(entry["cluster_id"] for entry in related)
        for entry in related:
            entry["same_draft_other_clusters"] = [cid for cid in ids if cid != entry["cluster_id"]]
    return {**identity, "mode": "local_demo", "proposed_groups": sum(
        entry["validation"] is not None for entry in entries), "distinct_drafts": len(duplicates), "groups": entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--rules", type=Path, default=Path("signatures/rules.yaml"))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        filename = args.data_dir / signature_review_groups.REPORT_NAME
        scan_report = json.loads(filename.read_text(encoding="utf-8"))
        report = build(args.data_dir, args.rules, scan_report)
        write_new(args.out or args.data_dir / REPORT_NAME,
                  json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(f"검사한 초안 {report['proposed_groups']}개 · 중복 제거 {report['distinct_drafts']}개")


if __name__ == "__main__":
    main()
