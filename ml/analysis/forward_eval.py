"""Evaluate frozen X04/X06 candidates on an approved post-freeze database copy."""
import argparse
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re

from match_signatures import event_time, load_rules, match
from ml.analysis import eval_candidates, splits
from ml.analysis.rules_version import write_new
from ml.analysis.eval_rule_removal import DEV_END

SOURCES = {"seoul", "syd"}


def utc(value, field):
    timestamp = event_time(value)
    if timestamp is None:
        raise ValueError(f"{field} must contain a timezone-aware timestamp")
    return timestamp


def check_window(plan, receipt, now):
    if plan.get("status") != "confirmed":
        raise ValueError("a confirmed final freeze is required")
    frozen = utc(plan["frozen_at_utc"], "frozen_at_utc")
    if frozen < datetime.fromisoformat(DEV_END).replace(tzinfo=timezone.utc):
        raise ValueError("final freeze cannot precede the archived development boundary")
    start = utc(receipt["collection_start_utc"], "collection_start_utc")
    end = utc(receipt["collection_end_exclusive_utc"], "collection_end_exclusive_utc")
    received = utc(receipt["received_at_utc"], "received_at_utc")
    if not frozen <= start < end <= received <= now:
        raise ValueError("collection and receipt must follow the freeze and end by the current time")
    if receipt.get("previously_accessed") is not False:
        raise ValueError("receipt must attest that the batch was not previously accessed")
    if (type(plan["min_days"]) is not int or plan["min_days"] < 1
            or type(plan["min_telnet_sessions"]) is not int or plan["min_telnet_sessions"] < 1):
        raise ValueError("freeze must specify positive integer pilot thresholds")
    sources = set(receipt["sources"])
    if not sources or not sources <= SOURCES:
        raise ValueError("receipt must list valid sources")
    return start, end, sources


def forward_sessions(connection, known, start, end, sources, test_ips, exclusions):
    """Yield complete eligible Telnet sequences without exposing raw input in reports."""
    cursor = connection.execute("""SELECT source, session_id, src_ip, protocol, excluded,
                                          start_ts, end_ts, n_commands
                                   FROM sessions ORDER BY source, session_id""")
    for source, sid, ip, protocol, excluded, start_raw, end_raw, count in cursor:
        key = source, sid
        began, ended = event_time(start_raw), event_time(end_raw)
        if source not in sources:
            exclusions["outside_receipt_sources"] += 1
        elif key in known:
            exclusions["seen_development_session"] += 1
        elif protocol != "telnet" or excluded or ip in test_ips or not count:
            exclusions["outside_population"] += 1
        elif began is None or ended is None:
            exclusions["missing_or_invalid_session_time"] += 1
        elif not start <= began <= ended < end:
            exclusions["outside_collection_window"] += 1
        else:
            rows = connection.execute("""
                SELECT ts, command FROM commands WHERE source=? AND session_id=? ORDER BY rowid
                """, key).fetchall()
            ordered = [(event_time(ts), ts, cmd) for ts, cmd in rows]
            if len(rows) != count or any(ts is None or not began <= ts <= ended for ts, _, _ in ordered):
                exclusions["incomplete_or_outside_session_commands"] += 1
            else:
                ordered.sort(key=lambda item: item[0])
                yield source, ip, [(raw, command) for _, raw, command in ordered]


def scores(records):
    """Aggregate at session, unique normalized sequence and IP levels."""
    units = {"session": [(r[2], r[3], r[4]) for r in records]}
    for name, index in (("unique_seq", 0), ("ip", 1)):
        groups = {}
        for row in records:
            key = row[index]
            if key is None:
                continue
            rules, a, b = groups.get(key, (set(), False, False))
            groups[key] = (rules | row[2], a or row[3], b or row[4])
        units[name] = list(groups.values())
    return {name: {
        "X04": eval_candidates.candidate_metrics([(rules, a) for rules, a, _ in rows]),
        "X06": eval_candidates.candidate_metrics([(rules, b) for rules, _, b in rows]),
        "X04_and_X06": sum(a and b for _, a, b in rows),
    } for name, rows in units.items()}


def evaluate(args, now=None):
    plan = json.loads(args.freeze.read_text(encoding="utf-8"))
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    start, end, sources = check_window(plan, receipt, now or datetime.now(timezone.utc))

    from ml import cluster

    eval_candidates.verify(args.candidates, plan["candidate_manifest_sha256"])
    candidates = json.loads(args.candidates.read_text(encoding="utf-8"))
    if utc(candidates["frozen_at_utc"], "candidate freeze") > utc(plan["frozen_at_utc"], "final freeze"):
        raise ValueError("final freeze cannot precede the candidate freeze")
    eval_candidates.verify(args.x04, candidates["X04"]["sha256"])
    eval_candidates.verify(args.baseline, candidates["baseline_rules_sha256"])
    eval_candidates.verify(Path(cluster.__file__), candidates["normalizer"]["cluster_py_sha256"])
    if (candidates["normalizer"]["normalize_version"] != cluster.NORMALIZE_VERSION
            or candidates["X06"]["protocol"] != "telnet"):
        raise ValueError("candidate format or normalizer version differs from the freeze")
    known_hash = candidates["development_input_sha256"]["ml.db"]
    if receipt["database_sha256"] in candidates["development_input_sha256"].values():
        raise ValueError("receipt identifies an archived development database")
    eval_candidates.verify(args.development_db, known_hash)
    eval_candidates.verify(args.new_db, receipt["database_sha256"])

    with closing(splits.ro(args.development_db)) as con:
        known = set(con.execute("SELECT source, session_id FROM sessions"))
    exclusions = Counter()
    baseline, x04 = load_rules(args.baseline), load_rules(args.x04)
    x06 = [re.compile(pattern) for pattern in candidates["X06"]["regexes"]]
    populations = {source: [] for source in sorted(sources)}
    with closing(splits.ro(args.new_db)) as con:
        for source, ip, commands in forward_sessions(con, known, start, end, sources, cluster.TEST_IPS, exclusions):
            seq = cluster.normalize_session([command for _, command in commands])
            old = set(match(baseline, commands))
            a = "X04" in match(x04, commands)
            b = any(pattern.fullmatch("\n".join(seq)) for pattern in x06)
            populations[source].append((seq, ip, old, a, b))
    total = [row for items in populations.values() for row in items]
    eval_candidates.verify(args.new_db, receipt["database_sha256"])
    eval_candidates.verify(args.development_db, known_hash)
    pilot_reasons = []
    if end - start < timedelta(days=plan["min_days"]):
        pilot_reasons.append("collection shorter than frozen minimum")
    if len(total) < plan["min_telnet_sessions"]:
        pilot_reasons.append("eligible sessions below frozen minimum")
    return {
        "scope": "post-freeze E3, Telnet on database copies",
        "status": "no_eligible_sessions" if not total else "pilot" if pilot_reasons else "evaluated",
        "pilot_reasons": pilot_reasons,
        "freeze_sha256": splits.sha256_file(args.freeze),
        "receipt_sha256": splits.sha256_file(args.receipt),
        "candidates_sha256": plan["candidate_manifest_sha256"],
        "baseline_rules_sha256": candidates["baseline_rules_sha256"],
        "database_sha256": receipt["database_sha256"],
        "frozen_at_utc": plan["frozen_at_utc"],
        "start_utc": start.isoformat(),
        "end_exclusive_utc": end.isoformat(),
        "exclusions": dict(exclusions),
        "results": {"all": scores(total), **{source: scores(rows) for source, rows in populations.items()}},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("freeze", "receipt", "candidates", "development-db", "new-db", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--x04", type=Path, default=eval_candidates.X04)
    parser.add_argument("--baseline", type=Path, default=eval_candidates.BASELINE)
    args = parser.parse_args()
    try:
        report = evaluate(args)
        write_new(args.out, json.dumps(report, ensure_ascii=True, indent=2) + "\n")
        print(f"{report['status']}: {report['results']['all']['session']['X06']['population']} Telnet sessions")
    except (ValueError, FileExistsError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
