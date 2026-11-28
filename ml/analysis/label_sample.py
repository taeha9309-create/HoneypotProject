"""Prepare blinded pilot sheets from the archived development window."""
import argparse
import csv
import json
import random
import re
from collections import Counter, defaultdict
from contextlib import closing
from itertools import groupby
from pathlib import Path

from ml.analysis import splits
from ml.analysis.eval_candidates import verify
from ml.analysis.eval_rule_removal import DEV_END

LABELS = {
    "1": "셸 진입만",
    "2": "장비·환경 정찰",
    "3": "도구·파일 반입 시도",
    "4": "지속성·정리 시도",
    "5": "기타·판정 불가",
}
COLUMNS = ("sample_id", "observed_input", "label", "notes")
VERBS = set("""enable linuxshell system shell sh bash ash busybox uname id whoami
    hostname arch pwd ls cat grep head tail echo printf cd ps top free df mount
    wget curl tftp ftp scp nc chmod chown mkdir touch cp mv rm kill pkill
    crontab nohup sleep exit logout su sudo which command export ulimit""".split())
COMMAND_START = re.compile(r"\s*(?:[\w./-]*/)?([a-z][a-z0-9_-]*)(?=\s|$)")


def safe_observation(sequence):
    """Represent ordered input with a fixed vocabulary; omit arbitrary arguments."""
    lines = []
    for command in sequence:
        match = COMMAND_START.match(command)
        if not match or match[1] not in VERBS:
            lines.append("[기타 입력 생략]")
            continue
        verb = match[1]
        if command[match.end():].strip():
            detail = "[탐침 토큰]" if verb == "busybox" and command[match.end():].strip() == "UNSTABLE" else "[인수 생략]"
            lines.append(f"{verb} {detail}")
        else:
            lines.append(verb)
    return "\n".join(lines)


def population(data_dir, t3):
    from ml.cluster import TEST_IPS, normalize_session

    hashes = t3["input_sha256"]
    ml_path = data_dir / "ml.db"
    dash_path = data_dir / "dashboard.db"
    for path in (ml_path, dash_path):
        verify(path, hashes[path.name])
    exclusions = {tuple(key) for arm in t3["candidates"].values() for candidate in arm
                  for key in candidate["support"]["session_keys"]}
    hits = set()
    with closing(splits.ro(dash_path)) as con:
        hits.update(con.execute("SELECT DISTINCT source, session_id FROM hits WHERE rule_id != 'B19'"))
    marks = ", ".join("?" for _ in TEST_IPS)
    with closing(splits.ro(ml_path)) as con:
        rows = con.execute(f"""
            SELECT s.source, s.session_id, s.src_ip, c.command
            FROM sessions AS s JOIN commands AS c USING (source, session_id)
            WHERE s.excluded = 0 AND s.n_commands > 0 AND s.protocol IN ('ssh', 'telnet')
              AND s.start_ts >= ? AND s.start_ts < ? AND c.ts < ?
              AND (s.src_ip IS NULL OR s.src_ip NOT IN ({marks}))
            ORDER BY s.source, s.session_id, c.ts, c.rowid
            """, (splits.CUTOFF, DEV_END, DEV_END, *TEST_IPS))
        groups = defaultdict(list)
        for (source, session, ip), group in groupby(rows, lambda row: row[:3]):
            sequence = normalize_session([row[3] for row in group])
            key = source, session
            if sequence and key not in exclusions:
                groups[sequence].append((key, ip, key in hits))
    return groups


def allocate(groups, total, common, seed):
    if total > len(groups) or total < common or (total - common) % 2:
        raise ValueError("need enough distinct sequences and equal exclusive sheet sizes")
    rng = random.Random(seed)
    strata = {"gap": [], "comparison": []}
    for sequence, members in sorted(groups.items()):
        # A sequence enters the comparison stratum if any member has a specific baseline rule.
        stratum = "comparison" if any(member[2] for member in members) else "gap"
        eligible = [member for member in members if member[2] == (stratum == "comparison")]
        strata[stratum].append((sequence, eligible, len(members), stratum))
    gap = min(len(strata["gap"]), max(total // 2, total - len(strata["comparison"])))
    selected = []
    shared = []
    for stratum, count in (("gap", gap), ("comparison", total - gap)):
        items = rng.sample(strata[stratum], count)
        shared_count = round(common * gap / total) if stratum == "gap" else common - round(common * gap / total)
        shared.extend(items[:shared_count])
        selected.extend(items[shared_count:])
    rng.shuffle(selected)
    assignments = {"A": [], "B": [], "shared": []}
    ip_counts = {key: Counter() for key in assignments}
    stratum_counts = {key: Counter() for key in assignments}
    exclusive = (total - common) // 2
    for sequence, eligible, weight, stratum in shared + selected:
        common_row = len(assignments["shared"]) < common
        slots = ["shared"] if common_row else [r for r in ("A", "B") if len(assignments[r]) < exclusive]
        options = [(r, member) for r in slots for member in eligible]
        rng.shuffle(options)
        rater, (key, ip, _) = min(options, key=lambda item: (
            ip_counts[item[0]][item[1][1]] if item[1][1] else 0,
            stratum_counts[item[0]][stratum], len(assignments[item[0]])))
        ip_counts[rater][ip] += 1
        stratum_counts[rater][stratum] += 1
        assignments[rater].append((sequence, key, weight, stratum))
    return assignments


def blind(assignments, seed):
    rng = random.Random(seed)
    mapping = []
    sheets = {}
    for rater in ("A", "B"):
        order = list(assignments[rater] + assignments["shared"])
        rng.shuffle(order)
        if rater == "B":
            shared = {item[1] for item in assignments["shared"]}
            a_order = [tuple(row["source_session"]) for row in mapping if row["shared"]]
            if len(shared) > 1 and [item[1] for item in order if item[1] in shared] == a_order:
                order.reverse()
        sheets[rater] = []
        shared = {item[1] for item in assignments["shared"]}
        for index, (sequence, key, weight, stratum) in enumerate(order, 1):
            sample_id = f"{rater}-{index:03}"
            sheets[rater].append({"sample_id": sample_id, "observed_input": safe_observation(sequence),
                                  "label": "", "notes": ""})
            mapping.append({"sample_id": sample_id, "rater": rater, "source_session": list(key),
                            "sequence_session_weight": weight, "stratum": stratum, "shared": key in shared})
    return sheets, mapping


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--t3", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--pilot", action="store_true")
    args = parser.parse_args()
    t3 = json.loads(args.t3.read_text(encoding="utf-8"))
    from ml import cluster
    verify(Path(cluster.__file__), t3["ml_version"]["cluster_py_sha256"])
    groups = population(args.data_dir, t3)
    count = min(100, 2 * (len(groups) // 2)) if args.pilot else 100
    assignments = allocate(groups, count, 20, args.seed)
    sheets, mapping = blind(assignments, args.seed)
    args.out.mkdir(parents=True, exist_ok=False)
    for rater, sheet in sheets.items():
        with (args.out / f"rater_{rater}.csv").open("x", encoding="utf-8-sig", newline="") as file:
            writer = csv.DictWriter(file, COLUMNS)
            writer.writeheader()
            writer.writerows(sheet)
    manifest = {
        "status": "development pilot" if count < 100 else "development sample",
        "requested_distinct_sequences": 100,
        "eligible_distinct_sequences": len(groups),
        "sampled_distinct_sequences": count,
        "common": 20,
        "exclusive_per_rater": (count - 20) // 2,
        "start_utc": splits.CUTOFF,
        "end_exclusive_utc": DEV_END,
        "input_sha256": t3["input_sha256"],
        "t3_sha256": splits.sha256_file(args.t3),
        "seed": args.seed,
        "labels": LABELS,
        "rows": mapping,
    }
    (args.out / "private_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                                                    encoding="utf-8")
    print(f"{count} sampled from {len(groups)} eligible; {20 + (count - 20) // 2} rows per rater")


if __name__ == "__main__":
    main()
