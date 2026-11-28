"""Persist deduplicated label drafts and immutable per-snapshot evidence."""
import argparse
from contextlib import closing
from hashlib import sha256
import json
import sqlite3
from pathlib import Path

from ml.analysis import candidate_registry, signature_proposal, signature_validation

DEFAULT_REGISTRY = Path(__file__).resolve().parents[2] / "work/review/candidates.db"


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def register_report(path, report):
    if report["mode"] != "local_demo":
        raise ValueError("unsupported proposal provider")
    identity = {key: report[key] for key in signature_validation.SNAPSHOT_KEYS}
    snapshot = sha256(canonical(identity).encode()).hexdigest()
    records = []
    for entry in report["groups"]:
        proposal = entry["proposal"]
        if proposal["decision"] == "abstain":
            continue
        steps = proposal["draft_steps"]
        if (entry["protocol"] not in ("ssh", "telnet") or not isinstance(steps, list)
                or not 2 <= len(steps) <= 8 or any(
                    not isinstance(s, str) or not signature_proposal.safe_step(s)
                    or s == signature_proposal.UNKNOWN or s.endswith(signature_proposal.OMITTED_ARGUMENTS)
                    for s in steps) or entry["validation"] is None):
            raise ValueError("invalid checked draft")
        payload = {"format": "redacted_sequence_v1", "protocol": entry["protocol"], "draft_steps": steps}
        candidate_id = "P" + sha256(canonical(payload).encode()).hexdigest()
        records.append((candidate_id, payload, str(entry["cluster_id"]), entry))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(candidate_registry.open_registry(path)) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS discoveries (
            candidate_id TEXT NOT NULL REFERENCES candidates(id), snapshot TEXT NOT NULL,
            cluster_id TEXT NOT NULL, identity TEXT NOT NULL, evidence TEXT NOT NULL,
            PRIMARY KEY(candidate_id,snapshot,cluster_id))""")
        with conn:
            for cid, payload, cluster, entry in records:
                payload.update({"id": cid, "name": " → ".join(payload["draft_steps"])})
                serialized = canonical(payload)
                conn.execute("INSERT OR IGNORE INTO candidates(id,payload,status) VALUES (?,?,'proposed')",
                             (cid, serialized))
                if conn.execute("SELECT payload FROM candidates WHERE id=?", (cid,)).fetchone()[0] != serialized:
                    raise ValueError("candidate identity collision")
                existing = conn.execute("""SELECT evidence FROM discoveries
                    WHERE candidate_id=? AND snapshot=? AND cluster_id=?""", (cid,snapshot,cluster)).fetchone()
                evidence = canonical(entry)
                if existing and existing[0] != evidence:
                    raise ValueError("snapshot evidence changed; rebuild with a new snapshot identity")
                conn.execute("INSERT OR IGNORE INTO discoveries VALUES (?,?,?,?,?)",
                             (cid,snapshot,cluster,canonical(identity),evidence))
    return len({cid for cid, *_ in records})


def load(path):
    path = Path(path)
    if not path.exists():
        return []
    with closing(sqlite3.connect(path.resolve().as_uri()+"?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='discoveries'").fetchone():
            return []
        result = []
        for row in conn.execute("""SELECT * FROM candidates WHERE id IN
                                  (SELECT candidate_id FROM discoveries) ORDER BY id"""):
            item = json.loads(row["payload"])
            item.update({k:row[k] for k in ("status","reviewer","decided_utc","reason")})
            item["discoveries"] = [
                {"snapshot":snapshot, "identity":json.loads(identity), "evidence":json.loads(evidence)}
                for snapshot,identity,evidence in conn.execute(
                    "SELECT snapshot,identity,evidence FROM discoveries WHERE candidate_id=? ORDER BY rowid DESC",
                    (row["id"],))]
            result.append(item)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--registry",type=Path,default=DEFAULT_REGISTRY)
    args=parser.parse_args()
    print(f"Registered {register_report(args.registry,json.loads(args.report.read_text(encoding='utf-8')))} distinct drafts")


if __name__ == "__main__":
    main()
