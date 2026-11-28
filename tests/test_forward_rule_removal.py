"""Synthetic tests for selection and scoring in forward E1."""
from argparse import Namespace
from contextlib import closing
from datetime import datetime, timezone
from importlib import metadata
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from ml import cluster
from ml.analysis import forward_rule_removal as e1, splits


class ForwardE1Tests(unittest.TestCase):
    def test_fit_only_and_held_labels_scored_on_the_same_population(self):
        with tempfile.TemporaryDirectory(prefix="e1#test-") as folder:
            root = Path(folder)
            start, end = "2026-11-01T00:00:00Z", "2026-12-02T00:00:00Z"
            archived, training, held = [root / name for name in ("archive.db", "train.db", "held.db")]
            for path, sessions in [
                (archived, [("syd", "fit", start), ("seoul", "old-holdout", start)]),
                (training, [("syd", "fit", start), ("seoul", "old-holdout", start)]),
                (held, [("seoul", "new", end), ("seoul", "old-holdout", end)]),
            ]:
                with closing(sqlite3.connect(path)) as db, db:
                    db.executescript("""
                        CREATE TABLE sessions(source,session_id,src_ip,protocol,excluded,start_ts,end_ts,n_commands);
                        CREATE TABLE commands(source,session_id,ts,command);
                        CREATE TABLE ml_clusters(source,session_id,protocol,cluster_id,assigned_by);
                    """)
                    for source, key, ts in sessions:
                        db.execute("INSERT INTO sessions VALUES (?,?,'192.0.2.1','telnet',0,?,?,1)",
                                   (source, key, ts, ts))
                        db.execute("INSERT INTO commands VALUES (?,?,?,'uname')", (source, key, ts))
                        db.execute("INSERT INTO ml_clusters VALUES (?,?,'telnet',7,?)",
                                   (source, key, "fit" if key == "fit" else "assign"))
            baseline = root / "baseline.yaml"
            baseline.write_text("- id: B11\n  type: behavior\n  patterns: ['^uname$']\n", encoding="utf-8")
            model = root / "telnet.joblib"
            model.write_bytes(b"synthetic model placeholder")
            plan = {
                "status": "confirmed", "frozen_at_utc": "2026-12-01T00:00:00Z",
                "min_days": 1, "min_telnet_sessions": 1,
                "e1": {
                    "training_end_exclusive_utc": "2026-11-26T00:00:00Z",
                    "edit_threshold": 0.5, "replicates": 20, "seed": 42,
                    "baseline_rules_sha256": splits.sha256_file(baseline),
                    "training_db_sha256": splits.sha256_file(training),
                    "development_db_sha256": splits.sha256_file(archived),
                    "telnet_model_sha256": splits.sha256_file(model),
                    "cluster_py_sha256": splits.sha256_file(Path(cluster.__file__)),
                    "normalize_version": cluster.NORMALIZE_VERSION,
                    "hdbscan": metadata.version("hdbscan"), "scikit_learn": metadata.version("scikit-learn"),
                },
            }
            receipt = {
                "collection_start_utc": "2026-12-01T00:00:00Z",
                "collection_end_exclusive_utc": "2026-12-03T00:00:00Z",
                "received_at_utc": "2026-12-03T00:00:00Z",
                "previously_accessed": False, "sources": ["seoul"],
                "database_sha256": splits.sha256_file(held),
            }
            freeze, receipt_file = root / "freeze.json", root / "receipt.json"
            freeze.write_text(json.dumps(plan), encoding="utf-8")
            receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
            args = Namespace(freeze=freeze, receipt=receipt_file, baseline=baseline, training_db=training,
                             development_db=archived, new_db=held, telnet_model=model)
            now = datetime(2026, 12, 4, tzinfo=timezone.utc)
            with patch.object(e1, "model_labels", return_value=[7]) as predict:
                result = e1.evaluate(args, now)
            predict.assert_called_once_with([("uname",)], model)
            self.assertEqual(result["training_sessions"], 1)
            self.assertEqual(result["exclusions"]["seen_development_session"], 1)
            rules = result["populations"]["all"]["metrics"]["unique_seq"]
            self.assertEqual(rules["D_ml_cluster"]["rules"]["B11"]["recall"]["value"], 1.0)
            self.assertEqual(rules["A_signatures_only"]["rules"]["B11"]["recall"]["value"], 0.0)
            plan["e1"]["training_end_exclusive_utc"] = "2026-12-02T00:00:00Z"
            with self.assertRaisesRegex(ValueError, "overlaps"):
                e1.check_settings(plan, receipt, now)
