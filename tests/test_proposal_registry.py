import copy
import tempfile
import unittest
from pathlib import Path
from contextlib import closing
from ml.analysis import proposal_registry as R, candidate_registry as C

class ProposalRegistryTests(unittest.TestCase):
    def test_repeat_discovery_and_decision_preservation(self):
        report={"mode":"local_demo","rules_sha256":"rules","built_at_utc":"build","trained_at_utc":"model",
                "groups":[{"protocol":"telnet","cluster_id":i,"proposal":{"decision":"propose","draft_steps":["sh","uname"]},
                           "validation":{"all":{"matches":2}}} for i in (5,7)]}
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"registry.db"
            self.assertEqual(R.register_report(p,report),1)
            R.register_report(p,report)
            rows=R.load(p)
            self.assertEqual(len(rows),1)
            self.assertEqual(len(rows[0]["discoveries"]),2)
            with closing(C.open_registry(p)) as conn:
                C.decide(conn,rows[0]["id"],"rejected","reviewer","too broad")
            newer=copy.deepcopy(report)
            newer["built_at_utc"]="next build"
            R.register_report(p,newer)
            self.assertEqual(R.load(p)[0]["status"],"rejected")
            self.assertEqual(len(R.load(p)[0]["discoveries"]),4)
            broken=copy.deepcopy(newer)
            broken["groups"][1]["validation"]["all"]["matches"]=9
            with self.assertRaises(ValueError):
                R.register_report(p,broken)
            self.assertEqual(len(R.load(p)[0]["discoveries"]),4)
