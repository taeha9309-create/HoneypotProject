"""Candidate alerts are deduplicated with delivery records without network access."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from streamlit_app import candidate_alerts, slack_delivery
from test_slack_delivery import snapshot

class CandidateAlertTests(unittest.TestCase):
    def test_counts_only_and_repeat_delivery(self):
        candidate={"id":"P"+"a"*64,"status":"proposed","protocol":"telnet",
                   "name":"private input","discoveries":[{"evidence":{"validation":{"all":{
                       "population":100,"matches":10,"b19_only_refined":8,"already_specific":2}}}}]}
        with patch.object(candidate_alerts.proposal_registry,"load",return_value=[candidate]):
            items=candidate_alerts.messages(None)
        self.assertNotIn("private input",items[0]["text"])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"alerts.db"
            sent=[]
            slack_delivery.deliver(snapshot(),path,"test",sent.append,items)
            self.assertEqual(len(sent),3)
            self.assertEqual(slack_delivery.deliver(snapshot(),path,"test",sent.append,items),(0,0))
        candidate["status"]="rejected"
        with patch.object(candidate_alerts.proposal_registry,"load",return_value=[candidate]):
            self.assertEqual(candidate_alerts.messages(None),[])
