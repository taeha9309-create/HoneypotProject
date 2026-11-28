"""Review contract tests using local fake responses and redacted flows."""
import unittest

from ml.analysis.signature_proposal import build_request, demo_provider, review


def group(steps):
    return {
        "protocol": "telnet", "cluster_id": 4, "cluster_sessions": 8, "gap_sessions": 6,
        "recurrent_gap_sessions": 4, "raw": "192.0.2.1",
        "representative_flows": [{"observed_flow": "\n".join(steps), "sessions": 4,
                                  "ips": 2, "steps_omitted": 0, "secret": "password"}],
    }


class SignatureProposalTests(unittest.TestCase):
    def test_demo_proposal_uses_only_the_redacted_request(self):
        fixture = group(["sh", "busybox [탐침 토큰]"])
        request = build_request(fixture)
        self.assertNotIn("192.0.2.1", str(request))
        self.assertNotIn("password", str(request))
        result = review(fixture)
        self.assertEqual(result["decision"], "propose")
        self.assertEqual(result["draft_steps"], ["sh", "busybox [탐침 토큰]"])
        self.assertEqual(result["evidence"][0]["sessions"], 4)

    def test_insufficient_evidence_returns_no_draft(self):
        result = review(group(["sh", "cat [인수 생략]"]))
        self.assertEqual(result["decision"], "abstain")
        self.assertIsNone(result["draft_steps"])

    def test_rejects_raw_flow_and_fabricated_evidence(self):
        with self.assertRaisesRegex(ValueError, "redacted vocabulary"):
            review(group(["sh", "cat private.example/file"]))

        def fabricated(request):
            reply = demo_provider(request)
            reply["draft"]["positions"] = [0, 99]
            return reply

        with self.assertRaisesRegex(ValueError, "observed flow"):
            review(group(["sh", "busybox [탐침 토큰]"]), fabricated)

    def test_provider_cannot_mutate_the_observation_to_invent_a_draft(self):
        def altered(request):
            request["representative_flows"][0]["steps"][1] = "busybox [탐침 토큰]"
            return demo_provider(request)

        with self.assertRaisesRegex(ValueError, "omitted arguments"):
            review(group(["sh", "cat [인수 생략]"]), altered)
