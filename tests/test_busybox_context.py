"""Synthetic fixtures for BusyBox context aggregation."""
import unittest

from ml.analysis.busybox_context import summarize


class ContextTests(unittest.TestCase):
    def test_adjacent_input_and_marker_counts_do_not_export_raw_data(self):
        records = [
            (("sh", "/bin/busybox UNSTABLE"), "192.0.2.1", {"B19"}),
            (("busybox CUSTOM", "private"), "192.0.2.2", {"B01", "B19"}),
            (("sh",), "192.0.2.2", {"B19"}),
        ]
        result = summarize(records)
        self.assertEqual(result["single_token_busybox_sessions"], 2)
        self.assertEqual(result["terminal_probe_sessions"], 1)
        self.assertEqual(result["marker_occurrences"], {"UNSTABLE": 1, "other_token": 1})
        self.assertEqual(result["preceding_input_occurrences"], {"sh": 1, "boundary": 1})
        self.assertEqual(result["following_input_occurrences"], {"boundary": 1, "other": 1})
        self.assertEqual(result["probe_ips_with_other_command_sessions"], 1)
        for private_value in ("192.0.2.2", "CUSTOM", "private"):
            self.assertNotIn(private_value, str(result))

    def test_nested_or_multitoken_busybox_input_is_not_counted(self):
        result = summarize([(("echo busybox UNSTABLE", "busybox echo more"), None, set())])
        self.assertEqual(result["single_token_busybox_sessions"], 0)
