from pathlib import Path
import unittest

from command_behaviors import observe, literal_commands
from match_signatures import load_rules, match

ROOT = Path(__file__).resolve().parents[1]


class PasswordChangeTests(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(ROOT / 'signatures/rules.yaml')

    def detected(self, command):
        return 'B03' in match(self.rules, [('2026-11-02T00:00:00Z', command)])

    def test_environment_assignment_development_cases(self):
        for command in ['LC_ALL=C passwd', 'LC_ALL=C passwd test',
                        'LC_ALL=C passwd oracle', 'LC_ALL=C passwd test1']:
            with self.subTest(command=command):
                self.assertTrue(self.detected(command))

    def test_assignment_quoting_and_multiple_values(self):
        for command in ['LC_ALL="C.UTF-8" passwd user', "A='one two' LC_ALL=C passwd",
                        'A= passwd', r'A=one\ two passwd', 'A="" passwd',
                        'LC_ALL=C /usr/bin/passwd user', 'LC_ALL=C busybox passwd user']:
            with self.subTest(command=command):
                self.assertTrue(self.detected(command))

    def test_direct_and_piped_invocations(self):
        for command in ['passwd', 'passwd user', '/usr/bin/passwd', 'busybox passwd',
                        'printf "%s\\n" example example | passwd',
                        'passwd -- user', 'passwd -d user', 'passwd --expire user',
                        'printf "%s\\n" user:example | chpasswd',
                        'LC_ALL=C chpasswd -e', 'chpasswd --md5']:
            with self.subTest(command=command):
                self.assertTrue(self.detected(command))

    def test_new_detector_excludes_queries_and_help(self):
        for command in ['passwd -S user', 'passwd --status user', 'passwd -Sa',
                        'passwd -a', 'passwd --help', 'passwd --version',
                        'LC_ALL=C passwd -S user', 'chpasswd --help',
                        'chpasswd --version', 'passwd -n 1 user']:
            with self.subTest(command=command):
                self.assertNotIn('password_change', observe(command))
        self.assertFalse(self.detected('LC_ALL=C passwd -S user'))

    def test_new_detector_excludes_quoted_text_and_comments(self):
        for command in ['echo "chpasswd"', 'echo "text; passwd user"',
                        "printf '%s' 'LC_ALL=C passwd user'", '# passwd user',
                        "'LC_ALL=C' passwd user", 'LC_ALL="C passwd user"',
                        'echo LC_ALL=C passwd user', 'cat /etc/passwd',
                        'grep chpasswd notes.txt', 'echo "LC_ALL=C; chpasswd"']:
            with self.subTest(command=command):
                self.assertNotIn('password_change', observe(command))

    def test_malformed_and_dynamic_forms_are_unsupported(self):
        for command in ["LC_ALL='C passwd", 'LC_ALL=$(echo C) passwd',
                        'LC_ALL=C passwd $USER', 'LC_ALL=C $PASSWD user',
                        'passwd user extra', 'LC_ALL=C',
                        r'echo -e "a"b\nexample\nexample"|passwd|bash']:
            with self.subTest(command=command):
                self.assertNotIn('password_change', observe(command))

    def test_legacy_dynamic_pipeline_detection_is_preserved(self):
        # Parsing the substitution is unsupported, but the previous B03 regex
        # match must not be lost by adding the new observation path.
        self.assertTrue(self.detected('echo "$(printf example)" | passwd'))

    def test_count_rows_not_prefixes_or_multiple_tools(self):
        row = [('2026-11-02T00:00:00Z', 'A=1 B=2 passwd; chpasswd')]
        self.assertEqual(match(self.rules, row)['B03'], ('2026-11-02T00:00:00Z', 1))

    def test_assignment_support_preserves_other_observations(self):
        self.assertEqual(list(literal_commands('A="hello world" cat /proc/self/exe')),
                         [(['cat', '/proc/self/exe'], None)])
        self.assertIn('self_exe_read', observe('A=1 cat /proc/self/exe'))
        self.assertNotIn('self_exe_read', observe("'A=1' cat /proc/self/exe"))


if __name__ == '__main__':
    unittest.main()
