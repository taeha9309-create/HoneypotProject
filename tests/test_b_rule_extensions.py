from pathlib import Path
import unittest

from command_behaviors import observe
from match_signatures import load_rules, match

ROOT = Path(__file__).resolve().parents[1]


class BRuleExtensionsTests(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(ROOT / 'signatures/rules.yaml')

    def hits(self, text):
        return match(self.rules, [('2026-11-02T00:00:00Z', text)])

    def test_b04_writes_and_atomic_replacement(self):
        for cmd in ['echo "ssh-rsa EXAMPLE" >> ~/.ssh/authorized_keys',
                    'LC_ALL=C echo ssh-rsa EXAMPLE >>~/.ssh/authorized_keys',
                    'printf "%s" example > /root/.ssh/authorized_keys',
                    'cat /tmp/public_key > .ssh/authorized_keys',
                    'mv .ssh/.auth_k .ssh/authorized_keys',
                    'cp -f /tmp/key /home/user/.ssh/authorized_keys',
                    'cat /tmp/key | tee -a ~/.ssh/authorized_keys',
                    '> ~/.ssh/authorized_keys',
                    'busybox cp key .ssh/authorized_keys2']:
            with self.subTest(cmd=cmd):
                self.assertIn('B04', self.hits(cmd))

    def test_b04_read_query_and_backup_are_not_key_writes(self):
        for cmd in ['cat ~/.ssh/authorized_keys', 'grep ssh-rsa ~/.ssh/authorized_keys',
                    'LC_ALL=C grep "ssh-rsa EXAMPLE" ~/.ssh/authorized_keys',
                    'cp ~/.ssh/authorized_keys /tmp/backup',
                    'cat ~/.ssh/authorized_keys > /tmp/backup',
                    'echo "write to ~/.ssh/authorized_keys"',
                    'cp --help key ~/.ssh/authorized_keys',
                    'tee --help ~/.ssh/authorized_keys',
                    'echo EXAMPLE > /tmp/authorized_keys',
                    'echo EXAMPLE > "$KEY_FILE"',
                    "echo 'unterminated > ~/.ssh/authorized_keys",
                    'echo EXAMPLE > ~/.ssh/authorized_keys |']:
            with self.subTest(cmd=cmd):
                self.assertNotIn('B04', self.hits(cmd))

    def test_history_and_key_replacement_development_shape(self):
        cmd = ('unset HISTORY HISTFILE; export HISTFILE=/dev/null; '
               'cat .ssh/authorized_keys | grep -v OLD >> .ssh/.auth_k; '
               'echo "ssh-rsa EXAMPLE" >> .ssh/.auth_k; '
               'mv .ssh/.auth_k .ssh/authorized_keys')
        hits = self.hits(cmd)
        self.assertIn('B04', hits)
        self.assertIn('B06', hits)

    def test_b17_binary_location_and_attribute_queries(self):
        for cmd in ['which ls', '/usr/bin/which -a ls uname', 'LC_ALL=C which ls',
                    'busybox which ls', 'command -v wget', 'type -p curl',
                    'ls -lh $(which ls)', 'LC_ALL=C ls -alh $(which ls)',
                    '/usr/bin/stat $(/usr/bin/which ls)']:
            with self.subTest(cmd=cmd):
                self.assertIn('B17', self.hits(cmd))

    def test_b17_does_not_evaluate_arbitrary_substitution_or_text(self):
        for cmd in ['echo "which ls"', "echo 'ls -lh $(which ls)'",
                    'which --help ls', 'which', 'ls -lh /tmp/file',
                    'ls -lh $(cat input)', 'ls -lh $(which $TOOL)',
                    'ls -lh $(which ls; passwd)', 'type --help',
                    'command -v $PROGRAM']:
            with self.subTest(cmd=cmd):
                self.assertNotIn('B17', self.hits(cmd))

    def test_b16_same_path_write_read_delete(self):
        for cmd in ['echo marker > /tmp/p; cat /tmp/p; rm -f /tmp/p',
                    'echo marker > /tmp/p && cat /tmp/./p && rm -f /tmp/p',
                    'LC_ALL=C printf "%s" marker > probe; cat probe; rm probe',
                    'busybox echo marker > /tmp/p; busybox cat /tmp/p; busybox rm -f /tmp/p',
                    'echo -e "\\x47\\x72\\x6f\\x70/tmp" > /tmp/.nippon; '
                    'cat /tmp/.nippon; rm -f /tmp/.nippon']:
            with self.subTest(cmd=cmd):
                self.assertIn('B16', self.hits(cmd))

    def test_b16_wrong_path_order_and_disconnected_stages(self):
        for cmd in ['echo marker > /tmp/a; cat /tmp/b; rm -f /tmp/a',
                    'echo marker > /tmp/a; cat /tmp/a; rm -f /tmp/b',
                    'cat /tmp/a; echo marker > /tmp/a; rm -f /tmp/a',
                    'echo marker > /tmp/a; rm -f /tmp/a; cat /tmp/a',
                    'echo marker > /tmp/a | cat /tmp/a; rm -f /tmp/a',
                    'echo marker > /tmp/a || cat /tmp/a; rm -f /tmp/a',
                    'echo marker > /tmp/a; cat /tmp/a & rm -f /tmp/a',
                    'echo marker > a; cd /other; cat a; rm -f a',
                    'echo marker > /tmp/link/../a; cat /tmp/a; rm -f /tmp/a',
                    'echo marker > "$FILE"; cat "$FILE"; rm -f "$FILE"',
                    'echo marker > /tmp/a; cat /tmp/a; rm -f /tmp/*',
                    'echo "echo marker > /tmp/a; cat /tmp/a; rm -f /tmp/a"']:
            with self.subTest(cmd=cmd):
                self.assertNotIn('B16', self.hits(cmd))

    def test_b16_does_not_join_separate_rows(self):
        rows = [('2026-11-02T00:00:00Z', 'echo marker > /tmp/a'),
                ('2026-11-02T00:00:01Z', 'cat /tmp/a'),
                ('2026-11-02T00:00:02Z', 'rm -f /tmp/a')]
        self.assertNotIn('B16', match(self.rules, rows))

    def test_new_behavior_tags_do_not_change_s02(self):
        self.assertIn('S02', self.hits('echo EXAMPLE | base64 -d | sh'))
        self.assertNotIn('B04', self.hits('echo "authorized_keys" | base64 -d | sh'))
        self.assertEqual(observe('which ls') & {'binary_inspection', 'ssh_key_write'}, {'binary_inspection'})

    def test_count_matching_rows_not_actions(self):
        cmd = 'echo marker > /tmp/p; cat /tmp/p; rm -f /tmp/p; which ls'
        hits = self.hits(cmd)
        self.assertEqual(hits['B16'][1], 1)
        self.assertEqual(hits['B17'][1], 1)


if __name__ == '__main__':
    unittest.main()
