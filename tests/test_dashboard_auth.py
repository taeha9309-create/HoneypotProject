import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'streamlit_app'))
import auth  # noqa: E402


class CheckPasswordTests(unittest.TestCase):
    def test_not_configured(self):
        self.assertFalse(auth.configured({}))
        self.assertFalse(auth.check_password('x', {}))

    def test_plain(self):
        env = {auth.ENV: 'secret-pw'}
        self.assertTrue(auth.configured(env))
        self.assertTrue(auth.check_password('secret-pw', env))
        self.assertFalse(auth.check_password('secret-pW', env))
        self.assertFalse(auth.check_password('', env))

    def test_hash(self):
        h = hashlib.sha256('한글 비번'.encode()).hexdigest()
        env = {auth.ENV: 'sha256:' + h}
        self.assertTrue(auth.check_password('한글 비번', env))
        self.assertFalse(auth.check_password('other', env))


class ThrottleTests(unittest.TestCase):
    def test_lock_after_max_fails_then_release(self):
        t = [100.0]
        th = auth.Throttle(max_fails=3, lock_seconds=60, now=lambda: t[0])
        th.fail(); th.fail()
        self.assertEqual(th.remaining(), 0)
        th.fail()
        self.assertGreater(th.remaining(), 0)
        t[0] += 61
        self.assertEqual(th.remaining(), 0)

    def test_success_resets(self):
        th = auth.Throttle(max_fails=2, lock_seconds=60, now=lambda: 0.0)
        th.fail(); th.ok(); th.fail()
        self.assertEqual(th.remaining(), 0)


if __name__ == '__main__':
    unittest.main()
