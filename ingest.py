"""Cowrie JSON 로그를 SQLite로 옮긴다.

사용법:
    python ingest.py <파일 또는 폴더> [...] [--db data/honeypot.db] [--source 이름]

두 가지 형식을 모두 읽는다.
  - 우리 허니팟(Cowrie 원본): 한 줄에 이벤트 하나(JSON Lines), 필드 `session`, `input`
  - CyberLab 공개 데이터: 파일 전체가 [{"<세션ID>": [이벤트, ...]}, ...] 배열,
    필드 `session_id`, 명령어는 message의 "CMD: ..." 에만 있음

source(데이터 출처)는 --source를 주지 않으면 이렇게 정한다.
  - 파일 이름이 cyberlab_ 로 시작 → "cyberlab"
  - 그 밖에는 파일이 들어 있는 폴더 이름 (raw/seoul/... → "seoul")

원본 파일은 읽기만 한다. 같은 파일을 여러 번 넣어도 결과가 같다.
"""
import argparse
import gzip
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# 우리가 직접 접속한 테스트 세션·IP (분석에서 제외)
TEST_SESSIONS = {"55b8894c004b", "068d4def1310"}
TEST_IPS = {"39.124.23.44", "118.235.26.80", "211.238.109.139", "211.238.109.168", "211.108.129.43"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    source        TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    sensor        TEXT,
    src_ip        TEXT,
    country       TEXT,
    protocol      TEXT,
    client_version TEXT,
    start_ts      TEXT,
    end_ts        TEXT,
    login_success INTEGER NOT NULL DEFAULT 0,
    username      TEXT,
    password      TEXT,
    n_commands    INTEGER NOT NULL DEFAULT 0,
    n_failed      INTEGER NOT NULL DEFAULT 0,
    excluded      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (source, session_id)
);
CREATE TABLE IF NOT EXISTS commands (
    source     TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ts         TEXT NOT NULL,
    command    TEXT NOT NULL,
    UNIQUE (source, session_id, ts, command)
);
-- 실패한 명령어는 입력 줄 전체가 아니라 실패한 조각만 남으므로 따로 둔다
CREATE TABLE IF NOT EXISTS failed_commands (
    source     TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ts         TEXT NOT NULL,
    command    TEXT NOT NULL,
    UNIQUE (source, session_id, ts, command)
);
CREATE TABLE IF NOT EXISTS downloads (
    source     TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ts         TEXT NOT NULL,
    url        TEXT,
    shasum     TEXT,
    UNIQUE (source, session_id, ts, url)
);
CREATE TABLE IF NOT EXISTS ingested_files (
    path        TEXT PRIMARY KEY,
    size        INTEGER,
    mtime       REAL,
    source      TEXT,
    n_events    INTEGER,
    ingested_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_commands_session ON commands (source, session_id, ts);
"""


def iter_files(args):
    for arg in args:
        p = Path(arg)
        if p.is_dir():
            # Cowrie는 cowrie.json.2026-10-27 처럼 날짜를 뒤에 붙여 돌려 쓴다
            yield from sorted(f for f in p.rglob("*") if f.is_file() and ".json" in f.name)
        else:
            yield p


def open_text(path):
    with open(path, "rb") as f:
        is_gzip = f.read(2) == b"\x1f\x8b"
    opener = gzip.open if is_gzip else open
    return opener(path, "rt", encoding="utf-8", errors="replace")


def iter_events(path):
    with open_text(path) as f:
        head = f.read(1)
        f.seek(0)
        if head == "[":
            for item in json.load(f):
                if not isinstance(item, dict):
                    continue
                # CyberLab 형식: {"<세션ID>": [이벤트, ...]}
                if "eventid" not in item and all(isinstance(v, list) for v in item.values()):
                    for events in item.values():
                        yield from (e for e in events if isinstance(e, dict))
                else:
                    yield item
            return
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue  # 로그 회전 중 잘린 줄
            if isinstance(obj, dict):
                yield obj


def guess_source(path):
    if path.name.startswith("cyberlab_"):
        return "cyberlab"
    return path.parent.name


def command_text(event):
    # CyberLab에는 input 필드가 없고 message가 "CMD: <명령어>" 형태다
    if event.get("input") is not None:
        return event["input"]
    msg = event.get("message") or ""
    for prefix in ("CMD: ", "Command not found: "):
        if msg.startswith(prefix):
            return msg[len(prefix):]
    return msg


def new_session():
    return {
        "sensor": None, "src_ip": None, "country": None, "protocol": None,
        "client_version": None, "start_ts": None, "end_ts": None,
        "login_success": 0, "username": None, "password": None,
    }


def collect(path):
    """파일 하나를 읽어 세션 요약, 명령어, 다운로드 목록을 만든다."""
    sessions, commands, failed, downloads = {}, [], [], []
    n_events = 0
    for e in iter_events(path):
        sid = e.get("session") or e.get("session_id")
        ts = e.get("timestamp")
        if not sid or not isinstance(ts, str):
            continue
        n_events += 1
        s = sessions.setdefault(sid, new_session())
        s["start_ts"] = ts if s["start_ts"] is None else min(s["start_ts"], ts)
        s["end_ts"] = ts if s["end_ts"] is None else max(s["end_ts"], ts)
        s["sensor"] = s["sensor"] or e.get("sensor")
        s["src_ip"] = s["src_ip"] or e.get("src_ip") or e.get("src_ip_identifier")
        # CyberLab은 protocol이 세션 안 일부 이벤트에만 있다
        s["protocol"] = s["protocol"] or e.get("protocol")
        geo = e.get("geolocation_data")
        if isinstance(geo, dict):
            s["country"] = s["country"] or geo.get("country_code2")

        eid = e.get("eventid")
        if eid == "cowrie.client.version":
            s["client_version"] = e.get("version") or e.get("ssh_client_version")
        elif eid == "cowrie.login.success":
            s["login_success"] = 1
            s["username"], s["password"] = e.get("username"), e.get("password")
        elif eid == "cowrie.command.input":
            commands.append((sid, ts, command_text(e)))
        elif eid == "cowrie.command.failed":
            failed.append((sid, ts, command_text(e)))
        elif eid == "cowrie.session.file_download":
            downloads.append((sid, ts, e.get("url"), e.get("shasum")))
    return sessions, commands, failed, downloads, n_events


def save(con, source, sessions, commands, failed, downloads):
    for sid, s in sessions.items():
        excluded = int(sid in TEST_SESSIONS or s["src_ip"] in TEST_IPS)
        # 회전된 로그에 한 세션이 나뉘어 있을 수 있어 기존 값과 합친다
        con.execute(
            """
            INSERT INTO sessions (source, session_id, sensor, src_ip, country, protocol,
                client_version, start_ts, end_ts, login_success, username, password, excluded)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (source, session_id) DO UPDATE SET
                sensor = COALESCE(sensor, excluded.sensor),
                src_ip = COALESCE(src_ip, excluded.src_ip),
                country = COALESCE(country, excluded.country),
                protocol = COALESCE(protocol, excluded.protocol),
                client_version = COALESCE(client_version, excluded.client_version),
                start_ts = MIN(start_ts, excluded.start_ts),
                end_ts = MAX(end_ts, excluded.end_ts),
                login_success = MAX(login_success, excluded.login_success),
                username = COALESCE(username, excluded.username),
                password = COALESCE(password, excluded.password),
                excluded = MAX(sessions.excluded, excluded.excluded)
            """,
            (source, sid, s["sensor"], s["src_ip"], s["country"], s["protocol"],
             s["client_version"], s["start_ts"], s["end_ts"], s["login_success"],
             s["username"], s["password"], excluded),
        )
    con.executemany(
        "INSERT OR IGNORE INTO commands (source, session_id, ts, command) VALUES (?, ?, ?, ?)",
        [(source, *c) for c in commands],
    )
    con.executemany(
        "INSERT OR IGNORE INTO failed_commands (source, session_id, ts, command) VALUES (?, ?, ?, ?)",
        [(source, *c) for c in failed],
    )
    con.executemany(
        # Keep the existing schema and legacy NULL rows; NULL and empty URL
        # identify the same event. A single INSERT also serializes concurrent writers.
        """INSERT OR IGNORE INTO downloads (source, session_id, ts, url, shasum)
        SELECT ?1, ?2, ?3, ?4, ?5 WHERE NOT EXISTS (
            SELECT 1 FROM downloads
            WHERE source = ?1 AND session_id = ?2 AND ts = ?3
                AND IFNULL(url, '') = ?4
        )""",
        [(source, sid, ts, url or '', shasum) for sid, ts, url, shasum in downloads],
    )
    con.executemany(
        """
        UPDATE sessions SET
            n_commands = (SELECT COUNT(*) FROM commands c WHERE c.source = ?1 AND c.session_id = ?2),
            n_failed = (SELECT COUNT(*) FROM failed_commands f WHERE f.source = ?1 AND f.session_id = ?2)
        WHERE source = ?1 AND session_id = ?2
        """,
        [(source, sid) for sid in sessions],
    )


def main():
    parser = argparse.ArgumentParser(description="Cowrie JSON 로그를 SQLite로 옮긴다.")
    parser.add_argument("paths", nargs="+", help="로그 파일 또는 폴더")
    parser.add_argument("--db", default="data/honeypot.db", help="SQLite 파일 (기본: data/honeypot.db)")
    parser.add_argument("--source", help="데이터 출처 이름 (기본: 파일 이름/폴더 이름으로 추정)")
    parser.add_argument("--force", action="store_true", help="이미 넣은 파일도 다시 읽는다")
    args = parser.parse_args()

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(args.db)
    con.executescript(SCHEMA)

    for path in iter_files(args.paths):
        stat = path.stat()
        key = str(path.resolve())
        row = con.execute("SELECT size, mtime FROM ingested_files WHERE path = ?", (key,)).fetchone()
        if row == (stat.st_size, stat.st_mtime) and not args.force:
            print(f"건너뜀(변경 없음): {path}")
            continue

        source = args.source or guess_source(path)
        sessions, commands, failed, downloads, n_events = collect(path)
        with con:  # 파일 하나 = 트랜잭션 하나. 중간에 실패하면 그 파일은 통째로 되돌린다
            save(con, source, sessions, commands, failed, downloads)
            con.execute(
                "INSERT OR REPLACE INTO ingested_files VALUES (?, ?, ?, ?, ?, ?)",
                (key, stat.st_size, stat.st_mtime, source, n_events,
                 datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
        n_cmd_sessions = len({c[0] for c in commands})
        print(f"{path.name} [{source}] 이벤트 {n_events:,} / 세션 {len(sessions):,} / "
              f"명령어 세션 {n_cmd_sessions:,}")

    total = con.execute(
        "SELECT source, COUNT(*), SUM(n_commands > 0), SUM(excluded) FROM sessions GROUP BY source"
    ).fetchall()
    print("\n[DB 합계] 출처 / 세션 / 명령어 세션 / 제외(테스트)")
    for source, n, n_cmd, n_ex in total:
        print(f"  {source}: {n:,} / {n_cmd:,} / {n_ex:,}")
    con.close()


if __name__ == "__main__":
    sys.exit(main())
