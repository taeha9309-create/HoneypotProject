"""주기 실행 파이프라인: 로그 동기화 → ingest → match_signatures → ml/cluster.py assign.

사용법 (저장소 루트에서, cron 등으로 주기 실행):
    python ml/pipeline.py [--logs data/raw/syd] [--db data/honeypot.db] [--source syd]
                          [--out ml/out] [--models ml/models] [--settle-minutes 10]

- 한 단계라도 실패하면 거기서 멈추고 종료 코드 1을 낸다.
- 같은 시간에 두 번 돌지 않게 ml/out/pipeline.lock을 OS 파일 잠금으로 잡는다. 이미 잡혀 있으면
  아무것도 하지 않고 종료 코드 0으로 끝낸다. 프로세스가 죽으면 OS가 잠금을 풀어 주므로 남은 잠금 파일은 지우지 않아도 된다.
- 실행마다 결과를 ml/out/runs.log에 JSON 한 줄로 남긴다(성공·실패·건너뜀 모두).
- fit은 하지 않는다. 모델이 없으면 assign 단계에서 실패로 기록된다(먼저 python ml/cluster.py fit).
"""
import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from contextlib import closing, contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ml.cluster import SETTLE_MINUTES, assign, now_iso  # noqa: E402


class Locked(Exception):
    pass


@contextmanager
def single_instance(path):
    """다른 실행이 잠금을 잡고 있으면 Locked를 낸다."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    f = open(path, "a+")
    try:
        try:
            if os.name == "nt":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise Locked(str(path)) from e
        try:
            yield
        finally:
            if os.name == "nt":
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    finally:
        f.close()


def sync_logs(logs_dir):
    """서버의 Cowrie 로그를 logs_dir로 가져온다. 지금은 이미 있는 폴더를 그대로 쓴다.

    ponytail: 분석 서버가 생기면 여기서 rsync를 부른다. 서버의 로그 폴더는 ubuntu로 못 읽으므로
    서버 쪽에서 sudo cp로 홈에 복사(또는 읽기 권한 부여)해 둔 경로를 대상으로 한다. 예:
        subprocess.run(["rsync", "-a", "-e", "ssh -p PORT -i KEY", "ubuntu@HOST:cowrie-export/", f"{logs_dir}/"], check=True)
    """
    if not Path(logs_dir).is_dir():
        raise FileNotFoundError(f"로그 폴더가 없다: {logs_dir}")


def run_script(*args):
    """저장소의 스크립트를 따로 실행한다. 실패하면 stderr 끝부분을 담아 RuntimeError."""
    r = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    print(r.stdout, end="")
    if r.returncode != 0:
        raise RuntimeError(f"종료 코드 {r.returncode}: {(r.stderr or r.stdout).strip()[-500:]}")


def run_pipeline(logs, db, out, models, source=None, settle_minutes=SETTLE_MINUTES):
    """파이프라인을 한 번 실행하고 runs.log에 남긴 기록(dict)을 돌려준다."""
    # 하위 스크립트는 저장소 루트에서 돌므로 경로를 미리 절대 경로로 바꾼다
    logs, db, out, models = (Path(p).resolve() for p in (logs, db, out, models))
    record = {"ts": now_iso(), "status": "ok"}
    started = time.perf_counter()
    step = None
    try:
        with single_instance(out / "pipeline.lock"):
            step = "sync"
            sync_logs(logs)
            step = "ingest"
            run_script("ingest.py", str(logs), "--db", str(db), *(["--source", source] if source else []))
            step = "match_signatures"
            run_script("match_signatures.py", "--db", str(db))
            step = "assign"
            with closing(sqlite3.connect(db)) as con:
                record.update(assign(con, out, models, settle_minutes))
    except Locked:
        record.update(status="skipped", reason="다른 실행이 잠금을 잡고 있음")
    except (Exception, SystemExit) as e:  # assign은 fit 전이면 sys.exit로 끝난다
        record.update(status="failed", step=step, error=str(e)[-500:] or type(e).__name__)
    record["seconds"] = round(time.perf_counter() - started, 1)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "runs.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def main():
    p = argparse.ArgumentParser(description="로그 동기화 → ingest → match_signatures → assign")
    p.add_argument("--logs", default="data/raw/syd")
    p.add_argument("--db", default="data/honeypot.db")
    p.add_argument("--source", help="ingest --source (기본: 폴더 이름)")
    p.add_argument("--out", default="ml/out")
    p.add_argument("--models", default="ml/models")
    p.add_argument("--settle-minutes", type=int, default=SETTLE_MINUTES)
    args = p.parse_args()
    record = run_pipeline(args.logs, args.db, args.out, args.models, args.source, args.settle_minutes)
    print(json.dumps(record, ensure_ascii=False))
    sys.exit(1 if record["status"] == "failed" else 0)


if __name__ == "__main__":
    main()
