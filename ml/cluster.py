"""세션 명령어 시퀀스를 정규화하고 TF-IDF + HDBSCAN으로 군집화한다.

사용법:
    python ml/cluster.py fit    [--db data/honeypot.db] [--out ml/out] [--models ml/models]
                                [--mcs N [--ms N]] [--max-copies 50]
    python ml/cluster.py assign [--db data/honeypot.db] [--out ml/out] [--models ml/models]

fit: 지금까지의 세션으로 정규화 → TF-IDF → SVD → HDBSCAN을 학습해 ml/models/<protocol>.joblib에
     저장하고, ml_clusters를 지우고 새로 채운다. 해시·DBSCAN·고유 시퀀스 단위 HDBSCAN과 비교한
     표(comparison.csv)와 파라미터 선택 이유(hdbscan_selection.md)를 ml/out/에 남긴다.
assign: ml_clusters에 아직 없는 세션만 저장된 모델로 approximate_predict해서 배정한다.
둘 다 끝나면 ml/out/에 session_clusters.csv, cluster_summary.csv, novel_candidates.csv를 다시 쓴다.

대상: excluded = 0, src_ip가 테스트 IP가 아니고 명령어가 1개 이상인 세션. SSH와 Telnet은
따로 학습하고 protocol이 NULL인 세션은 빼고 개수만 알린다. 원문(commands)은 건드리지 않는다.
signature_hits는 입력으로 쓰지 않고, 군집별 규칙 분포를 참고로만 보여 준다.
"""
import argparse
import csv
import re
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import hdbscan
import joblib
import numpy as np
from hdbscan.prediction import approximate_predict
from sklearn.cluster import DBSCAN
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import normalize as l2_normalize

TEST_IP = "211.238.109.139"  # ingest의 excluded와 별개로 한 번 더 뺀다
PROTOCOLS = ("ssh", "telnet")
NORMALIZE_VERSION = 3  # 2: /dev·/sys·/proc 경로는 <FILE> 제외, '/'로 시작하면 <B64> 제외. 3: 줄바꿈도 나눔. 정규화 규칙을 바꾸면 올린다. 모델과 다르면 assign이 멈추고 fit을 요구한다
MAX_COPIES = 50  # 세션 단위 HDBSCAN에서 같은 시퀀스를 최대 몇 개까지 복제할지 (0 = 제한 없음)
HDBSCAN_GRID = [(mcs, ms) for mcs in (10, 25, 50, 100) for ms in (1, 5, None)]  # None = mcs와 같음
UNIQUE_SIZES = (5, 10, 20)  # 비교용: 고유 시퀀스 단위 HDBSCAN
DBSCAN_EPS = (0.1, 0.2, 0.3, 0.5)
MAX_NOISE = 0.2  # 파라미터 선택 규칙: 노이즈가 이보다 많은 설정은 고르지 않는다
OUTLIER_QUANTILE = 0.95  # 신규 패턴 후보: 프로토콜별 이상 점수 상위 5%
RECENT_DAYS = 7  # 신규 패턴 후보: 데이터의 마지막 시각 기준 최근 7일 안에 처음 나온 군집

SCHEMA = """
DROP TABLE IF EXISTS ml_clusters;
CREATE TABLE ml_clusters (
    source        TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    protocol      TEXT NOT NULL,
    model         TEXT NOT NULL,
    params        TEXT NOT NULL,
    cluster_id    INTEGER NOT NULL, -- 학습 때 크기 순 번호(0이 가장 큼), 노이즈는 -1
    is_noise      INTEGER NOT NULL,
    outlier_score REAL,             -- 가장 가까운 군집 중심까지 코사인 거리 0~2 (클수록 이상)
    probability   REAL,             -- 군집 소속 강도
    assigned_by   TEXT NOT NULL,    -- fit / assign
    assigned_at   TEXT NOT NULL,
    PRIMARY KEY (source, session_id)
);
"""

# ---------------------------------------------------------------- 정규화

SPLIT_RE = re.compile(r"\s*(?:;|&&|\|\||[\r\n]+)\s*")  # 파이프 |는 그대로 둔다
URL_RE = re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\";|&<>`]+", re.I)
PASS_RE = re.compile(
    r"(echo\s+(?:-\w+\s+)*[\"']?[^\s:\"']+:)[^\s\"'|]+(?=[\"']?\s*\|\s*(?:sudo\s+)?chpasswd)")
IP_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?!\.?\d)")
# 대문자·소문자·숫자가 모두 있어야 base64로 본다(순수 16진수와 소문자 경로를 피하려고).
# '/'로 시작하면 경로로 보고 건너뛴다.
# ponytail: '/'로 시작하는 진짜 base64(예: JPEG의 /9j/...)는 놓친다
B64_RE = re.compile(
    r"(?<![A-Za-z0-9+/])(?!/)(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*\d)"
    r"[A-Za-z0-9+/]{40,}={0,2}")
HEX_RE = re.compile(r"(?<!\w)[0-9a-fA-F]{16,}(?!\w)")
# ponytail: '/' 뒤 8자 이상 영숫자 혼합을 무작위 이름으로 본다. /home/user2024a 같은 이름도 걸린다
RANDOM_FILE_RE = re.compile(
    r"(?<=/)(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{8,}(?![A-Za-z0-9_-])")
PATH_TOKEN_RE = re.compile(r"[^\s'\"|;&<>=]*/[^\s'\"|;&<>]*")
SYSTEM_PATH_RE = re.compile(r"^/(?:dev|sys|proc)/")  # 장치·커널 경로는 <FILE>로 바꾸지 않는다


def random_files(match):
    path = match.group(0)
    return path if SYSTEM_PATH_RE.match(path) else RANDOM_FILE_RE.sub("<FILE>", path)
NUM_RE = re.compile(r"(?<![\w.&-])\d+(?![\w.>])")
SPACE_RE = re.compile(r"\s+")


def split_command(cmd):
    """한 줄을 ; && || 로 나눈다. 따옴표 안의 구분자도 나눈다(셸 파서 아님)."""
    return [p for p in SPLIT_RE.split(cmd) if p.strip()]


def downloaded_names(cmds):
    """세션 명령어 속 URL에서 내려받는 파일 이름(경로 마지막 조각)을 모은다."""
    names = set()
    for cmd in cmds:
        for url in URL_RE.findall(cmd):
            name = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
            if name:
                names.add(name)
    return names


def normalize_part(part, files=()):
    s = URL_RE.sub("<URL>", part)
    s = PASS_RE.sub(r"\1<PASS>", s)
    s = IP_RE.sub("<IP>", s)
    s = B64_RE.sub("<B64>", s)
    s = HEX_RE.sub("<HEX>", s)
    for name in sorted(files, key=len, reverse=True):
        s = re.sub(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", "<FILE>", s)
    s = PATH_TOKEN_RE.sub(random_files, s)
    s = NUM_RE.sub("<NUM>", s)
    return SPACE_RE.sub(" ", s).strip()


def normalize_session(cmds):
    """원문 명령어 목록 → 정규화한 명령어 튜플(나눈 조각 하나가 원소 하나)."""
    files = downloaded_names(cmds)
    return tuple(n for c in cmds for p in split_command(c) if (n := normalize_part(p, files)))


# ---------------------------------------------------------------- 데이터

def load_sessions(con):
    """{(source, session_id): {"protocol", "src_ip", "ts": [...], "cmds": [...]}}"""
    rows = con.execute(
        """
        SELECT s.source, s.session_id, s.protocol, s.src_ip, c.ts, c.command
        FROM sessions s JOIN commands c USING (source, session_id)
        WHERE s.excluded = 0 AND s.src_ip IS NOT ? AND s.n_commands > 0
        ORDER BY s.source, s.session_id, c.ts, c.rowid
        """,
        (TEST_IP,),
    )
    sessions = {}
    for source, sid, protocol, ip, ts, cmd in rows:
        s = sessions.setdefault((source, sid), {"protocol": protocol, "src_ip": ip, "ts": [], "cmds": []})
        s["ts"].append(ts)
        s["cmds"].append(cmd)
    return sessions


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- 특징·군집화

def as_doc(seq):
    # 명령어 하나 = 토큰 하나. 공백을 \x1f로 바꿔 str.split이 명령어 단위로 자르게 한다
    # (str.split은 joblib으로 저장·불러오기가 되는 내장 함수라 별도 analyzer 함수를 안 쓴다)
    return " ".join(c.replace(" ", "\x1f") for c in seq)


def features(uniq):
    vec = TfidfVectorizer(tokenizer=str.split, token_pattern=None, lowercase=False, ngram_range=(1, 3))
    X = vec.fit_transform([as_doc(s) for s in uniq])
    svd = TruncatedSVD(n_components=min(50, X.shape[1] - 1), random_state=0)
    Z = l2_normalize(svd.fit_transform(X))
    return vec, svd, X, Z


def replicate(weights, max_copies):
    """고유 시퀀스를 세션 수만큼(최대 max_copies) 복제한 행 번호와, 각 시퀀스의 첫 행 번호."""
    copies = np.asarray(weights)
    if max_copies:
        copies = np.minimum(copies, max_copies)
    rows = np.repeat(np.arange(len(copies)), copies)
    first = np.concatenate(([0], np.cumsum(copies)[:-1]))
    return rows, first


def size_order(labels, weights):
    """세션 수가 많은 군집부터 0, 1, 2 ... 로 바꾸는 {원래 번호: 새 번호}. -1은 -1."""
    size = Counter()
    for lab, w in zip(labels, weights):
        if lab != -1:
            size[int(lab)] += w
    order = {lab: i for i, (lab, _) in enumerate(size.most_common())}
    order[-1] = -1
    return order


def centroid_distance(Z, centroids):
    """이상 점수: 가장 가까운 군집 중심까지 코사인 거리(0~2).
    같은 시퀀스가 반복되는 봇 데이터에서는 HDBSCAN GLOSH가 0/NaN이 돼서 이것을 쓴다."""
    if len(centroids) == 0:
        return np.ones(len(Z))
    return np.clip(1 - (Z @ centroids.T).max(axis=1), 0, None)


def silhouette(X, labels):
    """노이즈 제외 고유 시퀀스, TF-IDF 코사인 기준(모든 방법을 같은 공간에서 비교)."""
    mask = labels != -1
    k = len(set(labels[mask]))
    if k < 2 or k >= mask.sum():
        return None
    return silhouette_score(X[mask], labels[mask], metric="cosine",
                            sample_size=min(5000, int(mask.sum())), random_state=0)


def compare(X, Z, weights, max_copies):
    """방법·파라미터별 [{"model", "params", "labels"(고유 시퀀스 단위), "seconds", ...}]"""
    out = []

    def add(model, params, fn, **extra):
        t = time.perf_counter()
        labels = fn()
        out.append({"model": model, "params": params, "labels": labels,
                    "seconds": time.perf_counter() - t, **extra})

    rows, first = replicate(weights, max_copies)
    for mcs, ms in HDBSCAN_GRID:
        if len(rows) > mcs:
            add("hdbscan", f"mcs={mcs},ms={ms or mcs}",
                lambda: hdbscan.HDBSCAN(min_cluster_size=mcs, min_samples=ms).fit_predict(Z[rows])[first],
                mcs=mcs, ms=ms)
    for mcs in UNIQUE_SIZES:
        if len(weights) > mcs:
            add("hdbscan_uniq", f"mcs={mcs}", lambda: hdbscan.HDBSCAN(min_cluster_size=mcs).fit_predict(Z))
    add("hash", "-", lambda: np.array([i if w > 1 else -1 for i, w in enumerate(weights)]))
    for eps in DBSCAN_EPS:
        # 세션 수를 가중치로 줘서 밀도를 세션 기준으로 센다
        add("dbscan", f"eps={eps}", lambda: DBSCAN(eps=eps, min_samples=2, metric="cosine")
            .fit_predict(X, sample_weight=weights))

    total = sum(weights)
    for r in out:
        labels = r["labels"]
        r["n_clusters"] = len(set(labels) - {-1})
        r["noise"] = sum(w for lab, w in zip(labels, weights) if lab == -1) / total
        r["silhouette"] = silhouette(X, labels)
    return out


def choose(results, mcs=None, ms=None):
    """최종 HDBSCAN 설정과 고른 이유."""
    if mcs:
        return mcs, ms, "--mcs/--ms로 직접 지정"
    cands = [r for r in results if r["model"] == "hdbscan" and r["n_clusters"] >= 2]
    ok = [r for r in cands if r["noise"] <= MAX_NOISE and r["silhouette"] is not None]
    if ok:
        r = max(ok, key=lambda r: r["silhouette"])
        return r["mcs"], r["ms"], (f"군집 2개 이상·노이즈 {MAX_NOISE:.0%} 이하인 설정 {len(ok)}개 중 "
                                   f"실루엣 최대 ({r['silhouette']:.3f}, 노이즈 {r['noise']:.1%})")
    if cands:
        r = min(cands, key=lambda r: r["noise"])
        return r["mcs"], r["ms"], (f"노이즈 {MAX_NOISE:.0%} 이하이면서 실루엣이 있는 설정이 없어 "
                                   f"군집 2개 이상 중 노이즈 최소 ({r['noise']:.1%})")
    return None


# ---------------------------------------------------------------- fit

def fit(con, out_dir, models_dir, mcs=None, ms=None, max_copies=MAX_COPIES):
    con.executescript(SCHEMA)
    sessions = load_sessions(con)
    n_null = sum(s["protocol"] is None for s in sessions.values())
    print(f"대상 세션 {len(sessions):,}개 / protocol NULL로 제외 {n_null:,}개")
    out_dir, models_dir = Path(out_dir), Path(models_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)
    trained_at = now_iso()
    tables, notes = {}, {}

    for proto in PROTOCOLS:
        keys = [k for k, s in sessions.items() if s["protocol"] == proto]
        norm = {k: normalize_session(sessions[k]["cmds"]) for k in keys}
        uniq = sorted(set(norm.values()))
        n_raw = len({tuple(sessions[k]["cmds"]) for k in keys})
        print(f"\n[{proto}] 세션 {len(keys):,} / 고유 시퀀스: 정규화 전 {n_raw:,} → 후 {len(uniq):,}")
        if len(uniq) < 2:
            print("  고유 시퀀스가 2개 미만이라 학습하지 않는다")
            continue
        index = {seq: i for i, seq in enumerate(uniq)}
        counts = Counter(index[norm[k]] for k in keys)
        weights = [counts[i] for i in range(len(uniq))]
        vec, svd, X, Z = features(uniq)

        t = time.perf_counter()
        results = compare(X, Z, weights, max_copies)
        print(f"  비교 {len(results)}개 설정 {time.perf_counter() - t:.1f}초")
        picked = choose(results, mcs, ms)
        if picked is None:
            print("  HDBSCAN이 군집을 2개 이상 만든 설정이 없어 학습하지 않는다")
            tables[proto] = (results, None)
            continue
        f_mcs, f_ms, reason = picked
        params = f"mcs={f_mcs},ms={f_ms or f_mcs},max_copies={max_copies}"

        rows, first = replicate(weights, max_copies)
        clf = hdbscan.HDBSCAN(min_cluster_size=f_mcs, min_samples=f_ms, prediction_data=True).fit(Z[rows])
        raw = clf.labels_[first]
        order = size_order(raw, weights)
        labels = np.array([order[int(lab)] for lab in raw])
        w = np.asarray(weights)
        centroids = l2_normalize(np.array([np.average(Z[labels == c], axis=0, weights=w[labels == c])
                                           for c in range(len(set(labels) - {-1}))]))
        scores = centroid_distance(Z, centroids)
        probs = clf.probabilities_[first]
        joblib.dump({
            "normalize_version": NORMALIZE_VERSION, "trained_at": trained_at, "protocol": proto,
            "params": params, "n_sessions": len(keys), "vectorizer": vec, "svd": svd,
            "clusterer": clf, "label_order": order, "centroids": centroids,
        }, models_dir / f"{proto}.joblib")

        with con:
            con.executemany(
                "INSERT INTO ml_clusters VALUES (?, ?, ?, 'hdbscan', ?, ?, ?, ?, ?, 'fit', ?)",
                [(*k, proto, params, int(labels[i]), int(labels[i] == -1), float(scores[i]),
                  float(probs[i]), trained_at) for k in keys for i in [index[norm[k]]]],
            )
        tables[proto] = (results, (f_mcs, f_ms))
        notes[proto] = (params, reason, labels, weights)

    write_comparison(out_dir, tables, notes, trained_at, max_copies)
    write_outputs(con, out_dir)


def write_comparison(out_dir, tables, notes, trained_at, max_copies):
    definition = ("노이즈 비율: 세션 기준. 해시는 세션 1개짜리 시퀀스를 노이즈로 셈. "
                  "실루엣: 노이즈 제외 고유 시퀀스, TF-IDF 코사인. "
                  f"hdbscan = 세션 단위(같은 시퀀스 최대 {max_copies or '무제한'}개 복제, mcs가 세션 수 기준), "
                  "hdbscan_uniq = 고유 시퀀스 단위(mcs가 고유 시퀀스 수 기준), "
                  "dbscan = 고유 시퀀스에 세션 수 가중치.")
    with open(out_dir / "comparison.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["protocol", "model", "params", "n_clusters", "noise", "silhouette", "seconds", "chosen"])
        for proto, (results, final) in tables.items():
            for r in results:
                chosen = final is not None and r["model"] == "hdbscan" and (r["mcs"], r["ms"]) == final
                w.writerow([proto, r["model"], r["params"], r["n_clusters"], f"{r['noise']:.4f}",
                            "" if r["silhouette"] is None else f"{r['silhouette']:.4f}",
                            f"{r['seconds']:.2f}", int(chosen)])

    md = [f"# HDBSCAN 파라미터 선택\n\n학습 시각: {trained_at} / 정규화 규칙 버전: {NORMALIZE_VERSION}\n",
          f"선택 규칙: 세션 단위 HDBSCAN 중 군집 2개 이상, 노이즈 {MAX_NOISE:.0%} 이하인 설정에서 "
          "실루엣이 가장 높은 것. 없으면 군집 2개 이상 중 노이즈가 가장 적은 것.\n",
          f"정의: {definition}\n"]
    for proto, (results, final) in tables.items():
        print(f"\n[{proto}] 방법·파라미터별 결과 (* = 최종)")
        print(f"  {'model':13} {'params':12} {'군집':>6} {'노이즈':>7} {'실루엣':>7} {'초':>6}")
        md.append(f"\n## {proto}\n")
        if proto in notes:
            md.append(f"최종: `{notes[proto][0]}`  \n이유: {notes[proto][1]}\n")
        md.append("\n| model | params | 군집 수 | 노이즈 | 실루엣 | 초 |\n|---|---|---|---|---|---|")
        for r in results:
            chosen = final is not None and r["model"] == "hdbscan" and (r["mcs"], r["ms"]) == final
            sil = "-" if r["silhouette"] is None else f"{r['silhouette']:.3f}"
            mark = "*" if chosen else " "
            print(f" {mark}{r['model']:13} {r['params']:12} {r['n_clusters']:>6,} {r['noise']:>7.1%} "
                  f"{sil:>7} {r['seconds']:>6.1f}")
            md.append(f"| {r['model']}{' **(최종)**' if chosen else ''} | {r['params']} | {r['n_clusters']:,} "
                      f"| {r['noise']:.1%} | {sil} | {r['seconds']:.1f} |")
        if proto in notes:
            print(f"  최종 {notes[proto][0]}: {notes[proto][1]}")
    print(f"  ({definition})")
    (out_dir / "hdbscan_selection.md").write_text("\n".join(md) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- assign

def assign(con, out_dir, models_dir):
    if not con.execute("SELECT 1 FROM sqlite_master WHERE name = 'ml_clusters'").fetchone():
        sys.exit("ml_clusters가 없다. fit을 먼저 돌려야 한다")
    done = set(con.execute("SELECT source, session_id FROM ml_clusters"))
    sessions = load_sessions(con)
    assigned_at = now_iso()
    for proto in PROTOCOLS:
        keys = [k for k, s in sessions.items() if s["protocol"] == proto and k not in done]
        if not keys:
            print(f"[{proto}] 새 세션 없음")
            continue
        path = Path(models_dir) / f"{proto}.joblib"
        if not path.exists():
            print(f"[{proto}] 모델 없음({path}), 새 세션 {len(keys):,}개 건너뜀")
            continue
        m = joblib.load(path)
        if m["normalize_version"] != NORMALIZE_VERSION:
            sys.exit(f"{path}: 정규화 규칙 버전 {m['normalize_version']} ≠ 현재 {NORMALIZE_VERSION}. fit을 다시 돌려야 한다")
        docs = [as_doc(normalize_session(sessions[k]["cmds"])) for k in keys]
        Z = l2_normalize(m["svd"].transform(m["vectorizer"].transform(docs)))
        raw, probs = approximate_predict(m["clusterer"], Z)
        scores = centroid_distance(Z, m["centroids"])
        labels = [m["label_order"][int(lab)] for lab in raw]
        with con:
            con.executemany(
                "INSERT INTO ml_clusters VALUES (?, ?, ?, 'hdbscan', ?, ?, ?, ?, ?, 'assign', ?)",
                [(*k, proto, m["params"], lab, int(lab == -1), float(sc), float(p), assigned_at)
                 for k, lab, sc, p in zip(keys, labels, scores, probs)],
            )
        n_noise = sum(lab == -1 for lab in labels)
        print(f"[{proto}] 새 세션 {len(keys):,}개 배정 (노이즈 {n_noise:,}), 모델 학습 시각 {m['trained_at']}")
    write_outputs(con, out_dir)


# ---------------------------------------------------------------- 결과물

def parse_ts(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def write_outputs(con, out_dir):
    """세션별 cluster_id, 군집별 대표 명령어, 신규 패턴 후보 CSV 세 개를 쓴다."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sessions = load_sessions(con)
    ml = {(s, sid): (proto, c, sc, by) for s, sid, proto, c, sc, by in con.execute(
        "SELECT source, session_id, protocol, cluster_id, outlier_score, assigned_by FROM ml_clusters")}
    ml = {k: v for k, v in ml.items() if k in sessions}  # 대상 조건이 바뀐 세션은 내보내지 않는다
    downloaded = set(con.execute("SELECT DISTINCT source, session_id FROM downloads"))
    norm = {k: normalize_session(sessions[k]["cmds"]) for k in ml}

    # 1. 세션별 cluster_id
    with open(out_dir / "session_clusters.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["source", "session_id", "protocol", "src_ip", "start_ts", "cluster_id",
                    "outlier_score", "assigned_by"])
        for k, (proto, c, sc, by) in sorted(ml.items()):
            w.writerow([*k, proto, sessions[k]["src_ip"], sessions[k]["ts"][0], c, f"{sc:.4f}", by])

    # 2. 군집별 대표 명령어
    members = defaultdict(list)
    for k, (proto, c, _, _) in ml.items():
        members[(proto, c)].append(k)
    summary = []
    for (proto, c), ks in members.items():
        rep, n_rep = Counter(norm[k] for k in ks).most_common(1)[0]
        cmd_cov = Counter(cmd for k in ks for cmd in set(norm[k]))
        summary.append({
            "protocol": proto, "cluster_id": c, "n_sessions": len(ks),
            "n_ips": len({sessions[k]["src_ip"] for k in ks}),
            "first_ts": min(sessions[k]["ts"][0] for k in ks),
            "last_ts": max(sessions[k]["ts"][-1] for k in ks),
            "rep_share": f"{n_rep / len(ks):.3f}",
            "representative": " ; ".join(rep),
            "top_commands": " | ".join(f"{cmd} ({n / len(ks):.0%})" for cmd, n in cmd_cov.most_common(5)),
        })
    summary.sort(key=lambda r: (r["protocol"], r["cluster_id"] == -1, -r["n_sessions"], r["cluster_id"]))
    with open(out_dir / "cluster_summary.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0]) if summary else ["protocol"])
        w.writeheader()
        w.writerows(summary)

    # 3. 신규 패턴 후보: 노이즈 + 이상 점수 상위 + 최근에 처음 나온 군집. 같은 정규화 시퀀스는 하나로
    first_seen = {(r["protocol"], r["cluster_id"]): parse_ts(r["first_ts"]) for r in summary}
    latest = max((parse_ts(sessions[k]["ts"][-1]) for k in ml), default=None)
    threshold = {}
    for proto in PROTOCOLS:
        sc = [v[2] for v in ml.values() if v[0] == proto]
        threshold[proto] = float(np.quantile(sc, OUTLIER_QUANTILE)) if sc else None
    groups = defaultdict(list)
    for k, (proto, c, sc, _) in ml.items():
        reasons = []
        if c == -1:
            reasons.append("noise")
        if sc > 0 and sc >= threshold[proto]:
            reasons.append("outlier")
        if c != -1 and first_seen[(proto, c)] >= latest - timedelta(days=RECENT_DAYS):
            reasons.append("recent_cluster")
        if reasons:
            groups[(proto, norm[k])].append((sc, k, c, reasons))
    novel = []
    for (proto, seq), items in groups.items():
        sc, k, c, _ = max(items, key=lambda x: x[0])
        novel.append({
            "protocol": proto, "source": k[0], "session_id": k[1], "src_ip": sessions[k]["src_ip"],
            "start_ts": sessions[k]["ts"][0], "cluster_id": c, "outlier_score": f"{sc:.4f}",
            "n_commands": len(sessions[k]["cmds"]), "downloaded": int(k in downloaded),
            "n_sessions": len(items),
            "reasons": ",".join(sorted({r for it in items for r in it[3]})),
            "normalized_seq": " ; ".join(seq), "raw_seq": " ; ".join(sessions[k]["cmds"]),
        })
    novel.sort(key=lambda r: -float(r["outlier_score"]))
    with open(out_dir / "novel_candidates.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(novel[0]) if novel else ["protocol"])
        w.writeheader()
        w.writerows(novel)

    # 화면: 프로토콜별 가장 큰 군집 3개 + 규칙 분포(참고)
    rules_of = defaultdict(list)
    if con.execute("SELECT 1 FROM sqlite_master WHERE name = 'signature_hits'").fetchone():
        for source, sid, rid in con.execute("SELECT source, session_id, rule_id FROM signature_hits"):
            rules_of[(source, sid)].append(rid)
    for proto in PROTOCOLS:
        top = [r for r in summary if r["protocol"] == proto and r["cluster_id"] != -1][:3]
        if not top:
            continue
        print(f"\n[{proto}] 가장 큰 군집 3개")
        for r in top:
            ks = members[(proto, r["cluster_id"])]
            print(f"  군집 {r['cluster_id']}: 세션 {r['n_sessions']:,}, IP {r['n_ips']:,}, "
                  f"{r['first_ts'][:10]} ~ {r['last_ts'][:10]} (대표 시퀀스 일치 {float(r['rep_share']):.0%})")
            print(f"    {r['representative'][:300]}")
            if rules_of:
                hits = Counter(rid for k in ks for rid in rules_of[k])
                print(f"    규칙 분포(참고): "
                      f"{', '.join(f'{x} {n / len(ks):.0%}' for x, n in hits.most_common(6)) or '없음'}")
    print(f"\n신규 패턴 후보 {len(novel):,}종 (세션 {sum(r['n_sessions'] for r in novel):,}개)")
    print(f"저장: ml_clusters 표, {out_dir}/session_clusters.csv, cluster_summary.csv, novel_candidates.csv")


def main():
    parser = argparse.ArgumentParser(description="세션 명령어 시퀀스를 군집화한다.")
    parser.add_argument("command", choices=["fit", "assign"])
    parser.add_argument("--db", default="data/honeypot.db")
    parser.add_argument("--out", default="ml/out")
    parser.add_argument("--models", default="ml/models")
    parser.add_argument("--mcs", type=int, help="fit: min_cluster_size 직접 지정 (기본: 비교 후 규칙으로 선택)")
    parser.add_argument("--ms", type=int, help="fit: min_samples 직접 지정 (기본: mcs와 같음)")
    parser.add_argument("--max-copies", type=int, default=MAX_COPIES,
                        help=f"fit: 같은 시퀀스 최대 복제 수 (기본 {MAX_COPIES}, 0 = 세션 전부)")
    args = parser.parse_args()
    con = sqlite3.connect(args.db)
    if args.command == "fit":
        fit(con, args.out, args.models, args.mcs, args.ms, args.max_copies)
    else:
        assign(con, args.out, args.models)
    con.close()


if __name__ == "__main__":
    main()
