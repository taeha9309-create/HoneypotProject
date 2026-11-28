"""평가용 데이터 분할(시간·허니팟 교차)과 훈련 전용 군집 모델 실행, 결정성·환경 기록.

`ml/cluster.py`는 수정하지 않고 함수만 가져다 쓴다. 원본 DB는 읽기 전용으로만 열고, `fit`은 항상
사본 DB에서 돌린다(`fit`이 ml_clusters를 지우기 때문).

사용법 (저장소 루트에서):
    python ml/analysis/splits.py run  --data-dir <dashboard 데이터 폴더> --split time|syd_to_seoul|seoul_to_syd --out <폴더>
    python ml/analysis/splits.py determinism --data-dir ... --split time --out <폴더> [--runs 3]

해석 주의: 이 도구는 평가용 분할과 재현 기록을 만들 뿐이다. 군집 번호는 정답 라벨이 아니고 학습마다 달라진다.
공격자 입력은 문자열로만 다루며 실행하지 않는다.
"""
import argparse
import contextlib
import hashlib
import io
import json
import platform
import random
import shutil
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

CUTOFF = "2026-11-18T00:00:00"  # 개발 검증 구간 시작(UTC). 이 구간은 이미 사용됐다(docs/advancement-spec.ko.md 3절)
SPLITS = {
    "time": {"train": {"before": CUTOFF}, "eval": {"from": CUTOFF}},
    "syd_to_seoul": {"train": {"source": "syd"}, "eval": {"source": "seoul"}},
    "seoul_to_syd": {"train": {"source": "seoul"}, "eval": {"source": "syd"}},
}


# ---------------------------------------------------------------- 순수 함수 (단위 테스트 대상)

def in_part(source, start_ts, cond):
    """cond: {"before": ts} / {"from": ts} / {"source": name}."""
    if "before" in cond and not start_ts < cond["before"]:
        return False
    if "from" in cond and not start_ts >= cond["from"]:
        return False
    return not ("source" in cond and source != cond["source"])


def select(rows, split):
    """rows: (source, session_id, start_ts) 반복. 반환: (훈련 키 집합, 평가 키 집합). 겹치면 안 된다."""
    spec = SPLITS[split] if isinstance(split, str) else split
    train = {(s, i) for s, i, t in rows if in_part(s, t, spec["train"])}
    held = {(s, i) for s, i, t in rows if in_part(s, t, spec["eval"])}
    if train & held:
        raise ValueError("훈련과 평가 구간이 겹친다")
    return train, held


def top_share(counter, k=1):
    total = sum(counter.values())
    return round(sum(n for _, n in counter.most_common(k)) / total, 4) if total else None


def overlap(train, held):
    """train/held: {키: (정규화 순서 tuple, src_ip)}. 훈련과 평가의 순서·IP·캠페인(같은 IP+같은 순서) 겹침."""
    t_seq = {v[0] for v in train.values()}
    t_ip = {v[1] for v in train.values()}
    t_pair = {(v[1], v[0]) for v in train.values()}
    n = len(held)
    seq_seen = sum(1 for v in held.values() if v[0] in t_seq)
    ip_seen = sum(1 for v in held.values() if v[1] in t_ip)
    camp_seen = sum(1 for v in held.values() if (v[1], v[0]) in t_pair)
    held_seq = {v[0] for v in held.values()}
    unseen = held_seq - t_seq
    unseen_keys = [k for k, v in held.items() if v[0] in unseen]
    return {
        "train_sessions": len(train), "eval_sessions": n,
        "train_unique_seqs": len(t_seq), "eval_unique_seqs": len(held_seq),
        "eval_unseen_unique_seqs": len(unseen), "eval_unseen_sessions": len(unseen_keys),
        "eval_unseen_ips": len({held[k][1] for k in unseen_keys}),
        "eval_sessions_seq_seen_pct": round(seq_seen / n * 100, 1) if n else None,
        "eval_sessions_ip_seen_pct": round(ip_seen / n * 100, 1) if n else None,
        "eval_sessions_same_ip_and_seq_seen_pct": round(camp_seen / n * 100, 1) if n else None,
        "train_top1_ip_share": top_share(Counter(v[1] for v in train.values())),
        "eval_top1_ip_share": top_share(Counter(v[1] for v in held.values())),
        "train_top2_seq_share": top_share(Counter(v[0] for v in train.values()), 2),
        "eval_top2_seq_share": top_share(Counter(v[0] for v in held.values()), 2),
    }


def top_ip(items):
    """items: {키: (순서, src_ip)}. 세션이 가장 많은 IP(동률이면 문자열이 작은 IP). 없으면 None."""
    counts = Counter(v[1] for v in items.values())
    if not counts:
        return None
    best = max(counts.values())
    return min(ip for ip, n in counts.items() if n == best)


def drop_ip(items, ip):
    """해당 IP의 세션을 뺀 새 dict(원본은 그대로)."""
    return {k: v for k, v in items.items() if v[1] != ip}


def partition_diff(a, b):
    """a, b: {키: (protocol, cluster_id)}. 같은 키 집합에서 군집 번호가 다른 세션 수(0이면 완전히 같다)."""
    if set(a) != set(b):
        raise ValueError("두 결과의 세션 집합이 다르다")
    return sum(1 for k in a if a[k] != b[k])


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def env_record():
    """재현에 필요한 실행 환경과 난수 설정을 기록한다."""
    import numpy
    import sklearn
    out = {"python": platform.python_version(), "platform": platform.platform(),
           "numpy": numpy.__version__, "scikit_learn": sklearn.__version__}
    from importlib import metadata
    for name in ("hdbscan", "joblib", "scipy", "pandas"):
        try:
            out[name] = metadata.version(name)
        except metadata.PackageNotFoundError:  # 기록용이라 없으면 비워 둔다
            out[name] = None
    from ml import cluster
    out["cluster_py_sha256"] = sha256_file(Path(cluster.__file__))
    out["normalize_version"] = cluster.NORMALIZE_VERSION
    out["hdbscan_final_params"] = {"mcs": cluster.FINAL_MCS, "ms": cluster.FINAL_MS,
                                   "max_copies": cluster.MAX_COPIES, "ip_cap": cluster.IP_CAP}
    out["random_state"] = {"TruncatedSVD": 0, "silhouette_score": 0,
                           "note": "cluster.py 코드에 고정된 값. HDBSCAN 자체는 난수를 쓰지 않는다"}
    return out


# ---------------------------------------------------------------- DB 작업 (사본에서만)

def ro(path):
    return sqlite3.connect("file:" + Path(path).as_posix() + "?mode=ro", uri=True)


def _session_rows(con):
    return con.execute("SELECT source, session_id, start_ts FROM sessions WHERE excluded = 0 AND n_commands > 0").fetchall()


def _labels(con):
    return {(s, i): (p, c) for s, i, p, c in con.execute(
        "SELECT source, session_id, protocol, cluster_id FROM ml_clusters")}


def _scores(con):
    return {(s, i): sc for s, i, sc in con.execute("SELECT source, session_id, outlier_score FROM ml_clusters")}


def build_train_db(src_ml_db, dest_db, train_keys, shuffle_seed=None):
    """원본 ml.db를 사본으로 만들고 훈련 세션만 남긴다. shuffle_seed가 있으면 세션 단위로 삽입 순서를 섞는다
    (세션 안의 명령 순서는 유지: 같은 시각 명령은 rowid로 순서가 정해지므로 바꾸지 않는다)."""
    shutil.copy(src_ml_db, dest_db)
    con = sqlite3.connect(dest_db)
    cols_s = [r[1] for r in con.execute("PRAGMA table_info(sessions)")]
    cols_c = [r[1] for r in con.execute("PRAGMA table_info(commands)")]
    keep = set(train_keys)
    srows = [r for r in con.execute(f"SELECT {','.join(cols_s)} FROM sessions") if (r[0], r[1]) in keep]
    by_session = {}
    for r in con.execute(f"SELECT {','.join(cols_c)} FROM commands ORDER BY rowid"):
        if (r[cols_c.index("source")], r[cols_c.index("session_id")]) in keep:
            by_session.setdefault((r[cols_c.index("source")], r[cols_c.index("session_id")]), []).append(r)
    order = sorted(by_session)
    if shuffle_seed is not None:
        random.Random(shuffle_seed).shuffle(order)
        random.Random(shuffle_seed + 1).shuffle(srows)
    with con:
        con.execute("DELETE FROM commands")
        con.execute("DELETE FROM sessions")
        con.executemany(f"INSERT INTO sessions ({','.join(cols_s)}) VALUES ({','.join('?' * len(cols_s))})", srows)
        for k in order:
            con.executemany(f"INSERT INTO commands ({','.join(cols_c)}) VALUES ({','.join('?' * len(cols_c))})",
                            by_session[k])
    return con


def add_eval_sessions(con, src_ml_db, eval_keys):
    """평가 세션과 명령을 훈련용 사본에 넣는다(배정 전에만 쓴다)."""
    orig = ro(src_ml_db)
    cols_s = [r[1] for r in orig.execute("PRAGMA table_info(sessions)")]
    cols_c = [r[1] for r in orig.execute("PRAGMA table_info(commands)")]
    keep = set(eval_keys)
    srows = [r for r in orig.execute(f"SELECT {','.join(cols_s)} FROM sessions") if (r[0], r[1]) in keep]
    crows = [r for r in orig.execute(f"SELECT {','.join(cols_c)} FROM commands ORDER BY rowid")
             if (r[cols_c.index("source")], r[cols_c.index("session_id")]) in keep]
    with con:
        con.executemany(f"INSERT INTO sessions ({','.join(cols_s)}) VALUES ({','.join('?' * len(cols_s))})", srows)
        con.executemany(f"INSERT INTO commands ({','.join(cols_c)}) VALUES ({','.join('?' * len(cols_c))})", crows)
    orig.close()


def fit_quiet(con, out_dir, models_dir, **kwargs):
    """cluster.fit을 그대로 호출한다. kwargs는 fit의 기존 인자(예: ip_cap)만 전달한다."""
    from ml import cluster
    buf = io.StringIO()
    t = time.perf_counter()
    with contextlib.redirect_stdout(buf):
        cluster.fit(con, out_dir, models_dir, **kwargs)
    return round(time.perf_counter() - t, 1)


def assign_quiet(con, out_dir, models_dir):
    from ml import cluster
    buf = io.StringIO()
    t = time.perf_counter()
    with contextlib.redirect_stdout(buf):
        cluster.assign(con, out_dir, models_dir)
    return round(time.perf_counter() - t, 1)


def source_config(data_dir):
    """허니팟별 설정·수집 기간·원본 로그 여부(dashboard.db sources)."""
    con = ro(Path(data_dir) / "dashboard.db")
    cols = [r[1] for r in con.execute("PRAGMA table_info(sources)")]
    rows = [dict(zip(cols, r)) for r in con.execute("SELECT * FROM sources")]
    con.close()
    return rows


def run_split(data_dir, split, out_dir, with_assign=True, drop_top_train_ip=False, fit_ip_cap=0):
    """한 분할을 실행하고 요약 dict를 반환한다. 원본 DB 해시를 전후로 비교한다.

    민감도 실험용 옵션(기준선은 바꾸지 않는다): drop_top_train_ip면 훈련에서 세션이 가장 많은 IP를 뺀다.
    fit_ip_cap은 cluster.fit의 기존 ip_cap 인자(같은 IP+같은 순서를 최대 N세션까지만 가중)를 그대로 쓴다."""
    from ml.cluster import load_sessions, normalize_session
    data_dir, out_dir = Path(data_dir), Path(out_dir)
    src = data_dir / "ml.db"
    before = {f: sha256_file(data_dir / f) for f in ("ml.db", "dashboard.db") if (data_dir / f).exists()}
    run = out_dir / split
    if run.exists():
        shutil.rmtree(run)
    run.mkdir(parents=True)
    orig = ro(src)
    train_keys, eval_keys = select(_session_rows(orig), split)
    sess = load_sessions(orig)
    info = {k: (tuple(normalize_session(sess[k]["cmds"])), sess[k]["src_ip"]) for k in sess}
    train = {k: info[k] for k in train_keys if k in info}
    held = {k: info[k] for k in eval_keys if k in info}
    orig.close()
    dropped_n = 0
    if drop_top_train_ip:
        ip = top_ip(train)
        dropped_n = sum(1 for v in train.values() if v[1] == ip)
        train = drop_ip(train, ip)
    result = {"split": split, "spec": SPLITS[split], "overlap": overlap(train, held),
              "variant": {"drop_top_train_ip": bool(drop_top_train_ip), "fit_ip_cap": fit_ip_cap,
                          "dropped_train_sessions": dropped_n},
              "source_config": source_config(data_dir), "env": env_record(), "input_sha256": before}
    if with_assign:
        con = build_train_db(src, run / "ml_train.db", train)
        result["fit_seconds"] = fit_quiet(con, run / "out", run / "models", ip_cap=fit_ip_cap)
        tl = _labels(con)
        add_eval_sessions(con, src, held)
        result["assign_seconds"] = assign_quiet(con, run / "out", run / "models")
        al = _labels(con)
        sc = _scores(con)
        hold_l = {k: v for k, v in al.items() if k in held}
        train_clusters = {v for k, v in tl.items() if v[1] != -1}
        noise = sum(1 for v in hold_l.values() if v[1] == -1)
        result["model"] = {
            "train_clusters": len(train_clusters),
            "train_noise_pct": round(sum(1 for v in tl.values() if v[1] == -1) / max(len(tl), 1) * 100, 1),
            "eval_assigned": len(hold_l), "eval_noise_pct": round(noise / max(len(hold_l), 1) * 100, 1),
            "eval_in_unknown_cluster": sum(1 for v in hold_l.values() if v[1] != -1 and v not in train_clusters),
            "eval_score_le_1e-9_pct": round(sum(1 for k in hold_l if sc[k] is not None and sc[k] <= 1e-9)
                                            / max(len(hold_l), 1) * 100, 1),
        }
        # 훈련에 없던 순서의 배정 결과(군집·편집거리 팔이 다를 수 있는 지점)
        t_seq = {v[0] for v in train.values()}
        un = [k for k, v in held.items() if v[0] not in t_seq]
        result["model"]["eval_unseen_sessions_noise"] = sum(1 for k in un if al.get(k, (0, 0))[1] == -1)
        con.close()
    after = {f: sha256_file(data_dir / f) for f in before}
    result["orig_unchanged"] = before == after
    (run / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def determinism(data_dir, split, out_dir, runs=3):
    """같은 훈련 입력으로 fit을 여러 번 돌려 결과가 같은지 확인한다. 같은 입력 반복 + 세션 삽입 순서를 섞은 입력."""
    import numpy as np
    import joblib
    from ml.cluster import load_sessions
    data_dir, out_dir = Path(data_dir), Path(out_dir)
    src = data_dir / "ml.db"
    orig = ro(src)
    train_keys, _ = select(_session_rows(orig), split)
    orig.close()
    base = out_dir / f"determinism_{split}"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    variants = [("identical", None)] * runs + [("shuffled_sessions", 11), ("shuffled_sessions", 23)]
    outs = []
    for n, (kind, seed) in enumerate(variants):
        d = base / f"v{n}"
        d.mkdir()
        con = build_train_db(src, d / "ml.db", train_keys, shuffle_seed=seed)
        row_hash = hashlib.sha256(json.dumps(sorted(
            (k[0], k[1]) for k in load_sessions(con))).encode()).hexdigest()
        fit_quiet(con, d / "out", d / "models")
        labels, scores = _labels(con), _scores(con)
        models = {}
        for proto in ("ssh", "telnet"):
            p = d / "models" / f"{proto}.joblib"
            if p.exists():
                m = joblib.load(p)
                models[proto] = {"centroids": m["centroids"], "svd": m["svd"].components_,
                                 "vocab_n": len(m["vectorizer"].vocabulary_), "label_order": list(m["label_order"])}
        con.close()
        outs.append({"kind": kind, "seed": seed, "labels": labels, "scores": scores, "models": models,
                     "session_set_sha256": row_hash})
    ref = outs[0]
    report = {"split": split, "train_sessions": len(train_keys), "env": env_record(),
              "input_sha256": sha256_file(src), "comparisons": []}
    for n, o in enumerate(outs[1:], start=1):
        item = {"variant": n, "kind": o["kind"], "shuffle_seed": o["seed"],
                "same_session_set": o["session_set_sha256"] == ref["session_set_sha256"],
                "sessions_with_different_cluster": partition_diff(ref["labels"], o["labels"]),
                "max_abs_score_diff": float(max(abs((ref["scores"][k] or 0) - (o["scores"][k] or 0))
                                                for k in ref["scores"])),
                "models": {}}
        for proto, m in ref["models"].items():
            mo = o["models"].get(proto)
            item["models"][proto] = None if mo is None else {
                "centroids_allclose": bool(m["centroids"].shape == mo["centroids"].shape
                                           and np.allclose(m["centroids"], mo["centroids"], atol=1e-9)),
                "svd_allclose": bool(np.allclose(m["svd"], mo["svd"], atol=1e-9)),
                "vocab_same_size": m["vocab_n"] == mo["vocab_n"], "label_order_same": m["label_order"] == mo["label_order"]}
        report["comparisons"].append(item)
    report["deterministic"] = all(c["sessions_with_different_cluster"] == 0 for c in report["comparisons"])
    (base / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["run", "determinism"])
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--split", choices=list(SPLITS), required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--runs", type=int, default=3)
    a = ap.parse_args()
    r = run_split(a.data_dir, a.split, a.out) if a.command == "run" else determinism(a.data_dir, a.split, a.out, a.runs)
    print(json.dumps(r, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
