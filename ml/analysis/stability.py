"""군집화 안정성 측정: 고유 시퀀스 입력 순서를 무작위로 바꿔 여러 번 학습하고 기준 결과와 비교한다.

사용법 (저장소 루트에서):
    python ml/analysis/stability.py [--db data/honeypot.db] [--out ml/out] [--protocol telnet]
                                    [--runs 20] [--configs 10:10,25:25] [--ip-caps 0,5]

기준 결과 = fit과 같은 순서(사전순)로 넣은 결과. ARI는 세션 단위(노이즈도 하나의 라벨)로 계산한다.
바뀐 해시 그룹은 각 실행의 군집을 실제 세션이 가장 많이 겹치는 기준 군집에 맞춘 뒤 센다.
결과: ml/out/stability.csv, ml/out/stability_changes.csv
"""
import argparse
import csv
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

import hdbscan
import numpy as np
from sklearn.metrics import adjusted_rand_score

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.cluster import (FINAL_MCS, FINAL_MS, MAX_COPIES, features, load_sessions,  # noqa: E402
                        normalize_session, replicate, seq_weights, size_order)


def main():
    p = argparse.ArgumentParser(description="군집화 안정성 측정")
    p.add_argument("--db", default="data/honeypot.db")
    p.add_argument("--out", default="ml/out")
    p.add_argument("--protocol", default="telnet")
    p.add_argument("--runs", type=int, default=20)
    p.add_argument("--configs", default=f"{FINAL_MCS}:{FINAL_MS},25:25", help="mcs:ms 목록")
    p.add_argument("--ip-caps", default="0,5", help="같은 (src_ip, 시퀀스) 최대 개수 목록, 0 = 제한 없음")
    args = p.parse_args()

    con = sqlite3.connect(args.db)
    S = load_sessions(con)
    keys = [k for k, s in S.items() if s["protocol"] == args.protocol]
    norm = {k: normalize_session(S[k]["cmds"]) for k in keys}
    uniq = sorted(set(norm.values()))  # fit과 같은 순서
    index = {q: i for i, q in enumerate(uniq)}
    real = seq_weights(keys, norm, S, index, 0)
    bysize = sorted(range(len(uniq)), key=lambda i: (-real[i], uniq[i]))
    name = {i: f"H{r}" if real[i] > 1 else f"H-({uniq[i][-1][:30]})" for r, i in enumerate(bysize)}

    def run(order, weights, mcs, ms):
        uq = [uniq[i] for i in order]
        _, _, _, Z = features(uq)
        rows, first = replicate([weights[i] for i in order], MAX_COPIES)
        raw = hdbscan.HDBSCAN(min_cluster_size=mcs, min_samples=ms).fit_predict(Z[rows])[first]
        lab = np.empty(len(uniq), dtype=int)
        lab[np.asarray(order)] = raw
        o = size_order(lab, weights)
        return np.array([o[int(x)] for x in lab])

    def per_session(lab):
        return np.repeat(lab, real)

    def align(lab, base):
        ov = defaultdict(Counter)
        for i, (a, b) in enumerate(zip(lab, base)):
            ov[a][b] += real[i]
        m = {a: (-1 if a == -1 else c.most_common(1)[0][0]) for a, c in ov.items()}
        return np.array([m[a] for a in lab])

    summary, changes = [], []
    print(f"[{args.protocol}] 세션 {len(keys):,} / 고유 시퀀스 {len(uniq)} / 무작위 순서 {args.runs}회")
    for cfg in args.configs.split(","):
        mcs, ms = map(int, cfg.split(":"))
        for cap in map(int, args.ip_caps.split(",")):
            weights = seq_weights(keys, norm, S, index, cap)
            base = run(list(range(len(uniq))), weights, mcs, ms)
            rng = np.random.default_rng(0)
            aris, changed = [], defaultdict(Counter)
            for _ in range(args.runs):
                lab = run(list(rng.permutation(len(uniq))), weights, mcs, ms)
                aris.append(adjusted_rand_score(per_session(base), per_session(lab)))
                al = align(lab, base)
                for i in np.flatnonzero(al != base):
                    changed[i][int(al[i])] += 1
            row = {"mcs": mcs, "ms": ms, "ip_cap": cap, "runs": args.runs,
                   "n_clusters": len(set(base) - {-1}),
                   "noise_sessions": sum(real[i] for i in range(len(uniq)) if base[i] == -1),
                   "ari_mean": f"{np.mean(aris):.4f}", "ari_min": f"{min(aris):.4f}",
                   "identical_runs": sum(a > 0.9999 for a in aris)}
            summary.append(row)
            print(f"  mcs={mcs} ms={ms} ip_cap={cap}: 군집 {row['n_clusters']}, 노이즈 {row['noise_sessions']}세션, "
                  f"ARI 평균 {row['ari_mean']} 최소 {row['ari_min']}, 기준과 같은 실행 {row['identical_runs']}/{args.runs}")
            for i in sorted(changed, key=lambda i: -sum(changed[i].values())):
                to = ", ".join(f"{'노이즈' if c == -1 else f'C{c}'} {n}회" for c, n in changed[i].most_common())
                changes.append({"mcs": mcs, "ms": ms, "ip_cap": cap, "hash_group": name[i], "sessions": real[i],
                                "base_cluster": int(base[i]), "changed_runs": sum(changed[i].values()), "changed_to": to})
                print(f"    {name[i]} ({real[i]}세션) 기준 C{base[i]} → {to}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for fname, rows, fields in (("stability.csv", summary, list(summary[0])),
                                ("stability_changes.csv", changes,
                                 ["mcs", "ms", "ip_cap", "hash_group", "sessions", "base_cluster",
                                  "changed_runs", "changed_to"])):
        with open(out / fname, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
    print(f"저장: {out / 'stability.csv'}, {out / 'stability_changes.csv'}")


if __name__ == "__main__":
    main()
