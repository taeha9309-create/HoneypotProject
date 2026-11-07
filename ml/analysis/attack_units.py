"""같은 IP에서 짧은 간격으로 이어진 세션을 '공격 단위'로 묶어 군집 조합을 센다.

사용법 (저장소 루트에서, fit 이후):
    python ml/analysis/attack_units.py [--db data/honeypot.db] [--out ml/out] [--protocol telnet] [--gap 10]

간격 = 다음 세션의 첫 명령 시각 - 이전 세션의 마지막 명령 시각. 대상은 ml_clusters에 있는 세션
(명령어가 있는 세션)이고, 로그인만 하고 끝난 세션은 넣지 않는다.
결과: ml/out/attack_units.csv (군집 조합별), ml/out/attack_units_by_cluster.csv (군집별 공격 단위 수)
"""
import argparse
import csv
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ml.cluster import load_sessions  # noqa: E402


def parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def main():
    p = argparse.ArgumentParser(description="공격 단위 분석")
    p.add_argument("--db", default="data/honeypot.db")
    p.add_argument("--out", default="ml/out")
    p.add_argument("--protocol", default="telnet")
    p.add_argument("--gap", type=float, default=10, help="같은 공격으로 볼 최대 간격(초)")
    args = p.parse_args()

    con = sqlite3.connect(args.db)
    S = load_sessions(con)
    by_ip = defaultdict(list)
    for src, sid, c in con.execute(
            "SELECT source, session_id, cluster_id FROM ml_clusters WHERE protocol = ?", (args.protocol,)):
        s = S.get((src, sid))
        if s:
            by_ip[s["src_ip"]].append((parse(s["ts"][0]), parse(s["ts"][-1]), c))

    units, gaps = [], Counter()
    for ip, ss in by_ip.items():
        ss.sort()
        cur = [ss[0]]
        for prev, nxt in zip(ss, ss[1:]):
            g = (nxt[0] - prev[1]).total_seconds()
            gaps["≤gap" if g <= args.gap else "gap~60s" if g <= 60 else "1~10분" if g <= 600 else ">10분"] += 1
            if g <= args.gap:
                cur.append(nxt)
            else:
                units.append((ip, cur))
                cur = [nxt]
        units.append((ip, cur))

    combo, combo_ips, per_cluster, per_cluster_ips = Counter(), defaultdict(set), Counter(), defaultdict(set)
    for ip, u in units:
        k = "→".join(str(c) for *_, c in u)
        combo[k] += 1
        combo_ips[k].add(ip)
        for c in {c for *_, c in u}:
            per_cluster[c] += 1
            per_cluster_ips[c].add(ip)

    n_sess = sum(len(u) for _, u in units)
    print(f"[{args.protocol}] 세션 {n_sess:,}개 → 공격 단위 {len(units):,}개 (IP {len(by_ip)}개, 간격 {args.gap:g}초 이내)")
    print("단위당 세션 수:", dict(sorted(Counter(len(u) for _, u in units).items())))
    print("같은 IP 연속 세션 간격:", dict(gaps))
    print(f"\n{'군집 조합':<14} {'단위 수':>7} {'IP 수':>6}")
    for k, n in combo.most_common():
        print(f"{k:<14} {n:>7,} {len(combo_ips[k]):>6}")
    print(f"\n{'군집':<6} {'포함 단위 수':>10} {'IP 수':>6}")
    for c in sorted(per_cluster, key=lambda c: (c == -1, c)):
        print(f"{c:<6} {per_cluster[c]:>10,} {len(per_cluster_ips[c]):>6}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "attack_units.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["protocol", "gap_seconds", "cluster_combo", "units", "ips"])
        for k, n in combo.most_common():
            w.writerow([args.protocol, args.gap, k, n, len(combo_ips[k])])
    with open(out / "attack_units_by_cluster.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["protocol", "gap_seconds", "cluster_id", "units", "ips"])
        for c in sorted(per_cluster, key=lambda c: (c == -1, c)):
            w.writerow([args.protocol, args.gap, c, per_cluster[c], len(per_cluster_ips[c])])
    print(f"\n저장: {out / 'attack_units.csv'}, {out / 'attack_units_by_cluster.csv'}")


if __name__ == "__main__":
    main()
