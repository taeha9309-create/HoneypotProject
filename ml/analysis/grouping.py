"""간극 세션을 묶는 방식 비교(T2): B 고유 순서, C 편집 거리, D ML 군집. 읽기 전용, `ml/cluster.py` 불변.

세 방식은 같은 인터페이스(fit → group_of, assign)를 쓰고 입력(훈련·평가 세션), 규칙 서명, 평가 기준이 모두 같다.
달라지는 것은 "무엇을 한 묶음으로 보는가"뿐이다. 이 도구는 탐지 성능을 재지 않는다. 재는 것은 묶음 수준의 기술 지표다:
 - 묶음 순도: 같은 묶음 안의 고유 순서들이 같은 구체 규칙 서명을 갖는 정도
 - 평가 순서의 배정률, 규칙 일치 배정률(배정된 묶음의 다수 서명 == 그 순서의 서명)
 - 노이즈·미배정 순서의 별도 구성(규칙 종류별)
규칙 서명 = 해당 순서의 적중 규칙에서 약한 규칙(B19)을 뺀 집합. 규칙 일치는 "규칙이 정의한 행동 계열과 같은 묶음"이라는
뜻이지 정답이나 악성 판정이 아니다(docs/adr/0001). 개발 단계의 탐색적 실험이며, 최종 독립 평가는 동결 시점 F 이후 데이터로 한다.

사용법 (저장소 루트에서):
    python ml/analysis/grouping.py run --data-dir <dashboard 데이터 폴더> --out <폴더> [--splits syd_to_seoul time seoul_to_syd]
        [--variants full drop_top_ip ip_cap1]
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

NOISE = "NOISE"
WEAK = ("B19",)
EDIT_THRESHOLD_GRID = (0.1, 0.2, 0.3, 0.4, 0.5)
EDIT_DEFAULT = 0.3
MODES = ("separate", "excluded", "one_group")


# ---------------------------------------------------------------- 거리

def token_distance(a, b):
    """명령 토큰 단위 편집 거리를 긴 쪽 길이로 나눈 값(0~1)."""
    if not a and not b:
        return 0.0
    if not a or not b:
        return 1.0
    prev = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        cur = [i]
        for j, y in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (x != y)))
        prev = cur
    return prev[-1] / max(len(a), len(b))


# ---------------------------------------------------------------- 묶는 방식

class ExactGrouper:
    """B: 정규화 순서가 완전히 같은 것만 같은 묶음. 훈련에 없던 순서는 배정하지 않는다."""
    name = "B_exact"

    def fit(self, seqs):
        self.group_of = {s: i for i, s in enumerate(sorted(set(seqs)))}
        return self

    def assign(self, seq):
        return ("group", self.group_of[seq]) if seq in self.group_of else ("none", None)


class EditGrouper:
    """C: 토큰 편집 거리 기준 평균 연결 응집형 묶음. 임계값이 없으면 훈련 순서만으로 정한다(실루엣 최대, 라벨 불필요)."""
    name = "C_edit"

    def __init__(self, threshold=None):
        self.threshold = threshold

    def fit(self, seqs):
        from scipy.cluster.hierarchy import fcluster, linkage
        from scipy.spatial.distance import squareform
        self.seqs = sorted(set(seqs))
        n = len(self.seqs)
        self.dist = [[token_distance(a, b) for b in self.seqs] for a in self.seqs]
        if n < 2:
            self.group_of = {s: 0 for s in self.seqs}
            self.threshold = self.threshold or EDIT_DEFAULT
            return self
        Z = linkage(squareform(self.dist, checks=False), method="average")
        if self.threshold is None:
            self.threshold = self._pick(Z, fcluster)
        labels = fcluster(Z, t=self.threshold, criterion="distance")
        self.group_of = {s: int(lab) for s, lab in zip(self.seqs, labels)}
        return self

    def _pick(self, Z, fcluster):
        from sklearn.metrics import silhouette_score
        import numpy as np
        D = np.array(self.dist)
        best, best_t = -2.0, EDIT_DEFAULT
        for t in EDIT_THRESHOLD_GRID:
            labels = fcluster(Z, t=t, criterion="distance")
            k = len(set(labels))
            if k < 2 or k >= len(self.seqs):
                continue
            score = silhouette_score(D, labels, metric="precomputed")
            if score > best + 1e-12:
                best, best_t = score, t
        return best_t

    def assign(self, seq):
        if not self.seqs:
            return ("none", None)
        d, nearest = min((token_distance(seq, s), s) for s in self.seqs)
        return ("group", self.group_of[nearest]) if d <= self.threshold else ("none", None)


class ClusterGrouper:
    """D: ML 군집 번호를 읽는다(훈련 전용 모델이 낸 번호). 노이즈(-1)는 한 군집으로 합치지 않고 별도로 유지한다."""
    name = "D_ml_cluster"

    def __init__(self, train_labels, eval_labels):
        self.group_of = {s: (NOISE if c == -1 else c) for s, c in train_labels.items()}
        self.eval_labels = eval_labels

    def assign(self, seq):
        if seq not in self.eval_labels:
            return ("none", None)
        c = self.eval_labels[seq]
        return ("noise", None) if c == -1 else ("group", c)


# ---------------------------------------------------------------- 서명과 지표

def signature(rules, weak=WEAK):
    return frozenset(set(rules) - set(weak))


def _tie_key(sig):
    return tuple(sorted(sig))


def majority_signatures(group_of, sig_of):
    """묶음별 다수 서명(노이즈 묶음 제외). 동률이면 서명이 사전순으로 앞선 것."""
    by = defaultdict(Counter)
    for s, gid in group_of.items():
        if gid != NOISE:
            by[gid][sig_of.get(s, frozenset())] += 1
    return {gid: min(c, key=lambda x: (-c[x], _tie_key(x))) for gid, c in by.items()}


def train_purity(group_of, sig_of):
    by = defaultdict(Counter)
    for s, gid in group_of.items():
        if gid != NOISE:
            by[gid][sig_of.get(s, frozenset())] += 1
    multi = [c for c in by.values() if sum(c.values()) >= 2]
    purity = [max(c.values()) / sum(c.values()) for c in multi]
    return {"groups": len(by), "multi_seq_groups": len(multi),
            "mean_purity_multi_seq": round(sum(purity) / len(purity), 4) if purity else None,
            "singleton_groups": sum(1 for c in by.values() if sum(c.values()) == 1)}


def consistency_flags(outcomes, eval_sig, maj, noise_sig, mode):
    """평가 순서별 규칙 일치 여부. 구체 규칙 서명이 있는 순서만 대상이다.
    separate: 노이즈·미배정은 불일치로 센다(분모에 포함). excluded: 분모에서 뺀다.
    one_group: 노이즈·미배정을 하나의 묶음으로 보고 그 다수 서명(noise_sig)과 비교한다."""
    flags = {}
    for s, (kind, gid) in outcomes.items():
        sig = eval_sig.get(s, frozenset())
        if not sig:
            continue
        if kind == "group":
            flags[s] = maj.get(gid) == sig
        elif mode == "separate":
            flags[s] = False
        elif mode == "one_group":
            flags[s] = noise_sig == sig
    return flags


def consistency(outcomes, eval_sig, maj, noise_sig):
    out = {}
    for mode in MODES:
        flags = consistency_flags(outcomes, eval_sig, maj, noise_sig, mode)
        ok, total = sum(flags.values()), len(flags)
        out[mode] = {"consistent": ok, "denominator": total, "rate": round(ok / total, 4) if total else None}
    return out


def unassigned_composition(outcomes, sig, weights, weak_only):
    """노이즈·미배정 순서를 별도 분석 대상으로 남긴다: 순서·세션 수와 규칙 종류별 구성."""
    out = {}
    for kind in ("noise", "none"):
        seqs = [s for s, (k, _) in outcomes.items() if k == kind]
        specific = sum(1 for s in seqs if sig.get(s))
        weak = sum(1 for s in seqs if s in weak_only)
        out[kind] = {"seqs": len(seqs), "sessions": sum(weights.get(s, 0) for s in seqs),
                     "with_specific_rule": specific, "weak_only": weak,
                     "no_rule": len(seqs) - specific - weak}
    return out


def unit_rates(ok_by_seq, eval_records):
    """순서(주 지표)·세션·IP 단위 비율. ok_by_seq에 없는 순서는 분모에서 뺀다."""
    recs = [(s, ip) for s, ip in eval_records if s in ok_by_seq]
    ips_ok, ips_all = set(), set()
    for s, ip in recs:
        ips_all.add(ip)
        if ok_by_seq[s]:
            ips_ok.add(ip)

    def block(ok, total):
        return {"ok": ok, "total": total, "rate": round(ok / total, 4) if total else None}
    return {"unique_seq": block(sum(ok_by_seq.values()), len(ok_by_seq)),
            "session": block(sum(1 for s, _ in recs if ok_by_seq[s]), len(recs)),
            "ip": block(len(ips_ok), len(ips_all))}


# ---------------------------------------------------------------- 실행 (실제 데이터)

def _evaluate(grouper, train_seqs, train_sig, eval_seqs, eval_sig, eval_records, weights, weak_only, unseen):
    group_of = grouper.group_of
    maj = majority_signatures(group_of, train_sig)
    noise_group = {s: train_sig.get(s, frozenset()) for s, gid in group_of.items() if gid == NOISE}
    noise_sig = min(Counter(noise_group.values()).items(), key=lambda kv: (-kv[1], _tie_key(kv[0])))[0] if noise_group \
        else frozenset()
    outcomes = {s: grouper.assign(s) for s in eval_seqs}
    res = {"train": train_purity(group_of, train_sig), "train_noise_seqs": len(noise_group),
           "eval_seqs": len(eval_seqs), "eval_unseen_seqs": len(unseen)}
    assigned = {s: o[0] == "group" for s, o in outcomes.items()}
    res["assigned_rate"] = {"all": unit_rates(assigned, eval_records),
                            "unseen": unit_rates({s: v for s, v in assigned.items() if s in unseen}, eval_records)}
    res["consistency"] = {}
    for scope, subset in (("all", None), ("unseen", unseen)):
        sub = {s: o for s, o in outcomes.items() if subset is None or s in subset}
        summary = consistency(sub, eval_sig, maj, noise_sig)
        for mode in MODES:
            flags = consistency_flags(sub, eval_sig, maj, noise_sig, mode)
            summary[mode]["units"] = unit_rates(flags, eval_records)
        res["consistency"][scope] = summary
    res["unassigned"] = {"all": unassigned_composition(outcomes, eval_sig, weights, weak_only),
                         "unseen": unassigned_composition({s: o for s, o in outcomes.items() if s in unseen},
                                                          eval_sig, weights, weak_only)}
    return res, outcomes


def run_one(data_dir, split, out_dir, variant):
    import sqlite3
    from ml.analysis import gap_baseline, splits
    from ml.cluster import load_sessions, normalize_session
    kw = {"full": {}, "drop_top_ip": {"drop_top_train_ip": True}, "ip_cap1": {"fit_ip_cap": 1}}[variant]
    run_dir = Path(out_dir) / variant
    info = splits.run_split(data_dir, split, run_dir, **kw)
    rows, _ = gap_baseline.load_rows(data_dir)
    rules = {r["key"]: r["rules"] for r in rows}
    con = splits.ro(run_dir / split / "ml_train.db")
    sess = load_sessions(con)
    labels = {(s, i): (c, by) for s, i, c, by in con.execute(
        "SELECT source, session_id, cluster_id, assigned_by FROM ml_clusters")}
    con.close()
    seq = {k: tuple(normalize_session(sess[k]["cmds"])) for k in labels}
    train_keys = [k for k, (_, by) in labels.items() if by == "fit"]
    eval_keys = [k for k, (_, by) in labels.items() if by == "assign"]
    train_seqs = sorted({seq[k] for k in train_keys})
    eval_seqs = sorted({seq[k] for k in eval_keys})
    unseen = set(eval_seqs) - set(train_seqs)

    def sig_map(keys):
        u = defaultdict(set)
        for k in keys:
            u[seq[k]] |= set(rules.get(k, set()))
        return {s: signature(v) for s, v in u.items()}, {s for s, v in u.items() if v and v <= set(WEAK)}

    train_sig, _ = sig_map(train_keys)
    eval_sig, weak_only = sig_map(eval_keys)
    weights = Counter(seq[k] for k in eval_keys)
    eval_records = [(seq[k], sess[k]["src_ip"]) for k in eval_keys]
    lab_train, lab_eval = defaultdict(Counter), defaultdict(Counter)
    for k in train_keys:
        lab_train[seq[k]][labels[k][0]] += 1
    for k in eval_keys:
        lab_eval[seq[k]][labels[k][0]] += 1
    major = lambda d: {s: c.most_common(1)[0][0] for s, c in d.items()}  # noqa: E731
    groupers = {"B_exact": ExactGrouper().fit(train_seqs), "C_edit": EditGrouper().fit(train_seqs),
                "D_ml_cluster": ClusterGrouper(major(lab_train), major(lab_eval))}
    result = {"split": split, "variant": variant,
              # 실험에 쓴 ML 모델 버전: cluster.py 해시·파라미터를 항상 기록한다(팀원이 개선한 버전과 구분하기 위해)
              "ml_version": {"label": "baseline-cluster.py", **{k: info["env"][k] for k in (
                  "cluster_py_sha256", "normalize_version", "hdbscan_final_params", "hdbscan", "scikit_learn")}},
              "input_sha256": info["input_sha256"],
              "split_info": {k: info[k] for k in ("overlap", "variant", "model") if k in info},
              "exploratory": ("개발 단계 탐색적 실험이다. 주 분할(시드니→서울)은 데이터를 본 뒤 선택했고 11/18~25 구간은 "
                              "이미 사용됐다. 최종 독립 평가는 동결 시점 F 이후 데이터로 한다."),
              "edit_threshold": groupers["C_edit"].threshold, "groupers": {}}
    for name, gr in groupers.items():
        res, _ = _evaluate(gr, train_seqs, train_sig, eval_seqs, eval_sig, eval_records, weights, weak_only, unseen)
        result["groupers"][name] = res
    # 편집 거리 임계값 민감도: 선택값이 격자 끝에 걸리는지, 임계값에 따라 결론이 바뀌는지 본다(선택 규칙은 그대로 유지)
    result["edit_threshold_sensitivity"] = {}
    for t in EDIT_THRESHOLD_GRID + (0.6, 0.7):
        res_t, _ = _evaluate(EditGrouper(threshold=t).fit(train_seqs), train_seqs, train_sig, eval_seqs, eval_sig,
                             eval_records, weights, weak_only, unseen)
        cs = res_t["consistency"]
        result["edit_threshold_sensitivity"][str(t)] = {
            "groups": res_t["train"]["groups"], "purity": res_t["train"]["mean_purity_multi_seq"],
            "unseen_separate": cs["unseen"]["separate"], "unseen_excluded": cs["unseen"]["excluded"],
            "all_separate": cs["all"]["separate"]}
    # 훈련 순서 묶음 간 일치(C와 D): 번호가 아니라 분할의 일치(ARI)
    from sklearn.metrics import adjusted_rand_score
    seqs_nn = [s for s in train_seqs if groupers["D_ml_cluster"].group_of.get(s) != NOISE]
    result["ari_C_vs_D_train"] = round(adjusted_rand_score(
        [groupers["C_edit"].group_of[s] for s in seqs_nn],
        [groupers["D_ml_cluster"].group_of[s] for s in seqs_nn]), 3) if len(seqs_nn) > 1 else None
    (run_dir / split / "grouping.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str),
                                                    encoding="utf-8")
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["run"])
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--splits", nargs="*", default=["syd_to_seoul", "time", "seoul_to_syd"])
    ap.add_argument("--variants", nargs="*", default=["full", "drop_top_ip", "ip_cap1"])
    a = ap.parse_args()
    for split in a.splits:
        for variant in a.variants:
            r = run_one(a.data_dir, split, Path(a.out) / split, variant)
            print(split, variant, "done", {k: v["consistency"]["all"]["separate"]["rate"] for k, v in r["groupers"].items()})


if __name__ == "__main__":
    main()
