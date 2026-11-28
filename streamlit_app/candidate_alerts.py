"""Aggregate review alerts for pending local candidates."""
from ml.analysis import proposal_registry


def messages(path):
    result = []
    for candidate in proposal_registry.load(path):
        if candidate["status"] != "proposed":
            continue
        if candidate["protocol"] not in ("ssh", "telnet"):
            raise ValueError("unexpected candidate protocol")
        evidence = candidate["discoveries"][0]["evidence"]
        totals = evidence["validation"]["all"]
        # Only validated counts and fixed text enter an external message.
        keys = ("population", "matches", "b19_only_refined", "already_specific")
        counts = {key: totals[key] for key in keys}
        if any(type(value) is not int or value < 0 for value in counts.values()):
            raise ValueError("invalid candidate counts")
        cid = candidate["id"]
        if len(cid) != 65 or not cid.startswith("P") or any(c not in "0123456789abcdef" for c in cid[1:]):
            raise ValueError("invalid candidate ID")
        result.append({
            "event_key": "candidate/" + cid,
            "kind": "candidate_review",
            "text": (
                f"[허니팟 후보 검토] {candidate['protocol'].upper()} · {cid[:13]}\n"
                f"보관 자료 {counts['population']:,}세션 중 {counts['matches']:,}세션 일치 · "
                f"B19 단독 적중 세분화 {counts['b19_only_refined']:,}세션 · "
                f"기존 구체 규칙과 중복 {counts['already_specific']:,}세션\n"
                "로컬 예시 로직의 검토용 초안입니다. 대시보드의 저장된 검토 후보에서 근거를 확인하세요."
            ),
        })
    return result
