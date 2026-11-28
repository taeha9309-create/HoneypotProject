"""Build a redacted review request and validate a structured proposal.

The demo provider is local and deterministic. Draft steps reference observed
labels and are never operational rules.
"""
from copy import deepcopy

from ml.analysis.label_sample import VERBS

OMITTED_ARGUMENTS = " [인수 생략]"
UNKNOWN = "[기타 입력 생략]"


def safe_step(step):
    if step == UNKNOWN or step in VERBS:
        return True
    return (isinstance(step, str) and
            (step == "busybox [탐침 토큰]"
             or (step.endswith(OMITTED_ARGUMENTS) and step[:-len(OMITTED_ARGUMENTS)] in VERBS)))


def count(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError("invalid aggregate count")
    return value


def build_request(group):
    protocol = group["protocol"]
    if protocol not in ("ssh", "telnet"):
        raise ValueError("unexpected protocol")
    flows = []
    for flow in group["representative_flows"][:3]:
        steps = flow["observed_flow"].splitlines()
        if not 1 <= len(steps) <= 12 or not all(safe_step(step) for step in steps):
            raise ValueError("flow contains data outside the redacted vocabulary")
        sessions = count(flow["sessions"], 2)
        ips = count(flow["ips"])
        if ips > sessions:
            raise ValueError("flow IP count exceeds its session count")
        flows.append({"steps": steps, "sessions": sessions, "distinct_ip_count": ips,
                      "omitted_steps": count(flow["steps_omitted"])})
    recurrent = count(group["recurrent_gap_sessions"])
    gaps = count(group["gap_sessions"])
    total = count(group["cluster_sessions"])
    if not 0 < recurrent <= gaps <= total or not flows or sum(f["sessions"] for f in flows) > recurrent:
        raise ValueError("group counts do not match the representative flows")
    return {
        "protocol": protocol,
        "cluster_id": count(group["cluster_id"]),
        "cluster_sessions": total,
        "underdescribed_sessions": gaps,
        "recurrent_sessions": recurrent,
        "representative_flows": flows,
    }


def demo_provider(request):
    menu = ["enable", "linuxshell", "system", "shell", "sh"]
    for index, flow in enumerate(request["representative_flows"]):
        steps = flow["steps"]
        if steps in (menu, ["enable", "system", "shell", "sh"]) and not flow["omitted_steps"]:
            return {
                "decision": "propose",
                "behavior": "셸 진입 전 장비 메뉴를 순서대로 탐색하는 입력",
                "reason": "메뉴 진입 명령과 셸 진입이 같은 순서로 반복됐습니다.",
                "evidence_flows": [index],
                "draft": {"flow": index, "positions": list(range(len(steps)))},
            }
        if (len(steps) >= 2 and steps[-2:] == ["sh", "busybox [탐침 토큰]"]
                and not flow["omitted_steps"]):
            return {
                "decision": "propose",
                "behavior": "셸 진입 뒤 환경 탐침 입력",
                "reason": "셸 진입 직후 탐침 토큰이 반복돼 순서 조건을 검토할 수 있습니다.",
                "evidence_flows": [index],
                "draft": {"flow": index, "positions": [len(steps) - 2, len(steps) - 1]},
            }
    return {
        "decision": "abstain", "behavior": None,
        "reason": "표시된 입력만으로 구체적인 순서 조건을 제안할 근거가 부족합니다.",
        "evidence_flows": [0] if request["representative_flows"] else [], "draft": None,
    }


def checked_response(request, response):
    expected = {"decision", "behavior", "reason", "evidence_flows", "draft"}
    if not isinstance(response, dict) or set(response) != expected:
        raise ValueError("invalid review response fields")
    decision, behavior, reason = (response[key] for key in ("decision", "behavior", "reason"))
    if decision not in ("propose", "abstain") or not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 240:
        raise ValueError("invalid review decision")
    flows = request["representative_flows"]
    evidence = response["evidence_flows"]
    if (not isinstance(evidence, list)
            or any(type(index) is not int or not 0 <= index < len(flows) for index in evidence)
            or len(set(evidence)) != len(evidence)):
        raise ValueError("review evidence must reference representative flows")
    draft = response["draft"]
    labels = None
    if decision == "abstain":
        if behavior is not None or draft is not None:
            raise ValueError("abstention must not include a draft")
    else:
        if (not isinstance(behavior, str) or not 1 <= len(behavior.strip()) <= 120
                or not isinstance(draft, dict) or set(draft) != {"flow", "positions"}
                or type(draft["flow"]) is not int or draft["flow"] not in evidence):
            raise ValueError("proposal must reference its source flow")
        steps = flows[draft["flow"]]["steps"]
        positions = draft["positions"]
        if (not isinstance(positions, list) or not 2 <= len(positions) <= 8
                or any(type(i) is not int or not 0 <= i < len(steps) for i in positions)
                or positions != list(range(positions[0], positions[0] + len(positions)))):
            raise ValueError("draft steps must be contiguous positions in the observed flow")
        labels = [steps[i] for i in positions]
        if any(step == UNKNOWN or step.endswith(OMITTED_ARGUMENTS) for step in labels):
            raise ValueError("draft must not generalize omitted arguments or unknown input")
    return {
        "decision": decision,
        "behavior": behavior,
        "reason": reason.strip(),
        "evidence": [{"flow_number": index + 1, "sessions": flows[index]["sessions"],
                      "distinct_ip_count": flows[index]["distinct_ip_count"]} for index in evidence],
        "draft_steps": labels,
    }


def review(group, provider=demo_provider):
    request = build_request(group)
    return checked_response(request, provider(deepcopy(request)))
