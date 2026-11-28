"""Aggregate BusyBox input context without exporting commands, IPs, or session IDs."""
import re
from collections import Counter

PROBE = re.compile(r"(?:/bin/)?busybox ([A-Za-z][A-Za-z0-9_]{0,31})")
KNOWN_MARKERS = {"UNSTABLE", "HISILICON", "CM35goCW", "OWARI", "HolyFuck", "echo"}
MENU = {"enable", "linuxshell", "system", "shell", "sh"}


def context_class(command):
    if command is None:
        return "boundary"
    if command in MENU:
        return command
    return "busybox_single_token" if PROBE.fullmatch(command) else "other"


def summarize(records):
    """Records are (normalized sequence, IP, baseline rule IDs) triples."""
    total_by_ip = Counter(ip for _, ip, _ in records if ip)
    probe_sessions_by_ip = Counter()
    markers = Counter()
    previous = Counter()
    following = Counter()
    overlaps = Counter()
    sessions = uppercase_sessions = terminal_sessions = 0
    for sequence, ip, rules in records:
        probes = [(i, match[1]) for i, command in enumerate(sequence)
                  if (match := PROBE.fullmatch(command))]
        if not probes:
            continue
        sessions += 1
        uppercase_sessions += any(token.isupper() for _, token in probes)
        terminal_sessions += probes[-1][0] == len(sequence) - 1
        if ip:
            probe_sessions_by_ip[ip] += 1
        overlaps.update(rules)
        for i, token in probes:
            markers[token if token in KNOWN_MARKERS else "other_token"] += 1
            previous[context_class(sequence[i - 1] if i else None)] += 1
            following[context_class(sequence[i + 1] if i + 1 < len(sequence) else None)] += 1
    ips = set(probe_sessions_by_ip)
    return {
        "sessions": len(records),
        "single_token_busybox_sessions": sessions,
        "uppercase_token_diagnostic_sessions": uppercase_sessions,
        "terminal_probe_sessions": terminal_sessions,
        "marker_occurrences": dict(markers),
        "preceding_input_occurrences": dict(previous),
        "following_input_occurrences": dict(following),
        "baseline_rule_overlap_sessions": dict(overlaps),
        "probe_ips": len(ips),
        "probe_ips_with_other_command_sessions": sum(total_by_ip[ip] > probe_sessions_by_ip[ip] for ip in ips),
        "other_command_sessions_from_probe_ips": sum(total_by_ip[ip] - probe_sessions_by_ip[ip] for ip in ips),
    }
