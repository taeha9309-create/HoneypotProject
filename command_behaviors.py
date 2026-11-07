"""Conservative observations of literal shell commands; never executes input.

This is deliberately not a shell interpreter. Substitution and malformed quotes
are unsupported. Operators inside quoted arguments do not start commands.
"""
import re
import shlex

from decode_pipelines import decode_pipes
from behavior_extensions import extra_observations

DETECTORS = {"self_exe_read", "shell_script", "hex_file_write", "firewall_flush",
             "password_change", "decode_pipeline", "ssh_key_write",
             "file_write_probe", "binary_inspection"}


def without_assignments(fragment):
    """Remove literal NAME=value prefixes, preserving quoted command names.

    Shell assignments change the command environment, not the executable name.
    Quoting an assignment's name makes it a command word, so shlex tokens alone
    are insufficient: 'LC_ALL=C' passwd must not become passwd.
    """
    fragment = fragment.lstrip()
    while True:
        prefix = re.match(r'[A-Za-z_][A-Za-z0-9_]*=', fragment)
        if prefix is None:
            return fragment
        position, quote, escaped = prefix.end(), None, False
        while position < len(fragment):
            char = fragment[position]
            if escaped:
                escaped = False
            elif char == '\\' and quote != "'":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in "\"'":
                quote = char
            elif char.isspace():
                break
            position += 1
        fragment = fragment[position:].lstrip()


def literal_commands(text):
    """Yield (argv, stdout_file) for simple commands and compound fragments."""
    if not isinstance(text, str) or len(text) > 131072:
        return
    fragments, start, quote, escaped, redirect = [], 0, None, False, None
    for i, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            elif quote == '"' and (char == '`' or text[i:i + 2] == '$('):
                return
            continue
        if char in "\"'":
            quote = char
        elif char == '`' or text[i:i + 2] == '$(':
            return
        elif char == '#' and (i == 0 or text[i - 1].isspace()):
            # Skip comments, including script shebangs, without parsing their text.
            end = text.find('\n', i)
            if end == -1:
                text = text[:i]
                break
            # A comment-bearing line is unsupported; other input rows still work.
            return
        elif char in ';|&()\n':
            fragments.append((text[start:i], redirect))
            start, redirect = i + 1, None
        elif char == '>' and redirect is None:
            redirect = i - start
    if quote or escaped:
        return
    fragments.append((text[start:], redirect))
    for fragment, redirect in fragments:
        try:
            output = None
            if redirect is not None:
                head, tail = fragment[:redirect], fragment[redirect:]
                # Only literal stdout file writes; not fd duplication or stderr.
                if head and head[-1].isdigit():
                    continue
                suffix = shlex.split(tail.lstrip('>'))
                if not suffix or suffix[0].startswith('&'):
                    continue
                output = suffix[0]
                argv = shlex.split(without_assignments(head))
            else:
                argv = shlex.split(without_assignments(fragment))
        except ValueError:
            continue
        if not argv:
            continue
        if argv[0] in ('busybox', '/bin/busybox', '/usr/bin/busybox'):
            argv = argv[1:]
        if argv:
            yield argv, output


def executable_name(value):
    for prefix in ('/bin/', '/usr/bin/', '/sbin/', '/usr/sbin/'):
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


def password_change_command(name, args):
    """Supported password-changing invocations, not status/help queries.

    This observes attempts only. Stdin content and actual account changes are
    not inferred. Unknown option forms are left unsupported conservatively.
    """
    if name == 'passwd':
        remaining = list(args)
        if remaining and remaining[0] in ('-d', '--delete', '-e', '--expire'):
            remaining.pop(0)
        if remaining and remaining[0] == '--':
            remaining.pop(0)
        return (len(remaining) <= 1 and all(
            re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*\$?', value)
            for value in remaining))
    if name == 'chpasswd':
        return all(arg in ('-e', '--encrypted', '-m', '--md5') for arg in args)
    return False


def observe(text):
    """Return behavior tags, not maliciousness or execution-success verdicts."""
    tags = set()
    tags.update(extra_observations(text, without_assignments))
    if (isinstance(text, str) and 'base64' in text and '|' in text
            and decode_pipes(text, without_assignments)):
        tags.add('decode_pipeline')
    for argv, output in literal_commands(text):
        name, args = executable_name(argv[0]), argv[1:]
        if password_change_command(name, args):
            tags.add('password_change')
        if (name == 'cat' and '/proc/self/exe' in args
                and not {'--help', '--version'}.intersection(args)):
            tags.add('self_exe_read')
        if name in ('sh', 'bash', 'ash', 'dash'):
            index = 0
            while index < len(args) and args[index].startswith('-'):
                option = args[index]
                index += 1
                if option == '--':
                    break
                if (option.startswith('--') or not option[1:]
                        or any(c not in 'euxv' for c in option[1:])):
                    index = len(args)
                    break
            if (index < len(args) and args[index] != '-'
                    and not args[index].startswith(('$', '<', '>'))):
                tags.add('shell_script')
        if name in ('echo', 'printf') and output and output != '/dev/null':
            if not output.startswith(('$', '-')) and any(
                    re.search(r'(?:\\x[0-9a-fA-F]{2}){4,}', arg) for arg in args):
                tags.add('hex_file_write')
        if (name in ('iptables', 'ip6tables')
                and not {'-h', '--help', '-V', '--version'}.intersection(args) and any(
                arg in ('-F', '--flush') for arg in args)):
            tags.add('firewall_flush')
    return tags
