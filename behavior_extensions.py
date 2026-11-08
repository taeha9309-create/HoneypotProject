"""Additional literal behavior observations, never shell execution.

These are behavior tags, not maliciousness or success verdicts. Command parts
and operators are retained so file probes cannot cross unrelated pipelines.
"""
from functools import lru_cache
import posixpath
import re
import shlex

from decode_pipelines import command_parts, argv_for, standard_name


def literal_path(value):
    if (not value or '..' in value.split('/') or any(c in value for c in '$`*?[]\n\r\x00')
            or value in ('/dev/null', '/dev/stdout', '/dev/stderr')):
        return None
    return posixpath.normpath(value)


def auth_keys_path(value):
    path = literal_path(value)
    return bool(path and any(path == '.ssh/' + name or path.endswith('/.ssh/' + name)
                             for name in ('authorized_keys', 'authorized_keys2')))


def stdout_write(text, strip_assignments):
    """Parse one simple stdout > or >> file, returning (argv, target)."""
    quote, escaped = None, False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == '\\' and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == '<':
            return None
        elif char == '>':
            if index and text[index - 1].isdigit():
                return None  # fd forms deliberately unsupported
            width = 2 if text[index:index + 2] == '>>' else 1
            try:
                target = shlex.split(text[index + width:])
                argv = shlex.split(strip_assignments(text[:index]))
            except ValueError:
                return None
            if len(target) != 1 or target[0].startswith('&'):
                return None
            if argv and argv[0] in ('busybox', '/bin/busybox', '/usr/bin/busybox'):
                argv = argv[1:]
            path = literal_path(target[0])
            return (argv, path) if path else None
    return None


def positional_args(args, switches):
    """Support only listed switches and --; decline unknown option syntax."""
    result, options = [], True
    for value in args:
        if options and value == '--':
            options = False
        elif options and value.startswith('-'):
            if value not in switches:
                return None
        else:
            result.append(value)
    return result


def key_file_writer(argv):
    if not argv:
        return False
    name = standard_name(argv[0])
    if name in ('cp', 'mv'):
        files = positional_args(argv[1:], {'-f', '-v', '-n', '-i', '-p', '-T'})
        return bool(files and len(files) == 2 and auth_keys_path(files[-1]))
    if name == 'tee':
        files = positional_args(argv[1:], {'-a', '--append'})
        return bool(files and any(auth_keys_path(p) for p in files))
    return False


def binary_locator(argv):
    if not argv:
        return False
    name = standard_name(argv[0])
    if name == 'which':
        programs = positional_args(argv[1:], {'-a', '--all'})
    elif name == 'command' and len(argv) > 2 and argv[1] in ('-v', '-V'):
        programs = positional_args(argv[2:], set())
    elif name == 'type' and len(argv) > 2 and argv[1] in ('-p', '-P'):
        programs = positional_args(argv[2:], set())
    else:
        return False
    return bool(programs and all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.+-]*', p) for p in programs))


def literal_binary_metadata(text, strip_assignments):
    """Recognize only a bounded, literal $(which PROGRAM) metadata template.

    This does not evaluate substitution, nor allow arbitrary nested shell code.
    Other substitutions remain unsupported by the general command parser.
    """
    raw = strip_assignments(text).strip()
    prefix = r'(?:/(?:usr/)?bin/)?'
    metadata = r'(?:' + prefix + r'ls\s+-([alh]+)|' + prefix + r'stat)'
    pattern = (metadata + r'\s+\$\(\s*' + prefix + r'which\s+'
               r'[A-Za-z_][A-Za-z0-9_.+-]*\s*\)\s*;?')
    found = re.fullmatch(pattern, raw)
    return bool(found and (found[1] is None or 'l' in found[1]))


def extra_observations(text, strip_assignments):
    if not isinstance(text, str) or len(text) > 131072:
        return frozenset()
    if not ('authorized_keys' in text or any(k in text for k in ('which', 'command', 'type'))
            or (any(k in text for k in ('echo', 'printf')) and 'cat' in text and 'rm' in text)):
        return frozenset()
    return _extra_observations(text, strip_assignments)


@lru_cache(maxsize=128)
def _extra_observations(text, strip_assignments):
    tags = set()
    if literal_binary_metadata(text, strip_assignments):
        tags.add('binary_inspection')
    parts = command_parts(text)
    if parts is None:
        return frozenset(tags)
    for index, part in enumerate(parts):
        if not part.text.strip() and (part.separator not in (None, '\n')
                or (index and parts[index - 1].separator in ('|', '&&', '||'))):
            return frozenset(tags)
    pending = {}
    previous_separator = None
    for part in parts:
        if previous_separator in ('|', '||', '&'):
            pending.clear()
        argv = argv_for(part, strip_assignments)
        write = stdout_write(part.text, strip_assignments) if part.redirected else None
        if write and auth_keys_path(write[1]):
            tags.add('ssh_key_write')
        if key_file_writer(argv):
            tags.add('ssh_key_write')
        if binary_locator(argv):
            tags.add('binary_inspection')
        name = standard_name(argv[0]) if argv else None
        if name == 'cd':
            pending.clear()  # Never bind relative files across a directory change.
        if (write and write[0] and standard_name(write[0][0]) in ('echo', 'printf')
                and not write[1].startswith('~')):
            pending[write[1]] = 1
        if name == 'cat':
            files = positional_args(argv[1:], set())
            if files and len(files) == 1:
                path = literal_path(files[0])
                if pending.get(path) == 1:
                    pending[path] = 2
        if name == 'rm':
            files = positional_args(argv[1:], {'-f'})
            if files and len(files) == 1:
                path = literal_path(files[0])
                if pending.get(path) == 2:
                    tags.add('file_write_probe')
                pending.pop(path, None)
        previous_separator = part.separator
    return frozenset(tags)
