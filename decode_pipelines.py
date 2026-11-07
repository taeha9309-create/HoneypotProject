"""Recognize direct decoder-to-interpreter pipes without running shell input.

Only a limited literal shell subset is accepted. Substitutions, subshells,
here-documents and redirected candidate commands are deliberately unsupported,
apart from an optional trailing literal stderr sink to /dev/null.
"""
from dataclasses import dataclass
from functools import lru_cache
import re
import shlex


@dataclass(frozen=True)
class CommandPart:
    start: int
    end: int
    text: str
    separator: str | None
    redirected: bool


@dataclass(frozen=True)
class DecodePipe:
    decoder_start: int
    decoder_end: int
    interpreter_start: int
    interpreter_end: int
    interpreter: str


def command_parts(text, *, allow_groups=False, allow_here_strings=False):
    """Return spans with their following operators, or None if unsupported.

    Operators in quoted strings or escaped characters are not separators.
    Different commands separated by ;, && or || never become a direct pipe.
    """
    if not isinstance(text, str) or len(text) > 131072:
        return None
    parts = []
    start, index, quote, escaped, redirected = 0, 0, None, False, False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == '\\' and quote != "'":
            if text[index + 1:index + 2] in ('\n', '\r'):
                return None
            escaped = True
            index += 1
            continue
        if quote:
            if char == quote:
                quote = None
            elif quote == '"' and (char == '`' or text[index:index + 2] == '$('):
                return None
            index += 1
            continue
        if char in "\"'":
            quote = char
        elif char == '`' or text[index:index + 2] == '$(' or (char in '()' and not allow_groups):
            return None
        elif char == '#' and (index == 0 or text[index - 1].isspace()
                              or text[index - 1] in ';|&'):
            # A comment can follow a complete command or a pending pipe.
            pending = parts and parts[-1].separator == '|' and not text[start:index].strip()
            if not pending:
                parts.append(CommandPart(start, index, text[start:index], '\n', redirected))
            newline = text.find('\n', index)
            if newline == -1:
                start = index = len(text)
            else:
                start = index = newline + 1
            redirected = False
            continue
        elif char in '<>':
            if text[index:index + 3] == '<<<' and allow_here_strings:
                redirected = True
                index += 3
                continue
            if text[index:index + 2] == '<<':
                return None
            redirected = True
        elif char in ';|&\n()':
            pair = text[index:index + 2]
            if pair == '|&':
                return None
            separator = pair if pair in ('&&', '||') else char
            # A newline immediately following | continues the same pipeline.
            pending = char == '\n' and parts and parts[-1].separator == '|' and not text[start:index].strip()
            if not pending:
                parts.append(CommandPart(start, index, text[start:index], separator, redirected))
            index += len(separator)
            start, redirected = index, False
            continue
        index += 1
    if quote or escaped:
        return None
    parts.append(CommandPart(start, len(text), text[start:], None, redirected))
    return parts


def standard_name(value):
    for prefix in ('/bin/', '/usr/bin/', '/sbin/', '/usr/sbin/'):
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


def argv_for(part, strip_assignments, *, allow_stderr_sink=False):
    text = part.text
    if part.redirected:
        if not allow_stderr_sink:
            return []
        # A trailing literal stderr sink leaves stdout and stdin connected.
        sink = re.search(r'\s+2(?:>>|>)\s*/dev/null\s*$', text)
        if sink is None:
            return []
        text = text[:sink.start()]
        head = command_parts(text)
        if head is None or len(head) != 1 or head[0].redirected:
            return []
    try:
        argv = shlex.split(strip_assignments(text))
    except ValueError:
        return []
    if argv and argv[0] in ('busybox', '/bin/busybox', '/usr/bin/busybox'):
        argv = argv[1:]
    return argv


def is_decoder(argv):
    if not argv or standard_name(argv[0]) != 'base64':
        return False
    decoding, options, files = False, True, 0
    for arg in argv[1:]:
        if options and arg == '--':
            options = False
        elif options and arg == '--decode':
            decoding = True
        elif options and arg in ('--ignore-garbage', '-i'):
            pass
        elif options and arg.startswith('-') and arg != '-':
            if len(arg) > 1 and set(arg[1:]) <= {'d', 'i'}:
                decoding = decoding or 'd' in arg[1:]
            else:
                return False
        else:
            if arg.startswith('$'):
                return False
            files += 1
    return decoding and files <= 1


def stdin_interpreter(argv):
    """Return the interpreter name only when program input comes from stdin."""
    if not argv:
        return None
    name = standard_name(argv[0])
    if name not in ('sh', 'bash', 'perl'):
        return None
    stdin_option = False
    args = argv[1:]
    for index, arg in enumerate(args):
        if arg == '--':
            return name if index == len(args) - 1 or stdin_option else None
        if arg == '-':
            return name
        if arg.startswith('-'):
            supported = {'w'} if name == 'perl' else set('euxvs')
            if len(arg) < 2 or not set(arg[1:]) <= supported:
                return None
            stdin_option = stdin_option or (name != 'perl' and 's' in arg[1:])
        else:
            return name if stdin_option else None
    return name


def decode_pipes(text, strip_assignments):
    """Return immutable evidence for adjacent decoder | stdin-interpreter pairs.

    Bound input before caching; the cache cannot retain oversized input rows.
    The pure string result contains no session or timestamp state.
    """
    if not isinstance(text, str) or len(text) > 131072:
        return ()
    return _decode_pipes(text, strip_assignments)


@lru_cache(maxsize=128)
def _decode_pipes(text, strip_assignments):
    parts = command_parts(text)
    if parts is None:
        return ()
    for index, part in enumerate(parts):
        if not part.text.strip():
            if (part.separator not in (None, '\n')
                    or (index and parts[index - 1].separator in ('|', '&&', '||'))):
                return ()
    matches = []
    for left, right in zip(parts, parts[1:]):
        if left.separator != '|':
            continue
        if not is_decoder(argv_for(left, strip_assignments, allow_stderr_sink=True)):
            continue
        interpreter = stdin_interpreter(argv_for(right, strip_assignments, allow_stderr_sink=True))
        if interpreter:
            matches.append(DecodePipe(left.start, left.end, right.start, right.end, interpreter))
    return tuple(matches)
