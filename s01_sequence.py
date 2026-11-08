"""Track literal download, chmod and execution targets in one session."""
import re
import shlex
from dataclasses import replace
from urllib.parse import urlsplit

from command_behaviors import executable_name, without_assignments
from decode_pipelines import command_parts


def literal_path(value):
    if not value or value.endswith('/') or re.search(r'[$~*?\[\]{}<>\\]', value):
        return None
    parts = value.split('/')
    if '..' in parts:
        return None
    path = '/'.join(part for part in parts if part and part != '.')
    return ('/' if value.startswith('/') else '') + path if path else None


def download_target(name, args, stdout):
    if name == 'wget':
        options = {'-O': 'local', '--output-document': 'local',
                   '-w': 'wait', '--wait': 'wait',
                   '-T': 'timeout', '--timeout': 'timeout',
                   '-t': 'tries', '--tries': 'tries'}
        flags = {'-q', '--quiet'}
    elif name == 'curl':
        options = {'-o': 'local', '--output': 'local'}
        flags = {'-f', '-s', '-S', '-L', '--fail', '--silent', '--show-error', '--location'}
    elif name == 'tftp':
        options = {'-l': 'local', '-r': 'remote'}
        flags = {'-g'}
    else:
        return None

    operands, values, seen = [], {}, set()
    args = iter(args)
    for arg in args:
        combined = re.fullmatch(r'-([fsSL]+)o(.*)', arg) if name == 'curl' else None
        if combined:
            seen.update('-' + flag for flag in combined[1])
            arg = '-o' + combined[2]
        if arg == '--':
            operands.extend(args)
            break
        option, equal, value = arg.partition('=')
        if arg[:2] in options and len(arg) > 2 and not arg.startswith('--'):
            option, equal, value = arg[:2], '=', arg[2:]
        if option in options:
            field = options[option]
            if field in values:
                return None
            value = value if equal else next(args, '')
            if not value:
                return None
            if field in ('wait', 'timeout', 'tries'):
                numeric = r'\d+' if field == 'tries' else r'\d+(?:\.\d+)?'
                if re.fullmatch(numeric, value) is None:
                    return None
            values[field] = value
        elif arg in flags:
            seen.add(arg)
        elif name == 'curl' and re.fullmatch(r'-[fsSLO]+', arg):
            seen.update('-' + flag for flag in arg[1:])
        elif arg.startswith('-'):
            return None
        else:
            operands.append(arg)
    if len(operands) != 1:
        return None

    output = values.get('local')
    if name == 'tftp':
        if '-g' not in seen or not values.get('remote') or not output:
            return None
    else:
        address = operands[0]
        if name == 'wget' and '://' not in address:
            # Limit shorthand to a literal host[:port]/path operand.
            if re.match(r'[A-Za-z0-9][A-Za-z0-9.-]*(?::\d+)?/[^/]', address) is None:
                return None
            address = 'http://' + address
        try:
            url = urlsplit(address)
            _ = url.port  # Validate the optional port as well as the URL syntax.
        except ValueError:
            return None
        if (url.scheme not in ('http', 'https', 'ftp') or not url.hostname
                or re.search(r'[$`\s]', url.netloc)):
            return None
        if name == 'curl' and '-O' in seen and output is not None:
            return None
        if output is None:
            output = url.path.rsplit('/', 1)[-1] if name == 'wget' or '-O' in seen else '-'
            if not output or (name == 'wget' and url.query):
                return None
    return literal_path(stdout if output == '-' else output)


def simple_command(part):
    try:
        text = without_assignments(part.text)
        words = shlex.split(text)
        output = None
        if part.redirected:
            # Accept a literal password here-string before a sudo command.
            # The anchored prefix prevents operators inside quoted arguments
            # from being mistaken for shell redirection.
            password = r'''(?:"[^"$`\\]*"|'[^']*'|[A-Za-z0-9_.:@/+\-]+)'''
            sudo_input = re.fullmatch(
                r'((?:/(?:usr/)?bin/)?sudo(?:\s+-(?:S|n))*\s+)<<<\s*'
                + password + r'\s+([^<>]+)', text.strip())
            if sudo_input:
                return shlex.split(sudo_input[1] + sudo_input[2]), None
            lexer = shlex.shlex(text, posix=True, punctuation_chars='<>')
            lexer.whitespace_split = True
            lexer.commenters = ''
            tokens = list(lexer)
            # Accept one literal stdout redirection at the end of the command.
            if (len(tokens) < 3 or tokens[-2] not in ('>', '>>')
                    or any(token in ('>', '>>', '<', '<<', '>&') for token in tokens[:-2])
                    or re.search(r'\d[<>]', part.text)):
                return [], None
            words, output = tokens[:-2], tokens[-1]
    except ValueError:
        return [], None
    if words and executable_name(words[0]) == 'busybox':
        words = words[1:]
    return words, output


def actions(text):
    parts = command_parts(text, allow_groups=True, allow_here_strings=True)
    if parts is None:
        # Unknown shell input may change the working directory.
        yield 'cd', None
        return
    group = None
    closed = False
    previous_separator = None
    for part in parts:
        words, stdout = simple_command(part)
        if closed:
            if part.text.strip() and not part.text.lstrip().startswith('>'):
                return
            redirect = None
            if part.text.strip():
                _, redirect = simple_command(replace(part, text='group ' + part.text))
                if redirect is None:
                    return
            targets = {download_target(name, args, output or redirect)
                       for name, args, output in group}
            if len(targets) == 1:
                yield 'download', targets.pop()
            group, closed = None, False
            previous_separator = part.separator
            continue
        if part.separator == '(':
            if words or group is not None:
                return
            group = []
            continue
        if group is not None:
            if not words:
                return
            group.append((executable_name(words[0]), words[1:], stdout))
            if part.separator != ')':
                if part.separator != '||':
                    return
                continue
            closed = True
            continue
        if part.separator == ')':
            return
        if (words and executable_name(words[0]) == 'cd'
                and (previous_separator in ('&&', '||', '|', '&')
                     or part.separator in ('||', '|', '&'))):
            yield 'cd', None
        else:
            yield from command_actions(words, stdout)
        previous_separator = part.separator


def command_actions(words, stdout):
    if not words:
        return
    executable, *args = words
    name = executable_name(executable)
    if name == 'sudo':
        while args and args[0] in ('-S', '-n'):
            args = args[1:]
        if args and args[0] == '--':
            args = args[1:]
        if not args or args[0].startswith('-'):
            return
        executable, *args = args
        name = executable_name(executable)
        if name == 'cd':
            return
    if name == 'cd':
        if args and args[0] == '--':
            args = args[1:]
        directory = None
        if len(args) == 1 and not args[0].startswith('-'):
            value = args[0].rstrip('/') or '/'
            directory = '/' if value == '/' else literal_path(value)
        yield 'cd', directory
    elif name == 'chmod' and args and re.fullmatch(r'(?:[ugoa]*\+x|[0-7]{0,1}[0-7][0-7][0-7])', args[0]):
        mode, *targets = args
        if mode.endswith('+x') or any(int(digit) & 1 for digit in mode[-3:]):
            for target in targets:
                yield 'chmod', literal_path(target)
    elif name in ('wget', 'curl', 'tftp'):
        yield 'download', download_target(name, args, stdout)
    elif name in ('sh', 'bash', 'ash', 'dash'):
        if args and not args[0].startswith('-'):
            yield 'run', literal_path(args[0])
    elif executable.startswith(('./', '/')):
        yield 'run', literal_path(executable)
