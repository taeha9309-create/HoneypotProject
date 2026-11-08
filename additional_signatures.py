"""Additional low-specificity behavior observations; never executes commands."""
import re

from decode_pipelines import command_parts, argv_for, standard_name

DETECTORS = {'local_account_read', 'shell_entry', 'directory_listing'}


def positional(args, short_options):
    files, options = [], True
    for arg in args:
        if options and arg == '--':
            options = False
        elif options and arg.startswith('-'):
            if not re.fullmatch('-[' + short_options + ']+', arg):
                return None
        elif not arg or any(c in arg for c in '$`*?[]'):
            return None
        else:
            files.append(arg)
    return files


def observe_additional(text, strip_assignments):
    parts = command_parts(text)
    if parts is None:
        return set()
    # Incomplete operator chains cannot prove a command invocation.
    meaningful = [p for p in parts if p.text.strip()]
    if not meaningful or meaningful[-1].separator in ('|', '&&', '||'):
        return set()
    tags = set()
    for part in parts:
        argv = argv_for(part, strip_assignments)
        if not argv:
            continue
        name, args = standard_name(argv[0]), argv[1:]
        if name == 'cat':
            files = positional(args, 'AbEenstTuv')
            if files and '/etc/passwd' in files:
                tags.add('local_account_read')
        elif name == 'getent' and args == ['passwd']:
            tags.add('local_account_read')
        elif name in ('sh', 'bash', 'ash', 'dash'):
            # No script or -c payload inference; only explicit stdin/interactive entry.
            if not args or (len(args) == 1 and args[0] in ('-i', '-l', '-il', '-li', '--')):
                tags.add('shell_entry')
        elif name == 'ls':
            files = positional(args, 'aAlhRdF1rtS')
            if files is not None:
                tags.add('directory_listing')
    return tags
