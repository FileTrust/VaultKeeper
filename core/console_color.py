"""Standard ANSI colours for service output, without terminal dependencies."""
import os
import re

ANSI=re.compile(r'\x1b\[[0-9;]*m')


def paint(message):
    text=ANSI.sub('',str(message))
    if 'NO_COLOR' in os.environ or os.environ.get('VK_LOG_COLOR','').lower() in {'never','off','0','false'}:
        return text
    # Explicit levels win over words inside a diagnostic message.
    if '[FAIL]' in text or '[ERROR]' in text or text.startswith('Vaultkeeper stopped:'):
        color='31'
    elif '[WARN]' in text or '[WARNING]' in text or text.startswith('Uploads paused:') or 'Could not verify update information' in text:
        color='33'
    elif '[OK]' in text or text in {'Node registered on-chain','Proof parameters loaded; starting node'} or text.startswith('Vaultkeeper ready:'):
        color='32'
    elif re.search(r'\b(panic|fatal|failed|error|corrupt|denied)\b',text,re.I):
        color='31'
    else:
        return text  # Progress and informational messages remain plain.
    # Do not require isatty(): systemd captures output before journalctl displays it.
    return f'\x1b[{color}m{text}\x1b[0m'
