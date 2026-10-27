"""Convert operator input to VK's original integer byte allocation."""
from decimal import Decimal, InvalidOperation, localcontext
import re

UNITS={'b':1,'kb':1000,'mb':1000**2,'gb':1000**3,'tb':1000**4,
       'kib':1024,'mib':1024**2,'gib':1024**3,'tib':1024**4}


def parse_capacity(value, default_unit='gib'):
    text=str(value).strip()
    if len(text)>64:raise ValueError('Storage capacity input is too long')
    match=re.fullmatch(r'(\d+(?:\.\d+)?|\.\d+)\s*([a-zA-Z]*)',text)
    if not match:raise ValueError('Use a positive size, for example 200 MiB or 100 GiB')
    unit=match[2].lower() or default_unit
    if unit not in UNITS:raise ValueError('Use B, MB, GB, MiB or GiB units')
    try:
        with localcontext() as context:
            context.prec=100
            size=Decimal(match[1])*UNITS[unit]
    except InvalidOperation:raise ValueError('Invalid storage capacity') from None
    if not 1<=size<=2**63-1:raise ValueError('Storage capacity must be between 1 byte and 2^63-1 bytes')
    return int(size)
