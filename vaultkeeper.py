#!/usr/bin/env python3
"""Stable user entrypoint; internal modules live in core/."""
from pathlib import Path
import runpy,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'core'))
if __name__=='__main__':
    from ft_update_bootstrap import enter
    enter(ROOT)
    runpy.run_path(str(ROOT/'core/node.py'),run_name='__main__')
else:
    import node as implementation
    sys.modules[__name__]=implementation
    globals().update({name:getattr(implementation,name) for name in dir(implementation) if not name.startswith('__')})
