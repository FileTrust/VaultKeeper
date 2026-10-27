"""Require existing signed ABI, bytecode, proof dimensions and wiring bindings."""
import sys
from web3 import Web3

def validate(app,home,cfg,candidate,payload):
    sys.path.insert(0,str(app/'core'))
    from node import release_manifest
    from network import check_network
    from vk_http import session
    proposed={**cfg,**candidate['fields']}
    check_network(Web3(Web3.HTTPProvider(proposed['rpc_url'],request_kwargs={'timeout':30},session=session())),proposed,release_manifest(home),payload)
