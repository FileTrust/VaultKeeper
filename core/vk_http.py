"""Per-session HTTP adapters using fast TCP fallback; no HTTP request replay."""
import socket
import sys

import requests
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError

from vk_connect import create_connection


class _FastConnection:
    def _new_conn(self):
        try:
            sock=create_connection((self._dns_host,self.port),self.timeout,
                                   self.source_address,self.socket_options)
        except socket.gaierror as exc:
            raise NameResolutionError(self.host,self,exc) from exc
        except socket.timeout as exc:
            raise ConnectTimeoutError(self,'TCP connection timed out') from exc
        except OSError as exc:
            raise NewConnectionError(self,'TCP connection failed') from exc
        sys.audit('http.client.connect',self,self.host,self.port)
        return sock


class _HTTPConnection(_FastConnection,HTTPConnection):pass
class _HTTPSConnection(_FastConnection,HTTPSConnection):pass
class _HTTPPool(HTTPConnectionPool):ConnectionCls=_HTTPConnection
class _HTTPSPool(HTTPSConnectionPool):ConnectionCls=_HTTPSConnection


def _configure(manager):
    # Never modify urllib3's process-wide scheme map.
    manager.pool_classes_by_scheme={**manager.pool_classes_by_scheme,
                                    'http':_HTTPPool,'https':_HTTPSPool}
    return manager


class FastFallbackAdapter(HTTPAdapter):
    def init_poolmanager(self,connections,maxsize,block=False,**kwargs):
        self._pool_connections=connections;self._pool_maxsize=maxsize;self._pool_block=block
        self.poolmanager=_configure(PoolManager(num_pools=connections,maxsize=maxsize,block=block,**kwargs))

    def proxy_manager_for(self,proxy,**kwargs):
        manager=super().proxy_manager_for(proxy,**kwargs)
        # SOCKS connections have their own transport implementation.
        return manager if proxy.lower().startswith('socks') else _configure(manager)


def session():
    result=requests.Session()
    adapter=FastFallbackAdapter(pool_connections=8,pool_maxsize=16,max_retries=0,pool_block=True)
    result.mount('http://',adapter);result.mount('https://',adapter)
    return result
