"""Race TCP addresses before sending any HTTP data (Happy Eyeballs fallback).

The OS address order is respected, with address families interleaved and the
next attempt started after 250 ms. TLS, HTTP and request retries stay with their
existing libraries. This module never changes global socket or DNS functions.
"""
import errno
import http.client
import selectors
import socket
import sys
import time
import urllib.request

FALLBACK_DELAY = 0.25


def _addresses(host, port):
    rows = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    unique = list(dict.fromkeys(rows))
    if not unique:
        raise OSError('No TCP addresses found')
    first = unique[0][0]
    preferred = [row for row in unique if row[0] == first]
    alternate = [row for row in unique if row[0] != first]
    result = []
    for index in range(max(len(preferred), len(alternate))):
        if index < len(preferred):result.append(preferred[index])
        if index < len(alternate):result.append(alternate[index])
    return result


def create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None, socket_options=None):
    host, port = address
    if timeout is socket._GLOBAL_DEFAULT_TIMEOUT:timeout = socket.getdefaulttimeout()
    addresses = _addresses(host.strip('[]'), port)
    deadline = None if timeout is None else time.monotonic() + timeout
    pending = set()
    last_error = OSError('Could not connect to any resolved address')
    next_attempt = time.monotonic()
    index = 0
    selector = selectors.DefaultSelector()
    winner = None
    try:
        while index < len(addresses) or pending:
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                raise socket.timeout('TCP connection timed out')
            if index < len(addresses) and (now >= next_attempt or not pending):
                family, kind, proto, _, sockaddr = addresses[index]
                index += 1
                sock = None
                try:
                    sock = socket.socket(family, kind, proto)
                    for option in socket_options or ():
                        sock.setsockopt(*option)
                    if source_address:sock.bind(source_address)
                    sock.setblocking(False)
                    result = sock.connect_ex(sockaddr)
                    if result in (0, errno.EISCONN):
                        winner = sock
                        break
                    if result not in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR):
                        raise OSError(result, 'TCP connection failed')
                    selector.register(sock, selectors.EVENT_WRITE)
                    pending.add(sock)
                    next_attempt = time.monotonic() + FALLBACK_DELAY
                except OSError as exc:
                    last_error = exc
                    if sock is not None:sock.close()
                    next_attempt = time.monotonic()
                except BaseException:
                    if sock is not None:sock.close()
                    raise
                continue
            wait = None if deadline is None else max(0, deadline - now)
            if index < len(addresses):
                delay = max(0, next_attempt - now)
                wait = delay if wait is None else min(wait, delay)
            for event, _ in selector.select(wait):
                sock = event.fileobj
                selector.unregister(sock);pending.remove(sock)
                try:result = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                except OSError as exc:
                    last_error = exc;sock.close();continue
                if result == 0:
                    winner = sock
                    break
                last_error = OSError(result, 'TCP connection failed')
                sock.close()
            if winner is not None:break
        if winner is None:raise last_error
        winner.settimeout(timeout)
        sys.audit('socket.create_connection', address)
        return winner
    except BaseException:
        if winner is not None:winner.close()
        raise
    finally:
        for sock in pending:sock.close()
        selector.close()


class _HTTPConnection(http.client.HTTPConnection):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self._create_connection=create_connection


class _HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self._create_connection=create_connection


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self,request):return self.do_open(_HTTPConnection,request)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self,request):
        return self.do_open(_HTTPSConnection,request,context=self._context)


def urlopen(request,timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
    """Standard urllib redirects, proxies and TLS with fast TCP fallback."""
    return urllib.request.build_opener(_HTTPHandler(),_HTTPSHandler()).open(request,timeout=timeout)
