# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""A small threaded TCP proxy used to simulate a database outage.

``stop()`` closes the listener and every open connection, as a database
restart would; ``start()`` listens again on the same port.
"""

from __future__ import annotations

import contextlib
import socket
import threading


class TcpProxy:
    def __init__(self, upstream_host: str, upstream_port: int) -> None:
        self.upstream = (upstream_host, upstream_port)
        self.port = 0
        self._listener: socket.socket | None = None
        self._conns: list[socket.socket] = []
        self._lock = threading.Lock()

    def start(self) -> None:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen()
        self.port = listener.getsockname()[1]
        self._listener = listener
        threading.Thread(target=self._accept, args=(listener,), daemon=True).start()

    def stop(self) -> None:
        with self._lock:
            if self._listener is not None:
                # On Linux close() alone does not wake the thread blocked in
                # accept(), which would keep accepting on the old socket and
                # the outage would never happen; shutdown() makes it return.
                with contextlib.suppress(OSError):
                    self._listener.shutdown(socket.SHUT_RDWR)
                self._listener.close()
                self._listener = None
            for conn in self._conns:
                with contextlib.suppress(OSError):
                    conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            self._conns.clear()

    def _accept(self, listener: socket.socket) -> None:
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            try:
                server = socket.create_connection(self.upstream, timeout=5)
            except OSError:
                client.close()
                continue
            server.settimeout(None)
            with self._lock:
                self._conns += [client, server]
            for src, dst in ((client, server), (server, client)):
                threading.Thread(target=self._pump, args=(src, dst), daemon=True).start()

    @staticmethod
    def _pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            # shutdown() as in stop(): close() alone would neither wake the
            # pump blocked in recv() on the other direction nor send the FIN
            # the peer is waiting for.
            for s in (src, dst):
                with contextlib.suppress(OSError):
                    s.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(OSError):
                    s.close()
