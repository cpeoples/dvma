#!/usr/bin/env python3
"""DVMA capture listener.

A tiny, dependency-free HTTP (and optional HTTPS) server that logs every
request it receives - method, path, headers, and body - to stdout and to a
JSONL file. It exists so the *real* DVMA network modules (cleartext traffic,
accept-all trust, weak TLS, bypassable pinning, insecure WebView) have a local
endpoint to actually hit, and so a trainee can SEE the exfiltrated data on the
wire without needing mitmproxy running.

FOR AUTHORIZED TRAINING USE ONLY. This deliberately logs credentials-shaped
payloads that DVMA sends to it. Run it on your own machine on your own network.

Usage:
    # cleartext only, port 8080
    python3 automation/scripts/capture_listener.py

    # also serve HTTPS on 8443 with a self-signed cert (auto-generated)
    python3 automation/scripts/capture_listener.py --https 8443

Point the app at this host:
    # emulator: 10.0.2.2 already reaches the host loopback
    # physical device: pass your host LAN IP at build time, e.g.
    flutter run --dart-define=DVMA_CAPTURE_BASE=http://192.168.1.50:8080
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_LOG_LOCK = threading.Lock()
_LOG_PATH = Path("automation/artifacts/capture_flows.jsonl")


def _log(entry: dict) -> None:
    line = json.dumps(entry, ensure_ascii=False)
    with _LOG_LOCK:
        print(line, flush=True)
        _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _capture(self, method: str) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        entry = {
            "ts": _dt.datetime.now().isoformat(timespec="seconds"),
            "scheme": "https" if isinstance(self.connection, ssl.SSLSocket) else "http",
            "method": method,
            "path": self.path,
            "client": self.client_address[0],
            "headers": {k: v for k, v in self.headers.items()},
            "body": body,
        }
        _log(entry)
        payload = json.dumps({"ok": True, "captured": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # noqa: N802 (http.server uses do_<VERB> names)
    def do_GET(self):  # noqa: N802
        self._capture("GET")

    def do_POST(self):  # noqa: N802
        self._capture("POST")

    def do_PUT(self):  # noqa: N802
        self._capture("PUT")

    def log_message(self, *_args):  # silence default noisy logging
        pass


def _self_signed_cert() -> tuple[str, str]:
    """Generate a throwaway self-signed cert/key with openssl. Returns paths."""
    tmp = Path(tempfile.mkdtemp(prefix="dvma-cap-"))
    cert, key = tmp / "cert.pem", tmp / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "7",
            "-subj",
            "/CN=dvma-capture-listener",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return str(cert), str(key)


def _serve(port: int, https: bool) -> None:
    httpd = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    scheme = "http"
    if https:
        cert, key = _self_signed_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print(
        f"[dvma-capture] listening on {scheme}://0.0.0.0:{port}  " f"(flows -> {_LOG_PATH})",
        file=sys.stderr,
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dvma-capture] stopped", file=sys.stderr)


def _daemonize(log_path: str = "automation/artifacts/capture_listener.out") -> None:
    """Double-fork so the listener fully detaches from the launching shell
    (survives the parent process-group being reaped, which happens when a
    short-lived tool/CI shell exits on macOS)."""
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    devnull = os.open(os.devnull, os.O_RDWR)
    out = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(devnull, 0)
    os.dup2(out, 1)
    os.dup2(out, 2)


def main() -> int:
    ap = argparse.ArgumentParser(description="DVMA capture listener")
    ap.add_argument("--port", type=int, default=8080, help="cleartext HTTP port")
    ap.add_argument(
        "--https",
        type=int,
        metavar="PORT",
        default=0,
        help="also serve HTTPS on this port (self-signed)",
    )
    ap.add_argument(
        "--daemon",
        action="store_true",
        help="detach and run in the background (survives shell exit)",
    )
    args = ap.parse_args()

    if args.daemon:
        _daemonize()

    threads = [threading.Thread(target=_serve, args=(args.port, False), daemon=True)]
    if args.https:
        threads.append(threading.Thread(target=_serve, args=(args.https, True), daemon=True))
    for t in threads:
        t.start()
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
