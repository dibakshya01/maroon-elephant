"""Local-host dashboard server. stdlib http.server + Server-Sent Events. Zero-dep.

Routes:
  GET  /                      -> the dashboard (static/index.html)
  GET  /static/<file>         -> static assets
  POST /api/scan              -> {targets[], crownJewels, subscanners} -> {runId}
  GET  /api/stream/<runId>    -> SSE stream of orchestrator events (ends on 'complete')
  GET  /api/rules             -> rule catalog
"""
from __future__ import annotations

import json
import os
import queue
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict

from .. import __version__
from ..orchestrator import Orchestrator

_STATIC = os.path.join(os.path.dirname(__file__), "static")
_RUNS: Dict[str, "queue.Queue"] = {}
_CT = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
       ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".json": "application/json"}

# Security (set in serve()): a per-process CSRF token + the Host values we answer to.
_TOKEN = ""
_ALLOWED_HOSTS: set = set()
_MAX_BODY = 2_000_000          # cap POST body size
_MAX_CONCURRENT_RUNS = 32      # cap in-flight runs (anti-DoS / leak)


def _run_scan(run_id: str, targets, crown_jewels, subscanners):
    q = _RUNS[run_id]
    try:
        orch = Orchestrator(crown_jewels=crown_jewels, with_subscanners=subscanners)
        orch.run(targets, on_event=lambda ev: q.put(ev))
    except Exception as e:
        q.put({"kind": "scan_error", "error": str(e)})
    finally:
        q.put({"kind": "_eof"})


class Handler(BaseHTTPRequestHandler):
    server_version = "MaroonElephant/%s" % __version__

    def log_message(self, *a):  # quiet
        pass

    # ---- helpers ----
    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip()
        return host in _ALLOWED_HOSTS if _ALLOWED_HOSTS else True

    def _static(self, path):
        if path in ("", "/"):
            path = "/index.html"
        rel = path[len("/static/"):] if path.startswith("/static/") else path.lstrip("/")
        full = os.path.normpath(os.path.join(_STATIC, rel))
        if not (full == _STATIC or full.startswith(_STATIC + os.sep)) or not os.path.isfile(full):
            return self._send(404, b"not found")
        with open(full, "rb") as fh:
            body = fh.read()
        ext = os.path.splitext(full)[1]
        if os.path.basename(full) == "index.html":   # inject the CSRF token
            body = body.replace(b"__ME_CSRF__", _TOKEN.encode())
        self._send(200, body, _CT.get(ext, "application/octet-stream"))

    # ---- routing ----
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/" or path == "/index.html":
            return self._static("/index.html")
        if path.startswith("/static/"):
            return self._static(path)
        if path == "/api/rules":
            from ..analyzer import _load_rules
            rules = [{"id": r["id"], "title": r["title"], "severity": r.get("severity"),
                      "primary": r.get("primary")} for r in _load_rules()]
            return self._send(200, json.dumps(rules).encode(), "application/json")
        if path.startswith("/api/stream/"):
            return self._stream(path.rsplit("/", 1)[-1])
        return self._send(404, b"not found")

    def do_POST(self):
        if self.path != "/api/scan":
            return self._send(404, b"not found")
        # DNS-rebinding + CSRF + content-type + body-size defenses for the local server.
        if not self._host_ok():
            return self._send(403, b"bad host")
        if _TOKEN and self.headers.get("X-Maroon-Token") != _TOKEN:
            return self._send(403, json.dumps({"error": "missing/invalid CSRF token"}).encode(), "application/json")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype != "application/json":
            return self._send(415, json.dumps({"error": "Content-Type must be application/json"}).encode(), "application/json")
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0 or length > _MAX_BODY:
            return self._send(413, json.dumps({"error": "body too large or empty"}).encode(), "application/json")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, b"bad json")
        targets = [t.strip() for t in (data.get("targets") or []) if t.strip()]
        if not targets:
            return self._send(400, json.dumps({"error": "no targets"}).encode(), "application/json")
        # bound in-flight runs; prune finished/abandoned ones first
        if len(_RUNS) >= _MAX_CONCURRENT_RUNS:
            for k in list(_RUNS)[:len(_RUNS) - _MAX_CONCURRENT_RUNS + 1]:
                _RUNS.pop(k, None)
        run_id = uuid.uuid4().hex[:12]
        _RUNS[run_id] = queue.Queue()
        threading.Thread(target=_run_scan, args=(
            run_id, targets, data.get("crownJewels", ""), bool(data.get("subscanners", True)),
        ), daemon=True).start()
        self._send(200, json.dumps({"runId": run_id}).encode(), "application/json")

    def _stream(self, run_id):
        if not self._host_ok():
            return self._send(403, b"bad host")
        q = _RUNS.get(run_id)
        if q is None:
            return self._send(404, b"unknown run")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                ev = q.get()
                if ev.get("kind") == "_eof":
                    self.wfile.write(b"event: eof\ndata: {}\n\n")
                    self.wfile.flush()
                    break
                self.wfile.write(("data: %s\n\n" % json.dumps(ev)).encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            _RUNS.pop(run_id, None)


def serve(host: str = "127.0.0.1", port: int = 7879, open_browser: bool = True) -> int:
    global _TOKEN, _ALLOWED_HOSTS
    import secrets
    _TOKEN = secrets.token_urlsafe(24)
    _ALLOWED_HOSTS = {"%s:%d" % (host, port), "127.0.0.1:%d" % port, "localhost:%d" % port}
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = "http://%s:%d" % (host, port)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("⚠ binding to a non-loopback host (%s) exposes the dashboard with no auth — "
              "only do this on a trusted network." % host)
    print("🐘 Maroon Elephant dashboard: %s   (Ctrl-C to stop)" % url)
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0
