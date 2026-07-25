#!/usr/bin/env python3
"""A minimal stand-in for Ollama, used only by the Linux Gateway CI test.

Why a stand-in rather than the real thing: the Gateway path we need to verify is
a *systemd* mechanism (write a drop-in, disable autostart, relocate the engine to
the shadow port, restore everything exactly on revert). None of that depends on
real inference. Installing Ollama in CI would add a large download, a GPU-less
runtime, and a moving external dependency to a test about unit files.

What it must do to be a faithful stand-in:

  * honor ``OLLAMA_HOST`` exactly as Ollama does, since relocating the engine by
    setting that variable through a drop-in is the entire thing under test; and
  * answer the two endpoints Saffev uses to recognize and health-check an engine
    (``/api/tags`` returning a ``models`` array, and ``/api/version``).

Anything else returns 404, so a test that accidentally depends on real inference
fails loudly instead of quietly passing.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

DEFAULT_HOST = "127.0.0.1:11434"


def bind_target() -> tuple[str, int]:
    """Resolve OLLAMA_HOST the way Ollama does: ``host:port``, either part optional."""
    raw = os.environ.get("OLLAMA_HOST", DEFAULT_HOST).strip()
    # Tolerate a scheme prefix, which Ollama also accepts.
    for prefix in ("http://", "https://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.rstrip("/")
    host, _, port = raw.partition(":")
    return (host or "127.0.0.1", int(port) if port else 11434)


class Handler(BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (name fixed by BaseHTTPRequestHandler)
        path = self.path.split("?", 1)[0]
        if path == "/api/tags":
            # The shape Saffev uses to identify an engine as Ollama.
            self._json(200, {"models": []})
        elif path == "/api/version":
            self._json(200, {"version": "0.0.0-ci-fake"})
        else:
            self._json(404, {"error": f"fake-ollama does not serve {path}"})

    def log_message(self, *args) -> None:
        # Keep the CI log readable; the assertions are what matter.
        pass


def main() -> int:
    host, port = bind_target()
    print(f"fake-ollama listening on {host}:{port}", flush=True)
    HTTPServer((host, port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
