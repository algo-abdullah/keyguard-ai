#!/usr/bin/env python3
"""HTTP API for KeyGuard.

This is the user-facing server that serves the static UI, scans a directory,
judges findings via the local Ollama model, and applies verified fixes.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from fixer import generate_fix, verify, build_outputs, apply_fix
from llm import judge, MODEL_NAME
from scanner import scan_path

HOST = "127.0.0.1"
PORT = 8000
FINDINGS_STORE = {}


def _mask(value: str) -> str:
    if not value:
        return "****"
    if len(value) <= 4:
        return "****"
    return f"{value[:4]}****"


def _health_check():
    try:
        import urllib.request

        req = urllib.request.Request("http://127.0.0.1:11434/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8", "ignore"))
        models = payload.get("models", [])
        names = []
        for model in models:
            if isinstance(model, dict):
                name = model.get("name")
                if isinstance(name, str):
                    names.append(name)
        return {"ollama": True, "model": MODEL_NAME, "model_present": MODEL_NAME in names}
    except Exception:
        return {"ollama": False, "model": MODEL_NAME, "model_present": False}


class KeyGuardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
            try:
                with open(index_path, "r", encoding="utf-8") as handle:
                    content = handle.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content.encode("utf-8"))))
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            except FileNotFoundError:
                self.send_error(404, "index.html not found")
            return

        if parsed.path == "/api/health":
            payload = _health_check()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        self.send_error(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b"{}"

        try:
            payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        if parsed.path == "/api/scan":
            self._handle_scan(payload)
            return

        if parsed.path == "/api/fix":
            self._handle_fix(payload)
            return

        if parsed.path == "/api/apply":
            self._handle_apply(payload)
            return

        self.send_error(404, "Endpoint not found")

    def _handle_scan(self, payload):
        path = payload.get("path")
        if not isinstance(path, str):
            self._send_json(400, {"error": "Missing folder path."})
            return
        if not os.path.isdir(path):
            self._send_json(400, {"error": "Invalid path: directory does not exist."})
            return

        findings = scan_path(path)
        results = []
        for finding in findings:
            verdict = judge(finding)
            is_real = verdict.get("is_real_secret") is True
            source = verdict.get("verdict_source", "rule-based")
            if source == "rule-based":
                source_name = "rule"
            else:
                source_name = "llm"

            public_finding = {
                "id": finding.get("id"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "kind": finding.get("kind"),
                "masked_value": finding.get("masked_value"),
                "verdict": "REAL" if is_real else "FALSE POSITIVE",
                "source": source_name,
                "reason": verdict.get("reason", ""),
                "confidence": verdict.get("confidence", 0.0),
            }
            FINDINGS_STORE[finding.get("id")] = finding
            results.append(public_finding)

        self._send_json(200, {"findings": results})

    def _handle_fix(self, payload):
        finding_id = payload.get("finding_id")
        if not finding_id:
            self._send_json(400, {"error": "Missing finding_id."})
            return
        finding = FINDINGS_STORE.get(finding_id)
        if not finding:
            self._send_json(404, {"error": "Unknown finding id."})
            return
        verdict = judge(finding)
        if verdict.get("is_real_secret") is not True:
            self._send_json(400, {"error": "Only real findings may be fixed."})
            return

        result = generate_fix(finding)
        if result.get("status") == "unsupported":
            self._send_json(400, {"error": result.get("reason", "Unsupported language.")})
            return
        if result.get("status") in {"error", "failed"}:
            self._send_json(400, {"error": result.get("reason", "Fix failed.")})
            return

        checks = result.get("verification", {})
        checks_list = []
        for key in ["secret_removed", "env_var_present", "minimal_change", "syntax_ok"]:
            item = checks.get(key, {"name": key, "passed": False, "detail": "missing"})
            checks_list.append({"name": item.get("name", key), "passed": bool(item.get("passed", False)), "detail": item.get("detail", "")})

        self._send_json(200, {
            "status": result.get("status", "ok"),
            "env_var": result.get("env_var_name"),
            "diff": result.get("diff", ""),
            "checks": checks_list,
        })

    def _handle_apply(self, payload):
        finding_id = payload.get("finding_id")
        if not finding_id:
            self._send_json(400, {"error": "Missing finding_id."})
            return
        finding = FINDINGS_STORE.get(finding_id)
        if not finding:
            self._send_json(404, {"error": "Unknown finding id."})
            return

        result = generate_fix(finding)
        if result.get("status") not in {"ok", "failed"}:
            self._send_json(400, {"error": result.get("reason", "Fix unavailable.")})
            return
        checks = result.get("verification", {})
        if not all(check.get("passed", False) for check in checks.values()):
            self._send_json(400, {"error": "Refusing to apply unverified patch.", "checks": checks})
            return

        applied = apply_fix(finding_id)
        if applied.get("status") != "applied":
            self._send_json(400, {"error": applied.get("reason", "Apply failed.")})
            return

        self._send_json(200, {"status": "applied", "changes": applied})

    def _send_json(self, code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    print(f"Starting KeyGuard server at http://127.0.0.1:8000")
    print(f"Model: {MODEL_NAME}")
    server = ThreadingHTTPServer((HOST, PORT), KeyGuardHandler)
    server.serve_forever()
