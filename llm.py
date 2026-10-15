#!/usr/bin/env python3
"""Stage 2: local LLM integration for KeyGuard.

This module speaks to a local Ollama server, runs a tiny judge/fix loop,
and exposes a CLI for quick validation against the demo project.
"""

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from scanner import scan_path

MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5:3b")
OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
OLLAMA_TIMEOUT = 120

JUDGE_SYSTEM = (
    "You are a security code reviewer. You are given a code snippet and one flagged line. "
    "Decide whether the flagged value is a REAL hardcoded secret (a live credential, key or token) "
    "or a FALSE POSITIVE (placeholder like 'your-api-key-here', example, test value, UI label, hash, ID, "
    "config default, env var name). Reply ONLY with JSON: {\"is_real_secret\": true|false, \"confidence\": 0.0-1.0, \"reason\": \"one short sentence\"}."
)

JUDGE_EXAMPLES = (
    "Example real: 'API_KEY = \"AKIA_REDACTED\"' -> {\"is_real_secret\": true, \"confidence\": 0.99, \"reason\": \"Looks like a live AWS access key format.\"}\n"
    "Example false positive: 'password_label = \"password_label\"' -> {\"is_real_secret\": false, \"confidence\": 0.97, \"reason\": \"This is a UI label, not a credential.\"}"
)

FIX_SYSTEM = (
    "You refactor code to remove a hardcoded secret. Replace ONLY the flagged secret value with a read from an environment variable named by you in UPPER_SNAKE_CASE. "
    "Use os.environ[...] for Python, process.env.X for JS/TS, System.getenv for Java, getenv for PHP/Go equivalents. Keep everything else byte-for-byte identical, including indentation. "
    "Add the needed import only if missing in the snippet. Reply ONLY with JSON: {\"patched_snippet\": \"...\", \"env_var_name\": \"...\"}."
)

FIX_EXAMPLES = (
    "Example real: 'aws_key = \"AKIA_REDACTED\"' -> {\"patched_snippet\": \"aws_key = os.environ[\"AWS_KEY\"]\", \"env_var_name\": \"AWS_KEY\"}\n"
    "Example false positive: 'password_label = \"password_label\"' -> {\"patched_snippet\": \"password_label = \"password_label\"\", \"env_var_name\": \"PASSWORD_LABEL\"}"
)

KNOWN_REAL_KINDS = {
    "aws_access_key",
    "github_token",
    "stripe_key",
    "google_api_key",
    "slack_token",
    "private_key_header",
}

PLACEHOLDER_PATTERNS = (
    "placeholder",
    "change-me",
    "changeme",
    "your_",
    "your-",
    "xxxx",
    "todo",
)


def _mask_secret(value: str) -> str:
    if not value:
        return "****"
    if len(value) <= 4:
        return "****"
    return f"{value[:4]}****"


def _build_payload(messages: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "model": MODEL_NAME,
        "messages": messages,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0,
            "num_ctx": 2048,
            "num_predict": 300,
        },
    }


def _safe_json_extract(raw: str) -> Optional[Dict[str, Any]]:
    text = raw.strip()
    if not text:
        return None
    text = re.sub(r"```json\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"```\s*", "", text)

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    candidate = text[start : end + 1]

    try:
        obj = json.loads(candidate)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        return None
    return None


def _ensure_ollama_model() -> None:
    try:
        req = urllib.request.Request(
            "http://localhost:11434/api/tags",
            headers={"Content-Type": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", "ignore")
    except urllib.error.URLError as exc:
        raise RuntimeError('Ollama is not running. Run "ollama serve" or "ollama list".') from exc

    try:
        tags = json.loads(body)
    except json.JSONDecodeError:
        tags = {}

    models = []
    if isinstance(tags, dict):
        models = tags.get("models", [])
    found = False
    for entry in models:
        if isinstance(entry, dict):
            name = entry.get("name")
            if name == MODEL_NAME:
                found = True
                break
    if not found:
        raise RuntimeError(f'Model "{MODEL_NAME}" was not found. Run "ollama serve" or "ollama list".')


def _call_ollama(system_prompt: str, user_prompt: str, retry: bool = True) -> Dict[str, Any]:
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    payload = _build_payload(messages)
    request_data = json.dumps(payload).encode("utf-8")

    try:
        req = urllib.request.Request(
            OLLAMA_URL,
            data=request_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as response:
            body = response.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore")
        if exc.code == 404:
            raise RuntimeError(f'Model "{MODEL_NAME}" was not found. Run "ollama serve" or "ollama list".') from exc
        raise RuntimeError(f"Ollama HTTP {exc.code}: {detail[:200]}") from exc
    except urllib.error.URLError as exc:
        msg = str(exc)
        if "Connection refused" in msg or "timed out" in msg.lower():
            raise RuntimeError('Ollama is not running. Run "ollama serve" or "ollama list".') from exc
        raise RuntimeError(f"Ollama request failed: {msg}") from exc

    try:
        response_json = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Ollama returned invalid JSON.") from exc

    content = response_json.get("message", {}).get("content", "")
    if not isinstance(content, str):
        raise RuntimeError("Ollama response did not contain a string message.")

    if retry:
        parsed = _safe_json_extract(content)
        if parsed is None:
            stricter_prompt = user_prompt + "\nReturn valid JSON only, no commentary."
            return _call_ollama(system_prompt, stricter_prompt, retry=False)
    return {"content": content}


def _parse_judge_response(raw: str) -> Dict[str, Any]:
    parsed = _safe_json_extract(raw)
    if parsed is None:
        return {
            "is_real_secret": False,
            "confidence": 0.0,
            "reason": "LLM returned invalid JSON.",
            "error": True,
        }

    is_real = parsed.get("is_real_secret")
    confidence = parsed.get("confidence")
    reason = parsed.get("reason")
    if not isinstance(is_real, bool):
        return {"is_real_secret": False, "confidence": 0.0, "reason": "Invalid JSON schema.", "error": True}
    if not isinstance(confidence, (int, float)):
        return {"is_real_secret": is_real, "confidence": 0.0, "reason": "Invalid confidence value.", "error": True}
    if not isinstance(reason, str):
        return {"is_real_secret": is_real, "confidence": float(confidence), "reason": "Missing reason.", "error": True}

    confidence = float(confidence)
    if confidence < 0.0 or confidence > 1.0:
        confidence = max(0.0, min(1.0, confidence))

    return {
        "is_real_secret": is_real,
        "confidence": confidence,
        "reason": reason[:160],
    }


def _value_has_placeholder_marker(value: str) -> bool:
    text = (value or "").lower()
    if not text:
        return False
    text = text.replace("*", "")
    if re.search(r"(?i)akia[0-9a-z]{16}example", text):
        return False
    if re.search(r"(?i)\bexample\b", text):
        return True
    if re.search(r"(?i)(?:placeholder|change[-_]?me|your[_-]|xxxx|todo)", text):
        return True
    return False


def _looks_like_real_assignment(finding: Dict[str, Any]) -> bool:
    key_name = str(finding.get("kind", "")).lower()
    snippet = str(finding.get("snippet", "")).lower()
    value = str(finding.get("_raw") or finding.get("masked_value") or "").lower()
    if any(token in snippet for token in ("db_password", "password =", "api_key =", "secret =", "token =")):
        if "placeholder" not in value and "change-me" not in value and "example" not in value:
            return True
    if key_name == "generic_secret":
        if "password" in snippet or "secret" in snippet or "token" in snippet:
            if not _value_has_placeholder_marker(value):
                return True
    return False


def _reason_for_rule_based(kind: str, value: str) -> str:
    if kind == "aws_access_key":
        return "Known AWS access key format; this is a real credential pattern."
    if kind == "github_token":
        return "Known GitHub token format; this is a real token pattern."
    if kind == "stripe_key":
        return "Known Stripe key format; this is a real key pattern."
    if kind == "google_api_key":
        return "Known Google API key format; this is a real API key pattern."
    if kind == "slack_token":
        return "Known Slack token format; this is a real token pattern."
    if kind == "private_key_header":
        return "Private key header detected; this is a real private key marker."
    if _value_has_placeholder_marker(value):
        return "Placeholder text detected; this is not a real secret."
    return "Rule-based signal indicates this is a hardcoded secret."


def _llm_reason_only(system_prompt: str, user_prompt: str) -> str:
    try:
        response = _call_ollama(system_prompt, user_prompt)
        content = response.get("content", "")
        parsed = _safe_json_extract(content)
        if isinstance(parsed, dict):
            reason = parsed.get("reason")
            if isinstance(reason, str) and reason.strip():
                return reason.strip()[:160]
    except RuntimeError:
        pass
    return "LLM provided no usable reason."


def judge(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Use deterministic rules for high-confidence secrets and the LLM only for ambiguous cases."""
    try:
        _ensure_ollama_model()
    except RuntimeError as exc:
        return {
            "is_real_secret": False,
            "confidence": 0.0,
            "reason": str(exc),
            "error": True,
            "verdict_source": "rule-based",
        }

    kind = str(finding.get("kind", ""))
    raw_value = str(finding.get("_raw") or finding.get("masked_value") or "")
    snippet = str(finding.get("snippet", ""))

    if _looks_like_real_assignment(finding):
        return {
            "is_real_secret": True,
            "confidence": 1.0,
            "reason": "Strong assignment evidence indicates a real hardcoded secret.",
            "verdict_source": "rule-based",
        }

    if _value_has_placeholder_marker(raw_value) or _value_has_placeholder_marker(snippet):
        return {
            "is_real_secret": False,
            "confidence": 0.0,
            "reason": "Placeholder marker detected; this is not a real secret.",
            "verdict_source": "rule-based",
        }

    if kind in KNOWN_REAL_KINDS:
        reason_prompt = (
            "Generate one short sentence explaining why this matches a real secret format. "
            "Keep it to one sentence and no JSON.\n"
            f"Flagged kind: {kind}\nSnippet:\n{snippet[:2000]}"
        )
        reason = _llm_reason_only(JUDGE_SYSTEM, reason_prompt)
        return {
            "is_real_secret": True,
            "confidence": 1.0,
            "reason": reason,
            "verdict_source": "rule-based",
        }

    user_prompt = (
        f"Flagged kind: {kind}\n"
        f"Masked value: {finding.get('masked_value', '')}\n"
        f"Line number: {finding.get('line', '')}\n"
        f"Snippet:\n{snippet[:3000]}\n"
        f"{JUDGE_EXAMPLES}"
    )

    try:
        response = _call_ollama(JUDGE_SYSTEM, user_prompt)
        content = response.get("content", "")
        result = _parse_judge_response(content)
        result["verdict_source"] = "LLM-judged"
        return result
    except RuntimeError as exc:
        return {
            "is_real_secret": False,
            "confidence": 0.0,
            "reason": str(exc),
            "error": True,
            "verdict_source": "rule-based",
        }


def _parse_fix_response(raw: str) -> Dict[str, Any]:
    parsed = _safe_json_extract(raw)
    if parsed is None:
        return {
            "patched_snippet": "",
            "env_var_name": "",
            "error": "LLM returned invalid JSON.",
        }

    patched = parsed.get("patched_snippet")
    env_name = parsed.get("env_var_name")
    if not isinstance(patched, str) or not isinstance(env_name, str):
        return {
            "patched_snippet": "",
            "env_var_name": "",
            "error": "Invalid fix JSON schema.",
        }
    return {"patched_snippet": patched, "env_var_name": env_name}


def fix(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Ask the local LLM for a minimal environment-variable refactor."""
    try:
        _ensure_ollama_model()
    except RuntimeError as exc:
        return {"patched_snippet": "", "env_var_name": "", "error": str(exc)}

    snippet = str(finding.get("snippet", ""))
    kind = str(finding.get("kind", ""))
    masked = str(finding.get("masked_value", ""))
    user_prompt = (
        f"Flagged kind: {kind}\n"
        f"Masked value: {masked}\n"
        f"Snippet:\n{snippet[:3000]}\n"
        f"{FIX_EXAMPLES}"
    )

    try:
        response = _call_ollama(FIX_SYSTEM, user_prompt)
        content = response.get("content", "")
        return _parse_fix_response(content)
    except RuntimeError as exc:
        return {"patched_snippet": "", "env_var_name": "", "error": str(exc)}


def _scan_and_judge(path: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for finding in scan_path(path):
        verdict = judge(finding)
        verdict["id"] = finding.get("id")
        verdict["file"] = finding.get("file")
        verdict["line"] = finding.get("line")
        verdict["kind"] = finding.get("kind")
        verdict["masked_value"] = finding.get("masked_value")
        results.append(verdict)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a folder and ask Ollama to judge each finding.")
    parser.add_argument("path", nargs="?", default="demo_vulnerable", help="Folder to scan")
    args = parser.parse_args()

    print(f"KeyGuard LLM judge using model: {MODEL_NAME}")
    try:
        findings = _scan_and_judge(args.path)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")
        return 1

    if not findings:
        print("No findings found.")
        return 0

    for index, item in enumerate(findings, start=1):
        status = "REAL" if item.get("is_real_secret") else "FALSE POSITIVE"
        print(f"[{index}] {item.get('file')}:{item.get('line')} | {item.get('kind')} | {status} | conf={item.get('confidence', 0.0)} | {item.get('reason', 'no reason')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
