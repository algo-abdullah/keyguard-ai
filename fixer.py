#!/usr/bin/env python3
"""Stage 3: patch generation and verification for KeyGuard.

This module asks the local LLM for an environment-variable refactor,
replaces the secret value deterministically in the flagged line, verifies the
result, and applies the fix only after all checks pass.
"""

import argparse
import difflib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from llm import judge, fix as llm_fix
from scanner import scan_path

SESSION_FINDINGS: Dict[str, Dict[str, Any]] = {}


def mask_secret(value: str) -> str:
    if not value:
        return "****"
    if len(value) <= 4:
        return "****"
    return f"{value[:4]}****"


def _read_text(path: str) -> str:
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return ""


def _sanitize_env_var(env_var: str) -> Optional[str]:
    if not isinstance(env_var, str):
        return None
    cleaned = re.sub(r"[^A-Z0-9_]", "_", env_var.upper()).strip("_")
    if not cleaned:
        return None
    if not re.match(r"^[A-Z][A-Z0-9_]*$", cleaned):
        return None
    return cleaned


def _derive_env_name(finding: Dict[str, Any]) -> str:
    snippet = str(finding.get("snippet", "")).strip()
    name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*[\"']?", snippet)
    base_name = name_match.group(1) if name_match else "SECRET"
    cleaned = re.sub(r"[^A-Z0-9_]", "_", base_name.upper()).strip("_")
    cleaned = cleaned or "SECRET"
    if cleaned in {"API", "KEY", "SECRET", "TOKEN", "PASSWORD", "AUTH"}:
        cleaned = "SECRET_VALUE"
    return cleaned


def _lang_for_file(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".json": "json",
        ".java": "java",
        ".php": "php",
        ".go": "go",
        ".rb": "ruby",
        ".sh": "bash",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".env": "dotenv",
        ".ini": "ini",
        ".toml": "toml",
    }
    return mapping.get(ext, "text")


def _build_env_expression(language: str, env_var: str) -> Optional[str]:
    if language == "python":
        return f'os.environ["{env_var}"]'
    if language in {"javascript", "typescript"}:
        return f"process.env.{env_var}"
    if language == "java":
        return f'System.getenv("{env_var}")'
    return None


def _ensure_python_import_os(file_text: str) -> str:
    if "import os" in file_text:
        return file_text
    lines = file_text.splitlines(True)
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    else:
        insert_at = 0
    lines.insert(insert_at, "import os\n")
    return "".join(lines)


def _replace_secret_in_line(line: str, raw_secret: str, env_expression: str) -> str:
    if not raw_secret:
        return line
    # If the secret appears as a quoted string, replace the entire quoted literal
    # so we don't end up with quotes around the env expression (which causes
    # syntax errors, e.g. "os.environ["VAR"]").
    for q in ('"', "'"):
        quoted = q + raw_secret + q
        if quoted in line:
            return line.replace(quoted, env_expression, 1)

    # Fallback: replace the raw substring if present
    if raw_secret in line:
        return line.replace(raw_secret, env_expression, 1)

    # Last resort: use regex substitution for any remaining occurrence
    pattern = re.compile(re.escape(raw_secret))
    return pattern.sub(env_expression, line, count=1)


def _register_finding(finding: Dict[str, Any]) -> str:
    finding_id = str(finding.get("id") or finding.get("file", "") + ":" + str(finding.get("line", "")))
    SESSION_FINDINGS[finding_id] = finding
    return finding_id


def generate_fix(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a verified fix for a single finding without exposing the raw secret."""
    raw_secret = str(finding.get("_raw") or "")
    if not raw_secret:
        return {"status": "error", "reason": "missing raw secret", "patched_snippet": "", "env_var_name": "", "verification": {}}

    file_path = str(finding.get("file") or "")
    original_text = _read_text(file_path)
    if not original_text:
        return {"status": "error", "reason": "file not readable", "patched_snippet": "", "env_var_name": "", "verification": {}}

    llm_result = llm_fix(finding)
    env_var = _sanitize_env_var(llm_result.get("env_var_name")) or _derive_env_name(finding)
    language = _lang_for_file(file_path)
    expression = _build_env_expression(language, env_var)
    if expression is None:
        return {
            "status": "unsupported",
            "reason": f"unsupported language: {language}",
            "patched_snippet": "",
            "env_var_name": env_var,
            "verification": {"secret_removed": {"name": "secret_removed", "passed": False, "detail": "unsupported language"}},
        }

    lines = original_text.splitlines(True)
    target_line_index = max(0, int(finding.get("line", 1)) - 1)
    if target_line_index >= len(lines):
        target_line_index = len(lines) - 1

    target_line = lines[target_line_index]
    patched_line = _replace_secret_in_line(target_line, raw_secret, expression)
    lines[target_line_index] = patched_line
    patched_text = "".join(lines)

    if language == "python":
        patched_text = _ensure_python_import_os(patched_text)

    verification = verify(original_text, patched_text, raw_secret, env_var)
    all_passed = all(check.get("passed", False) for check in verification.values())

    diff_text = build_outputs(original_text, patched_text, raw_secret, env_var).get("diff", "")
    result = {
        "status": "ok" if all_passed else "failed",
        "reason": "verification passed" if all_passed else "verification failed",
        "patched_snippet": patched_line,
        "env_var_name": env_var,
        "patched_file_text": patched_text,
        "verification": verification,
        "diff": diff_text,
    }
    return result


def verify(original_file_text: str, patched_file_text: str, raw_secret: str, env_var: str) -> Dict[str, Dict[str, Any]]:
    """Return a check map with name, passed, and detail for each verification rule."""
    checks: Dict[str, Dict[str, Any]] = {}

    secret_removed = raw_secret not in patched_file_text
    checks["secret_removed"] = {
        "name": "secret_removed",
        "passed": secret_removed,
        "detail": "secret value absent from patched file" if secret_removed else f"patched file still contains {mask_secret(raw_secret)}",
    }

    env_present = env_var in patched_file_text
    checks["env_var_present"] = {
        "name": "env_var_present",
        "passed": env_present,
        "detail": f"env var {env_var} found in patched file" if env_present else f"env var {env_var} missing from patched file",
    }

    original_lines = original_file_text.splitlines()
    patched_lines = patched_file_text.splitlines()
    matcher = difflib.SequenceMatcher(None, original_lines, patched_lines)
    diff_count = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        diff_count += max(i2 - i1, j2 - j1)
    minimal_ok = diff_count <= 3
    checks["minimal_change"] = {
        "name": "minimal_change",
        "passed": minimal_ok,
        "detail": f"{diff_count} changed lines; limit is 3" if not minimal_ok else "patch stayed within 3 changed lines",
    }

    syntax_lang = "python" if "import os" in patched_file_text or "os.environ" in patched_file_text else "text"
    syntax_pass = True
    syntax_detail = "not checked"
    try:
        if "os.environ" in patched_file_text:
            compile(patched_file_text, "<patched>", "exec")
            syntax_detail = "Python syntax valid"
        elif "System.getenv" in patched_file_text or "process.env" in patched_file_text:
            syntax_detail = "not checked"
        else:
            syntax_detail = "not checked"
    except SyntaxError as exc:
        syntax_pass = False
        syntax_detail = f"Python syntax error: {exc.msg}"

    if "os.environ" in patched_file_text:
        syntax_pass = syntax_pass
    elif "System.getenv" in patched_file_text or "process.env" in patched_file_text:
        syntax_pass = True
        syntax_detail = "not checked"

    if "\"stripe_key\"" in patched_file_text or "'stripe_key'" in patched_file_text:
        try:
            json.loads(patched_file_text)
        except json.JSONDecodeError:
            syntax_pass = False
            syntax_detail = "JSON parse failed"

    checks["syntax_ok"] = {
        "name": "syntax_ok",
        "passed": syntax_pass,
        "detail": syntax_detail,
    }

    return checks


def build_outputs(original_file_text: str, patched_file_text: str, raw_secret: str, env_var: str) -> Dict[str, str]:
    diff_lines = list(difflib.unified_diff(original_file_text.splitlines(), patched_file_text.splitlines(), n=3))
    diff_text = "\n".join(diff_lines)
    diff_text = diff_text.replace(raw_secret, mask_secret(raw_secret))
    return {
        "diff": diff_text,
        "env_example_line": f"{env_var}=changeme",
        "gitignore_line": ".env",
    }


def apply_fix(finding_id: str) -> Dict[str, Any]:
    """Apply a verified patch only after all checks pass."""
    finding = SESSION_FINDINGS.get(finding_id)
    if not finding:
        return {"status": "error", "reason": "finding not found"}

    result = generate_fix(finding)
    if result.get("status") != "ok":
        return {"status": "refused", "reason": result.get("reason", "verification failed")}

    checks = result.get("verification", {})
    if not all(check.get("passed", False) for check in checks.values()):
        return {"status": "refused", "reason": "verification failed", "checks": checks}

    file_path = Path(str(finding.get("file") or ""))
    if not file_path.exists():
        return {"status": "error", "reason": "file missing"}

    backup_path = file_path.parent / (file_path.name + ".bak")
    shutil.copy2(file_path, backup_path)

    patched_text = result.get("patched_file_text", "")
    file_path.write_text(patched_text, encoding="utf-8")

    env_example_path = file_path.parent / ".env.example"
    env_line = result.get("env_var_name", "") + "=changeme"
    if env_example_path.exists():
        existing = env_example_path.read_text(encoding="utf-8", errors="ignore")
        if env_line not in existing.splitlines():
            with env_example_path.open("a", encoding="utf-8") as handle:
                if existing and not existing.endswith("\n"):
                    handle.write("\n")
                handle.write(env_line + "\n")
    else:
        env_example_path.write_text(env_line + "\n", encoding="utf-8")

    gitignore_path = file_path.parent / ".gitignore"
    if gitignore_path.exists():
        gitignore_text = gitignore_path.read_text(encoding="utf-8", errors="ignore")
        if ".env" not in gitignore_text.splitlines():
            with gitignore_path.open("a", encoding="utf-8") as handle:
                if gitignore_text and not gitignore_text.endswith("\n"):
                    handle.write("\n")
                handle.write(".env\n")
    else:
        gitignore_path.write_text(".env\n", encoding="utf-8")

    return {
        "status": "applied",
        "file": str(file_path),
        "backup": str(backup_path),
        "env_example_line": env_line,
        "gitignore_updated": True,
        "checks": checks,
    }


def _cli_scan(path: str) -> None:
    findings = scan_path(path)
    for finding in findings:
        verdict = judge(finding)
        if verdict.get("is_real_secret") is not True:
            continue
        finding_id = _register_finding(finding)
        result = generate_fix(finding)
        print(f"==== {finding.get('file')}:{finding.get('line')} [{finding.get('kind')}] ====")
        print(result.get("diff", ""))
        print(json.dumps(result.get("verification", {}), indent=2))
        print(f"env_var={result.get('env_var_name')}")
        print(f"status={result.get('status')}")
        print(f"finding_id={finding_id}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and verify fixes for real secret findings.")
    parser.add_argument("path", nargs="?", default="demo_vulnerable", help="Folder to scan")
    args = parser.parse_args()
    _cli_scan(args.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
