#!/usr/bin/env python3
"""Stage 1: local secret scanning for KeyGuard.

This module walks a directory tree, looks for likely hardcoded secrets,
and returns a short list of findings with masked values.
"""

import argparse
import json
import math
import os
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

SKIP_DIRS = {
    ".git",
    "node_modules",
    "venv",
    "__pycache__",
    "dist",
    "build",
}

TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".env",
    ".json",
    ".yml",
    ".yaml",
    ".java",
    ".php",
    ".go",
    ".rb",
    ".sh",
    ".txt",
    ".ini",
    ".cfg",
    ".toml",
}

KNOWN_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]+")),
    ("stripe_key", re.compile(r"sk_live_[A-Za-z0-9_]+")),
    ("private_key_header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

GENERIC_SECRET_RE = re.compile(
    r"(?i)([A-Za-z0-9_]*(?:api[_-]?key|secret|token|passwd|password|auth)[A-Za-z0-9_]*)\s*[:=]\s*[\"']([^\"']{8,})[\"']",
)

QUOTED_VALUE_RE = re.compile(r"(?P<quote>[\"'])(?P<value>[^\"'\n]{20,}?)(?P=quote)")

SEVERITY_ORDER = {
    "aws_access_key": 40,
    "github_token": 40,
    "google_api_key": 40,
    "slack_token": 40,
    "stripe_key": 40,
    "private_key_header": 40,
    "generic_secret": 20,
    "entropy_string": 10,
}


def is_probably_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return True
    sample = data[:1024]
    if not sample:
        return False
    text_chars = bytes(range(32, 127)) + b"\n\r\t\b\f"
    if len(sample) < 1024:
        return False
    non_text = sum(1 for b in sample if b not in text_chars)
    return non_text / len(sample) > 0.30


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def is_url_or_file_like(value: str) -> bool:
    v = value.strip().lower()
    if v.startswith(("http://", "https://", "ws://", "wss://", "/", "./", "../", "~/")):
        return True
    if re.match(r"^[a-z]:\\", v):
        return True
    return False


def mask_secret(value: str) -> str:
    if not value:
        return "****"
    if len(value) <= 4:
        return "****"
    return f"{value[:4]}****"


def detect_known_secret(line: str) -> Optional[Tuple[str, str, str]]:
    for kind, pattern in KNOWN_PATTERNS:
        match = pattern.search(line)
        if match:
            return kind, match.group(0), match.group(0)
    match = GENERIC_SECRET_RE.search(line)
    if match:
        name = match.group(1)
        raw_value = match.group(2)
        if is_likely_false_positive_name(name, raw_value):
            return None
        return "generic_secret", raw_value, raw_value
    return None


def walk_files(root: str) -> Iterable[str]:
    root_path = os.path.abspath(root)
    if not os.path.isdir(root_path):
        raise FileNotFoundError(f"Path not found: {root_path}")

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
        dirnames[:] = [
            d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")
        ]
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            if not os.path.isfile(file_path):
                continue
            try:
                if os.path.getsize(file_path) > 200 * 1024:
                    continue
            except OSError:
                continue

            ext = os.path.splitext(filename)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue

            try:
                with open(file_path, "rb") as handle:
                    sample = handle.read(4096)
            except OSError:
                continue

            if is_probably_binary(sample):
                continue
            yield file_path


def extension_to_language(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".env": "dotenv",
        ".json": "json",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".java": "java",
        ".php": "php",
        ".go": "go",
        ".rb": "ruby",
        ".sh": "bash",
        ".txt": "text",
        ".ini": "ini",
        ".cfg": "cfg",
        ".toml": "toml",
    }
    return mapping.get(ext, "text")


def is_likely_false_positive_name(name: str, value: str) -> bool:
    lowered_name = name.lower()
    lowered_value = value.lower()
    blocked = (
        "label",
        "example",
        "placeholder",
        "dummy",
        "sample",
        "not_",
        "test_",
        "fake",
    )
    if any(token in lowered_name for token in blocked):
        return True
    if lowered_value in {
        "example",
        "demo",
        "placeholder",
        "your_api_key_here",
        "your-api-key-here",
        "your_token_here",
        "changeme",
    }:
        return True
    return False


def scan_file(path: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    seen: Set[Tuple[str, int, str, str]] = set()

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return findings

    for idx, line in enumerate(lines):
        line_no = idx + 1

        known = detect_known_secret(line)
        if known:
            kind, raw_value, _ = known
            key = (os.path.abspath(path), line_no, kind, raw_value)
            if key in seen:
                continue
            seen.add(key)
            snippet_lines = lines[max(0, idx - 7) : min(len(lines), idx + 8)]
            findings.append(
                {
                    "id": f"{os.path.relpath(path)}:{line_no}:{kind}",
                    "file": os.path.abspath(path),
                    "line": line_no,
                    "kind": kind,
                    "masked_value": mask_secret(raw_value),
                    "snippet": "\n".join(snippet_lines),
                    "language": extension_to_language(path),
                    "_raw": raw_value,
                }
            )
            continue

        for match in QUOTED_VALUE_RE.finditer(line):
            raw_value = match.group("value")
            if len(raw_value) < 20:
                continue
            if is_url_or_file_like(raw_value):
                continue
            if shannon_entropy(raw_value) <= 4.0:
                continue
            key = (os.path.abspath(path), line_no, "entropy_string", raw_value)
            if key in seen:
                continue
            seen.add(key)
            snippet_lines = lines[max(0, idx - 7) : min(len(lines), idx + 8)]
            findings.append(
                {
                    "id": f"{os.path.relpath(path)}:{line_no}:entropy_string",
                    "file": os.path.abspath(path),
                    "line": line_no,
                    "kind": "entropy_string",
                    "masked_value": mask_secret(raw_value),
                    "snippet": "\n".join(snippet_lines),
                    "language": extension_to_language(path),
                    "_raw": raw_value,
                }
            )
            break

    return findings


def scan_path(root: str) -> List[Dict[str, object]]:
    aggregated: List[Dict[str, object]] = []
    for path in walk_files(root):
        aggregated.extend(scan_file(path))

    def severity_sort_key(item: Dict[str, object]) -> Tuple[int, str, int]:
        kind = str(item.get("kind", ""))
        score = SEVERITY_ORDER.get(kind, 0)
        return (-score, str(item.get("file", "")), int(item.get("line", 0)))

    aggregated.sort(key=severity_sort_key)
    return aggregated[:10]


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a project for likely hardcoded secrets.")
    parser.add_argument("path", help="Project directory to scan")
    args = parser.parse_args()

    findings = scan_path(args.path)
    print(json.dumps({"count": len(findings), "findings": findings}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
