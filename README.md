# KeyGuard

Local secret scanner + LLM-assisted auto-fixer for developers and teams.

KeyGuard helps find likely secret leaks in source trees, judges whether a finding is real using fast rules and a local LLM (Ollama), and generates verified, minimal fixes that replace literals with environment-variable lookups. Designed to run entirely locally (no raw secrets sent to third-party APIs).

## Features
- Fast static scanner (regexes + entropy heuristics).
- Hybrid judgement: deterministic rules first, then a local LLM via Ollama for ambiguous cases.
- Deterministic, server-side patch generation that never exposes raw secrets to the LLM.
- Safe apply flow: verification checks (secret removed, env-var present, minimal diff, syntax check) before write and automatic backup of patched files.
- Single-file static web UI for local review and manual apply.
- Demo projects and unit tests included.

## Important security notes
- KeyGuard intentionally keeps any raw secret values on the local server only; the web UI and API responses always show masked values.
- Do not run KeyGuard on untrusted machines with your real production secrets unless you trust the environment.
- Backups are created beside modified files (filename + `.bak`). Ensure your backup retention policy fits your needs.

## Requirements
- Python 3.10+ (stdlib only; no third-party packages required).
- Ollama (local) running at `http://127.0.0.1:11434` for LLM-assisted judgement/fix generation. If Ollama is not available, rule-based judgements still run.

## Quick start (local)

1. Start Ollama (optional, recommended for better judgement and fix suggestions):

```bash
ollama serve
```

2. Start the KeyGuard web server (serves the UI and API):

```bash
python3 app.py
# Server listens on 127.0.0.1:8000 by default
```

3. Open the UI in your browser: `http://127.0.0.1:8000`

Or run the CLI scanners directly for automation:

```bash
python3 scanner.py demo_vulnerable
python3 llm.py demo_vulnerable   # judge/fix helper (needs Ollama)
python3 fixer.py demo_vulnerable # generate/verify fixes programmatically
```

## Environment variables
- `MODEL_NAME` — (optional) Ollama model name to use (defaults to a sensible local model if present).

## API (local server)
- `GET /api/health` — checks Ollama availability and selected model.
- `POST /api/scan` — JSON: `{ "path": "<folder>" }` — returns findings (masked values only).
- `POST /api/fix` — JSON: `{ "finding_id": "<id>" }` — generate suggested patch and verification checks (server keeps raw secret internally).
- `POST /api/apply` — JSON: `{ "finding_id": "<id>" }` — applies verified patch, creates `.bak`, appends `.env.example`, updates `.gitignore` as needed.

All API responses intentionally omit raw secret values; the server stores raw secrets only in-memory or in its findings store during a session.

## Tests
- Unit tests are under `tests/`. Run:

```bash
python3 -m unittest -v
```

## Demos
- Demo projects are in `demo_projects/` and `demo_vulnerable/` for multi-language examples and test cases.

## Contributing and caution
- This project intentionally includes synthetic demo secrets for testing. When contributing, avoid committing real secrets.
- If pushing to remote repositories, enable your own repository's push protection and secret scanning to avoid accidental leaks.

## License
This repository is licensed under the MIT License — see `LICENSE`.

## Maintainer
- Muhammad Abdullah Ameen
# KeyGuard

KeyGuard is a local, offline secret-leak scanner and auto-fixer for small codebases. It scans a folder for likely hardcoded credentials, asks a local Ollama model to judge ambiguous cases, and verifies any suggested refactor before applying it.

## Why this exists

Many small teams need a fast check for accidental secrets in code without sending data to a cloud service. KeyGuard keeps the workflow entirely local and can run offline with a local model.

## Local model setup

```bash
ollama list
ollama serve
python3 llm.py demo_vulnerable
```

## Known limitations

- small models misjudge token-like strings, so we use rules for high-confidence formats
- regex-based detection can miss unusual secret formats
- only single-line secret values are handled in the first pass

## Hybrid judging approach

The judge uses a deterministic rule layer for high-confidence secret formats such as AWS access keys, GitHub tokens, Stripe keys, Google API keys, Slack tokens, and private key markers. Ambiguous values such as `generic_secret` and `entropy_string` are sent to the local LLM for a one-line judgment. Placeholder markers such as `placeholder`, `change-me`, `your_`, `example`, and `xxxx` are forced to `FALSE POSITIVE` regardless of the model output.
