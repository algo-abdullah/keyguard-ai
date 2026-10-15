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
