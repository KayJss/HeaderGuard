# HeaderGuard

Small post-deploy CLI that audits HSTS, Content-Security-Policy, X-Content-Type-Options and Referrer-Policy headers.

## Install

```bash
python -m pip install -e .
```

## Usage

```bash
headerguard https://example.com
headerguard https://example.com --min-score 80 --json
```

It detects missing/obviously weak values, scores the response, supports JSON/CI output, validates URLs/network failures, and has no third-party runtime dependencies. Exit code 0 means the policy passed; 2 means attention is required.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Structure

`headerguard/core.py` contains policy/scoring logic; `headerguard/cli.py` performs HTTP requests and presentation; `tests/` is deterministic and offline.

## License

Proprietary / All Rights Reserved. See `LICENSE`.
