# Contributing to CCHIA Skills

Contributions are welcome under the repository's [Apache License 2.0](LICENSE). By submitting a contribution, you
agree that it is licensed under Apache-2.0 and that you have the right to submit it.

All commits must include a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Create it with `git commit --signoff`. The sign-off certifies the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).

## CCHIA Check contract

Do not add isolated scripts. A control is a complete, versioned package:

```text
checks/<DOMAIN>/<CCHIA-ID>/
├── control.yaml
├── check.py
├── expected.json
├── mapping.yaml
├── README.md
└── fixtures/
    ├── positive.json
    ├── negative.json
    └── no_evidence.json
```

Checks must be pure and read-only. Missing, malformed, truncated or unavailable evidence must never become `PASS`.
Mappings require a rationale and a primary source; do not reproduce protected ISO text.

Create and validate a package from `seguridad-ia-cchia/`:

```powershell
python scripts/cchia.py new-check --id CCHIA-API-999 --domain API --title "Título verificable"
python scripts/cchia.py validate
python -m unittest discover -s tests -v
```

## Pull requests

- Keep collector commands in the central exact allow-list and reject free-form arguments.
- Add positive, negative and no-evidence fixtures with canonical hashes.
- Add adversarial tests for error, timeout, output limits, redaction and incomplete evidence.
- Do not commit credentials, provider snapshots, generated assessments, caches or customer identifiers.
- Explain limitations and what a `PASS` does not prove.
