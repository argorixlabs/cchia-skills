# Security Policy

## Supported versions

Security fixes are applied to the latest version on the default branch. Older snapshots and generated assessment
artifacts are not supported releases.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not open a public issue containing exploit details,
credentials, tenant identifiers, evidence payloads or personal data.

Include the affected component and version, the security boundary involved, reproducible steps using synthetic data,
expected versus observed behavior, and the potential impact. Do not test against third-party systems or production
infrastructure without explicit authorization.

## Scope notes

`read_only` describes the allow-listed provider operations. It does not guarantee that external CLI tools avoid local
cache/configuration writes. The bundled worker reports `strong_os_boundary=false`; checks from untrusted sources must
run behind an independent OS-level isolation boundary.
