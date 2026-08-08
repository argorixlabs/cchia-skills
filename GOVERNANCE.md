# Project governance

## Stewardship

This repository is published under the `argorixlabs` GitHub account with authorization to use the CCHIA project name
and namespace. The repository is a technical implementation; assessments and mappings are not institutional
certifications or legal opinions.

Repository maintainers are responsible for releases, catalog integrity, security response and enforcement of the
read-only collector boundary. Maintainer identity and permissions are governed through GitHub repository access.

## Changes

- Code, controls and documentation are changed through reviewed pull requests.
- Every CCHIA Check must remain a complete versioned package with its three contractual fixtures.
- Framework mappings require a rationale, a primary source and a verification date.
- Missing or insufficient evidence must remain `NOT_ASSESSED`, never an inferred `PASS`.
- Collector commands must remain in the exact central allow-list; free-form commands are not accepted.

## Releases

The engine and each control use independent semantic versions. Releases should publish the catalog fingerprint, test
result, fixture count and known limitations. Generated tenant assessments and local evidence are never release assets.

## Contributions and security

Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md) and Apache-2.0. Security reports follow
[SECURITY.md](SECURITY.md) and must not be disclosed through public issues before coordinated remediation.
