# Security policy

## Supported version

This repository is currently an alpha. Only the newest published alpha is supported.

## Reporting a vulnerability

Do not publish a proof of concept that targets real user files. Report security issues privately through GitHub Security Advisories when available.

Include:

- Windows version;
- Codex CLI version;
- Node.js version;
- the generated `-support.txt` report after reviewing it;
- exact reproduction steps using synthetic files only.

Never include `auth.json`, API keys, access tokens, or full private configuration files.

## Threat model

The Canary is designed to test selected Codex controls with disposable files. It does not defend against a malicious process running with the same or higher user privileges. It does not install hooks, alter Codex configuration, or certify the host system.


## Alternative Codex bundles

The Canary prefers a same-version complete Codex bundle found under a known `%LOCALAPPDATA%` installation root. If none exists, it may offer a newer complete bundle after checking that bundle's own sandbox command. A version-mismatched test requires explicit consent and is never reported as validation of the active CLI.

The Canary never installs, copies, replaces, or permanently reconfigures Codex components. The exact executable and tested version used for a live probe are included in the report.


## Report handling

Detailed reports can contain full local executable and configuration paths. Do not attach them publicly without manual review. The Canary creates a separate share-safe support report that omits usernames, executable paths, project paths, credential paths, and raw configuration contents. Automatic redaction is a risk-reduction measure, not an absolute guarantee.
