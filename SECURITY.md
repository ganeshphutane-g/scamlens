# Security Policy

ScamLens is a security tool, so its own integrity matters. Two guarantees are load-bearing and must never regress:

1. **It makes zero network calls.** Nothing you paste is ever transmitted. The detection engine (`src/`) has no `fetch`, no telemetry, and no external resource loads; the web page is fully self-contained and the optional local server (`bin/serve.js`) binds to `127.0.0.1` only.
2. **It has zero runtime dependencies.** The whole engine is auditable in one sitting, with no third-party package that could be compromised.

## Reporting a vulnerability

If you find a way to break either guarantee above — or any other security issue (e.g. a way to make the tool exfiltrate input, a cross-site scripting hole in the web UI, a denial-of-service input that hangs the engine) — please report it privately:

- Open a [GitHub Security Advisory](https://github.com/ganeshphutane-g/scamlens/security/advisories/new) (preferred), or
- Open a regular issue **without** exploit details and ask for a private channel.

Please don't disclose exploit details publicly until a fix is released. There's no bounty (this is a free, unfunded project), but you'll be credited in the changelog unless you'd rather not be.

## Scope

- **In scope:** the detection engine, the CLI, the web UI, and the local server in this repository.
- **Out of scope:** the accuracy of a given scam verdict. False positives and false negatives are detection-quality issues, not security vulnerabilities — please report those as normal issues (see [CONTRIBUTING.md](CONTRIBUTING.md)). ScamLens is a second opinion, never a guarantee.

## Supported versions

This project ships from `main`. Security fixes land there and are released as a new tag. There are no separately-maintained release branches.
