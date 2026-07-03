# Changelog

All notable changes to ScamLens are documented here. This project follows
[Semantic Versioning](https://semver.org/) loosely — detection-pattern
additions are minor bumps; engine/API changes are major.

## [Unreleased]

### Added
- **Hindi / Hinglish and Devanagari detection** across seven scam categories
  (credential requests, payment demands, arrest threats, official-notice
  impersonation, prizes, secrecy demands, urgency) — the most common
  language of scams targeting the tool's core audience.
- **Multi-character homoglyph detection** (`rn`→m, `vv`→w, `cl`→d) so
  domains like `rnonzo.com` (imitating Monzo) or `arnazon.com` are caught.
- New scam patterns: fake tech-support / virus alerts, family-emergency
  ("grandparent") money requests, QR-code phishing (quishing),
  subscription-renewal refund scams, and crypto-recovery scams.
- Coverage for business-email-compromise (bank-detail change), SIM-swap
  social engineering, toll-road smishing, and Telegram-interview job scams.
- ~50 additional impersonated brands (delivery services, neobanks, crypto
  exchanges, and non-India/US/UK government agencies).
- Web UI: "Copy report" button, screen-reader live region, auto-scroll to
  results, and comfortable touch targets.
- Continuous integration (GitHub Actions) running the test suite on Node
  18, 20, and 22.

### Fixed
- False positives on legitimate messages (restaurant/event QR codes,
  "don't tell mom about the surprise party", self-directed "update your
  password" IT notices, "I need help right now").
- Denial-of-service risk (ReDoS and unbounded edit-distance) on very long
  hostnames, now bounded by the DNS 253-character limit.
- URL-detection bypasses: trailing-dot FQDNs (`amazon.com.`) and IPv6
  bracket-literal links were silently dropped; now handled.
- Local web server now binds to `127.0.0.1` only (was exposed to the LAN).

## [0.1.0] — 2026-07-03

### Added
- Initial release: offline scam & phishing checker with a CLI and a
  dependency-free local web UI sharing one detection engine.
- Content-pattern detection (credential/OTP requests, gift-card & crypto
  payment demands, digital-arrest threats, remote-access lures,
  prize/investment fraud, impersonation notices, advance-fee scripts) and
  URL analysis (typosquats, homoglyphs, brand-in-domain, bare IPs,
  userinfo tricks, shorteners, high-abuse TLDs).
- Plain-language explanations and next-step advice for every finding.
