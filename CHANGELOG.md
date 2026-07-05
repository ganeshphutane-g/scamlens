# Changelog

All notable changes to ScamLens are documented here. This project follows
[Semantic Versioning](https://semver.org/) loosely — detection-pattern
additions are minor bumps; engine/API changes are major.

## [Unreleased]

### Added
- **Optional AI second opinion** (`src/ai.js`): after the always-offline rule
  check, users can opt in to an LLM judgment for novel scams — via a **local
  Ollama** model (private, message stays on device) or the **Anthropic API**
  with their own key (message sent off-device, only after an explicit
  warning). Available in the web UI and via the CLI `--ai` flag. The model is
  constrained by JSON-schema structured output, told never to declare a
  message definitively "safe," and instructed to treat the message as
  untrusted data. Zero new dependencies (raw `fetch`).
- Five more scam families with regression tests: overpayment / fake-check,
  sextortion / webcam blackmail, fake bank fraud-alert callbacks,
  rental-deposit scams, and pay-a-fee-to-release payout/insurance advance-fee
  scams; plus a Hinglish/Devanagari tech-support alternate.
- Multi-character homoglyph detection now also catches brand names hidden in
  **subdomains** (`vvhatsapp.secure-login.com`).
- Multi-line messages are normalized before matching, so a real scam SMS with
  line breaks between cue phrases is no longer scored a false "safe."
- WCAG-AA color fixes: darker primary button, stronger control borders,
  brighter critical-risk badge text.
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
