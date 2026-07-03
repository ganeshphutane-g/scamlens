# ScamLens

**Paste any suspicious message, email, or link. Get an instant, plain-language risk report. Nothing you paste ever leaves your device.**

Phishing texts, fake "digital arrest" police calls, KYC-expiry scams, lottery wins nobody entered, romance-scam money requests, work-from-home "task" fraud — the scripts repeat endlessly, and the people most often targeted (older relatives, first-time smartphone users, anyone in a moment of stress) are the least equipped to spot them. ScamLens exists so that anyone — not just security-savvy people — can paste a message and immediately understand *why* it's dangerous and *what to do next*, in plain language, with zero setup and zero risk of the message itself being sent anywhere.

- 🔒 **100% offline.** No server, no API calls, no account, no analytics. Every byte you paste stays in your browser or terminal.
- 🧠 **Explains itself.** Every red flag comes with a plain-language reason, not just a score.
- ⚡ **Zero setup.** One file for the web UI, one command for the CLI. No dependencies at runtime.
- 🌍 **Free forever, open source.** MIT licensed. Fork it, audit it, run it anywhere.

## Try it

No install, no build step. Clone it and run it straight from source:

```bash
git clone https://github.com/ganeshphutane-g/scamlens.git
cd scamlens
```

### Web (recommended for most people)

```bash
npm run web
```

Opens ScamLens at `http://localhost:4173`. Paste a message, click **Check for scams**.

*(Why not just double-click `web/index.html`? Chrome and most browsers block module imports from `file://` for security reasons — the local server is a two-second workaround, and your data still never leaves your machine.)*

### Command line

```bash
node bin/cli.js "Dear customer your account will be blocked. Share your OTP now: http://sbi-kyc-verify.xyz"
```

Or pipe a message in:

```bash
pbpaste | node bin/cli.js                    # macOS: check whatever's on your clipboard
echo "$MESSAGE" | node bin/cli.js --json      # machine-readable output for scripting
```

Want the `scamlens` command available globally? `npm link` from inside the cloned repo.

## What it catches

ScamLens looks for two independent kinds of evidence and combines them:

**Content patterns** — the language scammers actually use: requests for OTPs/PINs/passwords (including the SIM-swap "read us the code you just got" script), demands for gift-card or crypto payment, threats of arrest or "digital arrest," requests to install remote-access apps (AnyDesk/TeamViewer), too-good-to-be-true prizes and investment returns, fake bank/government/utility/toll-road notices, business-email-compromise ("we changed our bank account") wire fraud, work-from-home and Telegram-interview job fraud, secrecy demands ("don't tell your family"), surprise refund/cashback bait, manufactured urgency, and advance-fee ("send money to receive money") scripts.

**Link analysis** — domains that impersonate real brands: typosquats (`amaz0n-security.com`), lookalike-character homoglyphs (Cyrillic letters standing in for Latin ones), brand names buried inside an unrelated domain (`paypal.com.verify-account.xyz`), bare-IP links, `user@host` address-hiding tricks, link shorteners, and high-abuse domain endings.

Signals that only appear together in real scams (a threat plus a secrecy demand, a deceptive link plus a credential request) score extra highly — the goal is that a single ambiguous phrase never triggers a false alarm, but the actual combinations scammers use reliably do.

Every report ends with **What to do** — concrete, non-technical next steps, not just a red flag.

## What it will never do

- Send anything you type over the network. There is no server-side component; the web UI and CLI both run the same detection code locally.
- Ask for an account, email, or any personal information.
- Silently update itself or phone home for telemetry.

You can verify this yourself — the entire detection engine is under 750 lines in [`src/`](src/), readable in one sitting, with zero runtime dependencies. The local web server (`bin/serve.js`) binds to `127.0.0.1` only — it is never reachable from your network, even on shared Wi-Fi.

## Limitations (please read)

ScamLens is a **second opinion, not a guarantee**. A low score does not mean a message is safe — novel scam scripts, or scams in languages/regions the pattern set doesn't yet cover well, can still slip through. A medium/high score does not mean a message is definitely fraudulent — always use your own judgment, and when money, credentials, or personal data are involved, verify independently through an official app or number you already trust, not anything in the message itself.

The pattern set currently has stronger coverage for English-language scams common in India, the US, and the UK. Coverage of other languages and regions is an open area — see [Contributing](#contributing).

## Development

```bash
git clone https://github.com/ganeshphutane-g/scamlens.git
cd scamlens
npm test          # run the test suite (65+ tests: unit + a real-world scam/legit corpus)
npm run web       # local web UI at http://localhost:4173
npm start "..."    # run the CLI directly from source
```

No build step, no bundler, no external dependencies. `src/engine.js` is the single source of truth used by both the CLI and the web UI.

## Contributing

The most valuable contributions right now:

- **New scam patterns** — add a real (anonymized) scam script you've seen to `src/data/patterns.js` and a matching regression test in `tests/corpus.test.js`.
- **Regional/language coverage** — banks, government agencies, and scam scripts specific to your country or language.
- **False-positive reports** — if a legitimate message scored medium/high, open an issue with the (anonymized) text.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. All contributions are reviewed against the existing test corpus so detection quality never regresses.

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, embed it, ship it.
