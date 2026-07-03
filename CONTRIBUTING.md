# Contributing to ScamLens

Thanks for considering it. This project exists to protect people, so the bar for changes is simple: **never make detection worse, and never compromise the privacy guarantee.**

## Ground rules

1. **Zero network calls, ever.** Nothing in `src/`, `bin/`, or `web/` may perform a network request of any kind. This is the entire trust model of the tool.
2. **Zero runtime dependencies.** `package.json`'s `dependencies` must stay empty. Anyone should be able to read the whole engine in one sitting.
3. **Every new detection pattern needs a test.** Add your case to `tests/corpus.test.js` (or `tests/urls.test.js` for URL-specific logic) in the same PR.
4. **Every change must keep `npm test` green**, including the existing scam/legit corpus — a change that "improves" detection by breaking a legitimate-message test is not an improvement.

## Adding a scam pattern

1. Add a real, **anonymized** example to the `SCAMS` array in `tests/corpus.test.js` (strip names, phone numbers, real account numbers — keep the scam *script* intact).
2. Add or extend a pattern in `src/data/patterns.js`. Keep the regex as narrow as you can while still catching the pattern — false positives on legitimate messages erode trust in the tool for everyone.
3. Run `npm test`. If your new pattern accidentally flags something in the `LEGIT` corpus, narrow it further.
4. If your pattern only matches when combined with other signals (rather than being dangerous alone), consider adding it to `COMBOS` in `src/data/patterns.js` instead of giving it a high standalone weight.
5. Know the scoring floor: no single pattern, however high its weight, can push a message to "high" on its own — `analyze()` requires at least one signal ≥18 *and* enough combined weight to cross the score threshold. A brand-new single-signal pattern will land at "medium" at best, by design. That's normal, not a bug — pair it with a realistic `LEGIT`/`SCAMS` example either way so the threshold stays guarded.
6. If the trigger phrase is ambiguous between "attacker asking you to disclose something" and "legitimate self-service action" (e.g. verbs like enter/verify/confirm/update), give it low weight (~10) rather than folding it into a high-confidence pattern — see `credential-entry-prompt` vs `credential-request` in `src/data/patterns.js` for the split this project uses.

## Adding brand/domain coverage

Add to the `BRANDS` array in `src/data/brands.js`. Mark `generic: true` for brand names that are also common English words (e.g. "Target," "Chase") to avoid false-positiving on unrelated domains that happen to contain that word.

## Reporting a false positive or false negative

Open an issue with:
- The (anonymized) message or link text
- What ScamLens said (score/level/signals — `--json` output is easiest to paste)
- What you expected

## Regional and language coverage

The pattern set covers scams common in India, the US, and the UK, in English and Hindi/Hinglish (romanized Hindi and Devanagari — see the Hinglish/Devanagari alternates inside each pattern in `src/data/patterns.js`). Expanding to other languages and regions is one of the highest-value contributions possible. To add a language, add localized alternates as additional regexes inside the *existing* category (so the category's advice and combos still apply) rather than creating a separate parallel pattern set, and include both scam and legitimate examples in that language in the test corpus.

## Code style

- No build step, no bundler, no TypeScript — plain, dependency-free JavaScript (ES modules) that runs identically in Node and browsers.
- `web/index.html` imports `src/engine.js` directly; never duplicate detection logic into the web UI.
- Keep functions small and comments rare — only explain the *why* when it's non-obvious (e.g. "we use maxDist=1 not 2 here because 2 false-positives on real words like 'gitlab'").

## Running everything locally

```bash
npm test        # unit tests + scam/legit regression corpus
npm run web      # web UI at http://localhost:4173
node bin/cli.js "..."   # CLI
```
