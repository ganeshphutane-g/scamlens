<!-- Thanks for contributing to ScamLens! -->

## What this changes

Briefly describe the change and why.

## Checklist

- [ ] `npm test` passes locally.
- [ ] If this adds/changes a detection pattern, I added a matching example to
      `tests/corpus.test.js` (`SCAMS` for a scam, `LEGIT` for a legitimate
      message it must not over-flag).
- [ ] No new runtime dependencies (`package.json` `dependencies` stays empty).
- [ ] No network calls added anywhere in `src/`, `bin/`, or `web/`.
- [ ] User-facing text (advice/details) is plain-language, no jargon.
