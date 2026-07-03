// Direct unit tests for the hand-maintained lookalike/brand tables in
// src/data/. These are only exercised indirectly through tests/urls.test.js
// otherwise — a typo'd table entry (e.g. an accidentally-removed digit
// mapping) would otherwise only surface as an unrelated-looking failure,
// if at all.

import test from 'node:test';
import assert from 'node:assert/strict';
import { CONFUSABLES, normalizeConfusables, hasMixedScript } from '../src/data/homoglyphs.js';
import { BRANDS, OFFICIAL_DOMAINS, MIN_BRAND_TOKEN, brandTokens } from '../src/data/brands.js';

test('normalizeConfusables: pure ASCII is unchanged', () => {
  assert.equal(normalizeConfusables('amazon'), 'amazon');
  assert.equal(normalizeConfusables('PayPal'), 'paypal');
});

test('normalizeConfusables: digit lookalikes map to letters', () => {
  assert.equal(normalizeConfusables('paypa1'), 'paypal');
  assert.equal(normalizeConfusables('amaz0n'), 'amazon');
  assert.equal(normalizeConfusables('g00gle'), 'google');
});

test('normalizeConfusables: Cyrillic lookalikes map to Latin', () => {
  assert.equal(normalizeConfusables('аpple'), 'apple'); // Cyrillic а
  assert.equal(normalizeConfusables('рayрal'), 'paypal'); // Cyrillic р
});

test('normalizeConfusables: Greek lookalikes map to Latin', () => {
  assert.equal(normalizeConfusables('νetflix'), 'vetflix'); // Greek nu -> v
  assert.equal(normalizeConfusables('ωallet'), 'wallet'); // Greek omega -> w
});

test('normalizeConfusables: empty string', () => {
  assert.equal(normalizeConfusables(''), '');
});

test('CONFUSABLES table has no accidental self-mappings that would hide a swap', () => {
  for (const [from, to] of Object.entries(CONFUSABLES)) {
    assert.notEqual(from, to, `CONFUSABLES maps "${from}" to itself — pointless entry`);
  }
});

test('hasMixedScript: detects Cyrillic/Greek presence', () => {
  assert.equal(hasMixedScript('аpple.com'), true);
  assert.equal(hasMixedScript('apple.com'), false);
  assert.equal(hasMixedScript(''), false);
});

test('brandTokens: filters tokens shorter than MIN_BRAND_TOKEN', () => {
  const tokens = brandTokens();
  for (const { token } of tokens) {
    assert.ok(token.length >= MIN_BRAND_TOKEN, `token "${token}" is shorter than MIN_BRAND_TOKEN (${MIN_BRAND_TOKEN})`);
  }
});

test('brandTokens: excludes ordinary-word domains that would cause noise', () => {
  const tokens = brandTokens().map(t => t.token);
  assert.ok(!tokens.includes('live'));
  assert.ok(!tokens.includes('office'));
});

test('brandTokens: every entry carries a brand name and generic flag', () => {
  for (const t of brandTokens()) {
    assert.ok(typeof t.token === 'string' && t.token.length > 0);
    assert.ok(typeof t.brand === 'string' && t.brand.length > 0);
    assert.ok(typeof t.generic === 'boolean');
  }
});

test('OFFICIAL_DOMAINS contains every domain listed in BRANDS', () => {
  for (const brand of BRANDS) {
    for (const domain of brand.domains) {
      assert.ok(OFFICIAL_DOMAINS.has(domain), `${domain} (from ${brand.name}) missing from OFFICIAL_DOMAINS`);
    }
  }
});

test('OFFICIAL_DOMAINS size matches the flattened BRANDS domain count (no silent dedup gaps)', () => {
  const flat = new Set(BRANDS.flatMap(b => b.domains));
  assert.equal(OFFICIAL_DOMAINS.size, flat.size);
});
