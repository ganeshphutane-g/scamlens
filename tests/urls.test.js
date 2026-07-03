import test from 'node:test';
import assert from 'node:assert/strict';
import { extractUrls, levenshtein, registrableDomain, analyzeUrl } from '../src/urls.js';

test('levenshtein basics', () => {
  assert.equal(levenshtein('paypal', 'paypal'), 0);
  assert.equal(levenshtein('paypal', 'paypa1'), 1);
  assert.equal(levenshtein('amazon', 'amazan'), 1);
  assert.equal(levenshtein('netflix', 'netfliix'), 1);
  assert.equal(levenshtein('', 'abc'), 3);
});

test('registrableDomain handles multi-part TLDs', () => {
  assert.equal(registrableDomain('www.example.com'), 'example.com');
  assert.equal(registrableDomain('a.b.example.co.in'), 'example.co.in');
  assert.equal(registrableDomain('sbi.co.in'), 'sbi.co.in');
  assert.equal(registrableDomain('paypal.com.verify.evil.top'), 'evil.top');
  assert.equal(registrableDomain('localhost'), 'localhost');
});

test('extractUrls finds and cleans links', () => {
  const text = 'Go to https://example.com/x, or www.test.org! Also bit.ly/abc now.';
  const urls = extractUrls(text);
  assert.ok(urls.includes('https://example.com/x'));
  assert.ok(urls.includes('www.test.org'));
  assert.ok(urls.includes('bit.ly/abc'));
});

test('official brand domain is not flagged', () => {
  const r = analyzeUrl('https://www.amazon.com/orders/123');
  assert.equal(r.knownBrand, true);
  assert.equal(r.flags.length, 0);
});

test('typosquat is flagged', () => {
  const r = analyzeUrl('https://www.amazan.com/login');
  assert.ok(r.flags.some(f => f.id === 'url-typosquat'));
});

test('digit-substitution homoglyph is flagged', () => {
  const r = analyzeUrl('https://paypa1.com/secure');
  assert.ok(r.flags.some(f => f.id === 'url-homoglyph-brand' || f.id === 'url-typosquat'));
});

test('brand buried in unrelated domain is flagged', () => {
  const r = analyzeUrl('http://paypal.com.account-verify.xyz/login');
  assert.ok(r.flags.some(f => f.id === 'url-brand-in-domain'));
});

test('bare IP URL is flagged', () => {
  const r = analyzeUrl('http://192.168.4.12/bank');
  assert.ok(r.flags.some(f => f.id === 'url-ip'));
});

test('URL shortener is a weak flag', () => {
  const r = analyzeUrl('https://bit.ly/3xYzAb');
  const flag = r.flags.find(f => f.id === 'url-shortener');
  assert.ok(flag);
  assert.ok(flag.weight <= 12);
});

test('punycode / mixed script is flagged', () => {
  const r = analyzeUrl('https://xn--pple-43d.com/login');
  assert.ok(r.flags.some(f => f.id === 'url-homoglyph-script'));
});

test('ordinary unrelated domains are not brand-flagged', () => {
  for (const url of [
    'https://zomato.com/order', 'https://wikipedia.org/wiki/Fraud',
    'https://pineapple-recipes.com/cake', 'https://myadvisor.org/help'
  ]) {
    const r = analyzeUrl(url);
    assert.ok(!r.flags.some(f => f.weight >= 25), `false positive on ${url}: ${JSON.stringify(r.flags)}`);
  }
});

test('a single trailing dot does not bypass detection ("amazon.com." === "amazon.com")', () => {
  const withDot = analyzeUrl('https://amaz0n-security.com./reset');
  const withoutDot = analyzeUrl('https://amaz0n-security.com/reset');
  assert.ok(withDot, 'trailing-dot URL must still parse, not be silently dropped');
  assert.equal(withDot.registrable, withoutDot.registrable);
  assert.deepEqual(withDot.flags.map(f => f.id), withoutDot.flags.map(f => f.id));
});

test('IPv6 bracket-literal links are extracted and flagged as bare-IP', () => {
  const text = 'Login here: http://[2001:db8::1]/bank-login';
  const urls = extractUrls(text);
  assert.equal(urls.length, 1, 'the IPv6 literal must not be truncated at the closing bracket');
  const r = analyzeUrl(urls[0]);
  assert.ok(r.flags.some(f => f.id === 'url-ip'));
});

test('IPv4 bare-IP links still extract cleanly alongside the IPv6 case', () => {
  const urls = extractUrls('Login here: http://192.168.4.12/bank');
  assert.deepEqual(urls, ['http://192.168.4.12/bank']);
});

test('hostnames beyond the DNS 253-char limit are rejected, not processed', () => {
  const hostname = 'a'.repeat(300) + '.com';
  const r = analyzeUrl(`https://${hostname}/x`);
  assert.equal(r, null);
});

test('a very long non-matching hostname label resolves quickly (ReDoS/DoS guard)', () => {
  const longLabel = 'a'.repeat(48000) + '1'; // long run of letters not ending in a letter
  const start = Date.now();
  const r = analyzeUrl(`http://${longLabel}/verify`);
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 500, `analyzeUrl took ${elapsed}ms on a long garbage hostname — expected a fast, bounded rejection`);
  // A 48,001-char single label exceeds the 253-char hostname cap, so this
  // is correctly rejected outright rather than analyzed.
  assert.equal(r, null);
});

test('a long but DNS-legal-length label near the brand-comparison threshold still resolves quickly', () => {
  const label = 'a'.repeat(63); // one full DNS label, well within the 253-char host cap
  const start = Date.now();
  analyzeUrl(`http://${label}.com/verify`);
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 200, `analyzeUrl took ${elapsed}ms on a 63-char label`);
});
