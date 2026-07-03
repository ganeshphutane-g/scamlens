// URL extraction and analysis: finds links in a message and checks each
// for the deception techniques phishing URLs actually use.

import { normalizeConfusables, hasMixedScript } from './data/homoglyphs.js';
import { RISKY_TLDS, MULTI_PART_TLDS, URL_SHORTENERS } from './data/tlds.js';
import { OFFICIAL_DOMAINS, brandTokens, MIN_BRAND_TOKEN } from './data/brands.js';

// The IPv6-literal alternative must come first: the generic https? branch
// excludes "]" (so URLs inside markdown-link brackets aren't over-matched),
// which would otherwise truncate "http://[::1]/path" before the closing
// bracket and silently drop the URL from analysis entirely.
const URL_RE = /\bhttps?:\/\/\[[0-9a-f:]+\][^\s<>"']*|\bhttps?:\/\/[^\s<>"'\)\]]+|\bwww\.[^\s<>"'\)\]]+|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+\/[^\s<>"'\)\]]*/gi;
const TRAILING_PUNCT = /[.,;:!?'"»›]+$/;

/** Pull URL-looking strings out of free text (deduplicated, cleaned). */
export function extractUrls(text) {
  const found = new Set();
  for (const match of text.matchAll(URL_RE)) {
    const cleaned = match[0].replace(TRAILING_PUNCT, '');
    if (cleaned.length > 3) found.add(cleaned);
  }
  return [...found];
}

/** Levenshtein edit distance — small inputs only (domain labels). */
export function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const curr = [i];
    for (let j = 1; j <= n; j++) {
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
    prev = curr;
  }
  return prev[n];
}

/**
 * Registrable domain ("example.co.in" from "a.b.example.co.in") using a
 * compact multi-part-suffix list — good enough for red-flag analysis.
 */
export function registrableDomain(hostname) {
  const labels = hostname.toLowerCase().split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo)) return labels.slice(-3).join('.');
  return lastTwo;
}

function tokensOf(hostname) {
  // Split every label on separators; "secure-paypal.com.evil.top" →
  // ["secure","paypal","com","evil","top"]
  return hostname.toLowerCase().split(/[.\-_]/).filter(Boolean);
}

const TOKEN_LIST = brandTokens();

function signal(id, weight, title, detail, evidence) {
  return { id, category: 'url', weight, title, detail, evidence };
}

/**
 * Analyze one URL string. Returns { raw, hostname, registrable, knownBrand,
 * flags: [signal...] }. Unparseable input returns null.
 */
export function analyzeUrl(raw) {
  let parsed;
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  try {
    parsed = new URL(withScheme);
  } catch {
    return null;
  }
  // Strip a single trailing dot — "amazon.com." is a legal, DNS-equivalent
  // absolute name for "amazon.com" and a known trick to dodge naive filters.
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');

  // DNS hostnames cannot legitimately exceed 253 characters. Reject early,
  // before any regex/DP work runs on it — this is what keeps the checks
  // below (which are otherwise O(n^2)-ish on attacker-controlled length)
  // from being a denial-of-service vector on a garbage-token "link".
  if (hostname.length > 253) return null;

  if (/^\[[0-9a-f:]+\]$/i.test(hostname)) {
    return {
      raw, hostname, registrable: hostname, knownBrand: false,
      flags: [signal('url-ip', 25, 'Link points to a bare IP address',
        'Legitimate services use named domains. Bare-IP links are a classic phishing setup.', raw)]
    };
  }

  // Reject non-domain hosts the loose regex may have caught (e.g. "v1.2.3/x")
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) && !/[a-z]{2,63}$/.test(hostname)) {
    return null;
  }
  const registrable = registrableDomain(hostname);
  const flags = [];

  // Exact official domain → trusted brand link; still check userinfo trick.
  const knownBrand = OFFICIAL_DOMAINS.has(registrable);

  if (withScheme.includes('@') && parsed.username) {
    flags.push(signal('url-userinfo', 25, 'Address hides the real destination',
      `Everything before the "@" is a decoy — this link actually goes to "${hostname}".`, raw));
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    flags.push(signal('url-ip', 25, 'Link points to a bare IP address',
      'Legitimate services use named domains. Bare-IP links are a classic phishing setup.', raw));
    return { raw, hostname, registrable, knownBrand: false, flags };
  }

  if (hostname.split('.').some(l => l.startsWith('xn--')) || hasMixedScript(hostname)) {
    flags.push(signal('url-homoglyph-script', 30, 'Domain uses lookalike foreign characters',
      'The address contains characters designed to look like ordinary letters (e.g. a Cyrillic "а"). This is a homoglyph attack.', raw));
  }

  if (URL_SHORTENERS.has(registrable)) {
    flags.push(signal('url-shortener', 10, 'Shortened link hides the destination',
      'You cannot see where this link really goes. Treat with caution, especially in unexpected messages.', raw));
    return { raw, hostname, registrable, knownBrand: false, flags };
  }

  if (!knownBrand) {
    const tld = registrable.split('.').pop();
    if (RISKY_TLDS.has(tld)) {
      flags.push(signal('url-risky-tld', 12, `High-abuse domain ending ".${tld}"`,
        'This domain ending is disproportionately used in phishing because it is cheap or free to register.', raw));
    }

    const sld = registrable.split('.')[0];
    const sldNorm = normalizeConfusables(sld);
    const hostTokens = new Set(tokensOf(hostname).map(normalizeConfusables));

    for (const { token, brand, generic } of TOKEN_LIST) {
      if (sldNorm === token && sld !== token) {
        flags.push(signal('url-homoglyph-brand', 35, `Fake "${brand}" domain using disguised characters`,
          `"${registrable}" imitates ${brand} by swapping in lookalike characters/digits.`, raw));
        break;
      }
      if (sldNorm !== token && sldNorm.length >= MIN_BRAND_TOKEN) {
        const maxDist = token.length <= 7 ? 1 : 2;
        // Cheap pre-check: two strings whose lengths differ by more than
        // maxDist can never be within maxDist edits of each other — skips
        // the O(m*n) DP table for the (common) obviously-unrelated case.
        // Scoped to this branch only — must NOT skip the brand-in-domain
        // check below for the same token (e.g. "amaz0n-security.com" is a
        // length-mismatched non-typosquat SLD, but still legitimately
        // contains the bare "amazon" token and must reach that check).
        const dist = Math.abs(sldNorm.length - token.length) <= maxDist ? levenshtein(sldNorm, token) : Infinity;
        if (dist > 0 && dist <= maxDist) {
          flags.push(signal('url-typosquat', 35, `Misspelled "${brand}" domain`,
            `"${registrable}" is one keystroke away from the real ${brand} domain — a typosquat.`, raw));
          break;
        }
      }
      if (!generic && sldNorm !== token && hostTokens.has(token)) {
        flags.push(signal('url-brand-in-domain', 35, `"${brand}" name buried in an unrelated domain`,
          `The real domain here is "${registrable}", not ${brand}. Scammers put brand names in front of their own domain (e.g. "paypal.com.verify-account.xyz").`, raw));
        break;
      }
    }

    const subdomainCount = hostname.split('.').length - registrable.split('.').length;
    if (subdomainCount >= 3) {
      flags.push(signal('url-many-subdomains', 8, 'Unusually deep subdomain chain',
        'Long subdomain chains are used to push the real domain out of sight on small screens.', raw));
    }
  }

  return { raw, hostname, registrable, knownBrand, flags };
}

/** Analyze every URL found in a text. */
export function analyzeUrls(text) {
  return extractUrls(text).map(analyzeUrl).filter(Boolean);
}
