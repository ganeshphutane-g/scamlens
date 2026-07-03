// Characters commonly substituted to disguise a brand name in a domain
// (e.g. "g00gle.com", "аpple.com" with a Cyrillic "а").
// Maps each confusable character to the ASCII letter it imitates.

export const CONFUSABLES = {
  // Digits and symbols used as letters
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g',
  '@': 'a', '$': 's', '!': 'i', '|': 'l',
  // Cyrillic lookalikes
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
  'у': 'y', 'х': 'x', 'і': 'i', 'ѕ': 's', 'ԁ': 'd',
  'ɡ': 'g', 'һ': 'h', 'ј': 'j', 'к': 'k', 'м': 'm',
  'н': 'h', 'т': 't', 'в': 'b', 'п': 'n',
  // Greek lookalikes
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k',
  'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u',
  'χ': 'x', 'ω': 'w', 'η': 'n', 'μ': 'u'
};

const CYRILLIC_OR_GREEK = /[Ͱ-ϿЀ-ӿ]/;

// Multi-character visual confusables: two glyphs that together imitate one
// letter at a glance ("rnicrosoft" reads as "microsoft"). Applied only for
// brand-lookalike comparison (never to display text), so a rare incidental
// collision in an unrelated domain just yields a low-value "looks like X"
// hint, not a hard error. Ordered longest-first so overlaps resolve safely.
const MULTI_CONFUSABLES = [
  ['rn', 'm'],
  ['vv', 'w'],
  ['cl', 'd'],
];

/**
 * Lowercase, strip accents, and replace confusable characters with the
 * ASCII letters they imitate. Used ONLY for lookalike comparison.
 */
export function normalizeConfusables(str) {
  const lowered = str.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '');
  let out = '';
  for (const ch of lowered) out += CONFUSABLES[ch] ?? ch;
  return out;
}

/**
 * Like normalizeConfusables, but also collapses multi-character visual
 * confusables (rn→m, vv→w, cl→d). Kept separate so callers can compare
 * against BOTH forms and only treat a match as a homoglyph attack when the
 * aggressive form differs from the plain one.
 */
export function normalizeConfusablesAggressive(str) {
  let out = normalizeConfusables(str);
  for (const [from, to] of MULTI_CONFUSABLES) out = out.split(from).join(to);
  return out;
}

/** True if the string mixes in Cyrillic/Greek script (classic homoglyph attack). */
export function hasMixedScript(str) {
  return CYRILLIC_OR_GREEK.test(str);
}
