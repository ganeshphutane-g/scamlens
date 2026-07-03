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

/** True if the string mixes in Cyrillic/Greek script (classic homoglyph attack). */
export function hasMixedScript(str) {
  return CYRILLIC_OR_GREEK.test(str);
}
