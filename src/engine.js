// ScamLens core engine: turns a message into a scored, explained risk report.
// Pure functions, zero dependencies, runs identically in Node and browsers.

import { CONTENT_PATTERNS, COMBOS, ADVICE } from './data/patterns.js';
import { analyzeUrls } from './urls.js';

export const LEVELS = ['low', 'medium', 'high', 'critical'];

function contentSignals(text) {
  const signals = [];
  for (const p of CONTENT_PATTERNS) {
    for (const re of p.re) {
      const match = text.match(re);
      if (match) {
        signals.push({
          id: p.id, category: p.category, weight: p.weight,
          title: p.title, detail: p.detail,
          evidence: match[0].trim().slice(0, 120)
        });
        break; // one hit per pattern
      }
    }
  }
  return signals;
}

function comboSignals(signals, urlFlagged) {
  const present = new Set(signals.map(s => s.category));
  const out = [];
  for (const combo of COMBOS) {
    const categoriesMet = combo.categories.every(c => present.has(c));
    const urlMet = combo.needsUrlFlag ? urlFlagged : true;
    if (categoriesMet && urlMet) {
      out.push({
        id: combo.id, category: 'combo', weight: combo.weight,
        title: combo.title, detail: combo.detail, evidence: null
      });
    }
  }
  return out;
}

function levelFor(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

// Minimum weight of a single signal (or of every category a combo
// requires — combos are always gated on categories carrying at least this
// weight already, see COMBOS/CONTENT_PATTERNS) that counts as real
// evidence, not just noise. Without this, three unrelated weak signals
// (e.g. a "click here" link + a deadline + a WhatsApp number — plausible
// in an ordinary marketing email) can stack past "medium" under the
// saturation curve even though none of them, alone or combined, resembles
// a specific scam script.
const STRONG_SIGNAL_WEIGHT = 18;

const LEVEL_SUMMARY = {
  low: 'No strong scam signals detected. Stay alert — absence of red flags is not proof of safety, especially for requests involving money or personal data.',
  medium: 'Some caution signals present. Verify through official channels before acting on this message.',
  high: 'Multiple scam patterns detected. Do not click links, share codes, or send money based on this message.',
  critical: 'This message matches known scam playbooks. Do not respond, click, pay, or share anything. Warn the sender\'s other contacts if it came from a known person (their account may be compromised).'
};

/**
 * Analyze a message.
 * @param {string} text - the suspicious message, email, or link
 * @returns {{score:number, level:string, summary:string, signals:Array,
 *            urls:Array, advice:string[]}}
 */
export function analyze(text) {
  // Cap length first (DoS bound), then collapse all whitespace — including
  // newlines — to single spaces. Real scam SMS/emails are heavily
  // line-broken, and several patterns bridge cue phrases across a sentence
  // with ".{0,N}"; since "." never matches "\n", a line break between the
  // cues would otherwise silently drop the whole match (false "safe").
  const input = String(text ?? '').slice(0, 50_000).replace(/\s+/g, ' ').trim();
  if (!input) {
    return { score: 0, level: 'low', summary: 'Nothing to analyze.', signals: [], urls: [], advice: [] };
  }

  const urls = analyzeUrls(input);
  const urlSignals = [];
  const seen = new Set();
  for (const u of urls) {
    for (const f of u.flags) {
      const key = `${f.id}|${u.registrable}`;
      if (!seen.has(key)) {
        seen.add(key);
        urlSignals.push(f);
      }
    }
  }

  const content = contentSignals(input);
  const strongUrlFlag = urlSignals.some(s => s.weight >= 25);
  const combos = comboSignals(content, strongUrlFlag);

  const signals = [...urlSignals, ...content, ...combos]
    .sort((a, b) => b.weight - a.weight);

  const raw = signals.reduce((sum, s) => sum + s.weight, 0);
  // Soft saturation: single weak signals stay low; stacked independent
  // signals approach 100 without any one category dominating.
  const score = Math.round(100 * (1 - Math.exp(-raw / 45)));
  let level = levelFor(score);
  // "high"/"critical" require at least one genuinely strong signal, not
  // just several weak ones stacking under the saturation curve.
  const hasStrongAnchor = signals.some(s => s.weight >= STRONG_SIGNAL_WEIGHT);
  if ((level === 'high' || level === 'critical') && !hasStrongAnchor) level = 'medium';

  const adviceKeys = new Set(signals.map(s => s.category === 'combo' ? null : s.category).filter(Boolean));
  if (urlSignals.length > 0) adviceKeys.add('url');
  const advice = [...adviceKeys].map(k => ADVICE[k]).filter(Boolean);

  return { score, level, summary: LEVEL_SUMMARY[level], signals, urls, advice };
}
