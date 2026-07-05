#!/usr/bin/env node
// ScamLens CLI: scamlens "<message>"  |  echo "<message>" | scamlens
// Flags: --json (machine-readable), --no-color, --ai (AI second opinion)
//
// The rule engine always runs offline. --ai additionally consults an LLM:
// a local Ollama server if one is running (private), otherwise the
// Anthropic API when ANTHROPIC_API_KEY is set (the message is sent to
// Anthropic in that case — the CLI says so before doing it).

import { analyze, LEVELS } from '../src/engine.js';
import { aiSecondOpinion, ollamaAvailable, DEFAULT_OLLAMA_URL } from '../src/ai.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
const useAi = args.includes('--ai');
const noColor = args.includes('--no-color') || !process.stdout.isTTY;
const positional = args.filter(a => !a.startsWith('--'));

function paint(code, s) {
  return noColor ? s : `[${code}m${s}[0m`;
}
const LEVEL_COLOR = { low: '32', medium: '33', high: '31', critical: '41;97' };
// Fail loud (not silently uncolored) if engine.js's levels and this map
// ever drift apart — see also the .badge/.meter CSS classes in web/index.html,
// which must be kept in sync with LEVELS by hand (CSS can't import JS).
for (const level of LEVELS) {
  if (!(level in LEVEL_COLOR)) throw new Error(`bin/cli.js: LEVEL_COLOR is missing an entry for level "${level}"`);
}

async function readStdin() {
  let data = '';
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

const text = positional.length > 0 ? positional.join(' ')
  : !process.stdin.isTTY ? await readStdin()
  : null;

if (text === null || !text.trim()) {
  console.error('Usage: scamlens "<suspicious message or link>"');
  console.error('       echo "<message>" | scamlens');
  console.error('Flags: --json  --no-color  --ai');
  console.error('');
  console.error('--ai asks an AI model for a second opinion after the offline check:');
  console.error('  * uses a local Ollama server if running (private, nothing leaves your machine)');
  console.error('  * else uses the Anthropic API if ANTHROPIC_API_KEY is set (message is sent to Anthropic)');
  console.error('  Env: SCAMLENS_AI_MODEL to override the model, OLLAMA_URL for a non-default Ollama.');
  process.exit(2);
}

const report = analyze(text);

let ai = null;
let aiError = null;
if (useAi) {
  const ollamaUrl = process.env.OLLAMA_URL || DEFAULT_OLLAMA_URL;
  try {
    if (await ollamaAvailable(ollamaUrl)) {
      ai = await aiSecondOpinion(text, report, {
        backend: 'ollama',
        ollamaUrl,
        model: process.env.SCAMLENS_AI_MODEL
      });
    } else if (process.env.ANTHROPIC_API_KEY) {
      if (!json) console.error(paint('2', 'No local Ollama found — sending the message to the Anthropic API (your key, your account)...'));
      ai = await aiSecondOpinion(text, report, {
        backend: 'claude',
        apiKey: process.env.ANTHROPIC_API_KEY,
        model: process.env.SCAMLENS_AI_MODEL
      });
    } else {
      aiError = 'No AI backend available. Run a local Ollama (https://ollama.com) for a private check, or set ANTHROPIC_API_KEY.';
    }
  } catch (err) {
    aiError = err.message;
  }
}

if (json) {
  console.log(JSON.stringify({ ...report, ai, aiError }, null, 2));
  process.exit(0);
}

const badge = ` ${report.level.toUpperCase()} RISK — ${report.score}/100 `;
console.log('');
console.log(paint(LEVEL_COLOR[report.level], badge));
console.log('');
console.log(report.summary);

if (report.signals.length > 0) {
  console.log('');
  console.log(paint('1', `Red flags found (${report.signals.length}):`));
  for (const s of report.signals) {
    console.log(`  ${paint('31', '⚑')} ${paint('1', s.title)}`);
    console.log(`     ${s.detail}`);
    if (s.evidence) console.log(`     ${paint('2', `matched: “${s.evidence}”`)}`);
  }
}

if (report.advice.length > 0) {
  console.log('');
  console.log(paint('1', 'What to do:'));
  for (const a of report.advice) console.log(`  ${paint('32', '✓')} ${a}`);
}

if (useAi) {
  console.log('');
  console.log(paint('1', 'AI second opinion:'));
  if (ai) {
    const verdictColor = ai.verdict === 'scam' ? '31' : ai.verdict === 'suspicious' ? '33' : '32';
    const label = ai.verdict.replace('_', ' ').toUpperCase();
    console.log(`  ${paint(verdictColor, label)} (confidence ${ai.confidence}/100${ai.scam_type ? `, looks like: ${ai.scam_type}` : ''})`);
    if (ai.explanation) console.log(`  ${ai.explanation}`);
    if (ai.advice) console.log(`  ${paint('32', '✓')} ${ai.advice}`);
    console.log(paint('2', `  (${ai.backend === 'ollama' ? `local model ${ai.model} via Ollama — message stayed on this machine` : `Anthropic ${ai.model}`})`));
  } else {
    console.log(`  ${paint('33', 'unavailable:')} ${aiError}`);
  }
}
console.log('');
