#!/usr/bin/env node
// ScamLens CLI: scamlens "<message>"  |  echo "<message>" | scamlens
// Flags: --json (machine-readable), --no-color

import { analyze, LEVELS } from '../src/engine.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
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
  console.error('Flags: --json  --no-color');
  process.exit(2);
}

const report = analyze(text);

if (json) {
  console.log(JSON.stringify(report, null, 2));
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
console.log('');
