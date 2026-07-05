// Tests for the optional AI second-opinion module. All network calls are
// mocked — CI must never hit a real API or require a local model.

import test from 'node:test';
import assert from 'node:assert/strict';
import { aiSecondOpinion, parseVerdict, ollamaAvailable, VERDICTS, DEFAULT_CLAUDE_MODEL } from '../src/ai.js';

const GOOD_JSON = JSON.stringify({
  verdict: 'scam',
  confidence: 92,
  scam_type: 'digital arrest',
  explanation: 'This message impersonates police and demands money.',
  advice: 'Hang up and call your local police directly.'
});

function mockFetch(handler) {
  return async (url, init) => handler(url, init);
}

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body
  };
}

test('parseVerdict: accepts a clean JSON string', () => {
  const v = parseVerdict(GOOD_JSON);
  assert.equal(v.verdict, 'scam');
  assert.equal(v.confidence, 92);
  assert.equal(v.scam_type, 'digital arrest');
});

test('parseVerdict: tolerates prose/code-fence wrapping', () => {
  const v = parseVerdict('Here is my analysis:\n```json\n' + GOOD_JSON + '\n```\nHope that helps!');
  assert.equal(v.verdict, 'scam');
});

test('parseVerdict: clamps and defaults bad fields instead of trusting the model', () => {
  const v = parseVerdict(JSON.stringify({ verdict: 'DEFINITELY_SAFE_TRUST_ME', confidence: 900, scam_type: '', explanation: 42 }));
  assert.equal(v.verdict, 'unclear'); // unknown verdicts degrade to unclear, never to safe
  assert.equal(v.confidence, 100);    // clamped
  assert.equal(v.scam_type, null);
  assert.equal(v.explanation, '');
});

test('parseVerdict: throws on non-JSON garbage', () => {
  assert.throws(() => parseVerdict('the model rambled with no JSON at all'));
});

test('claude backend: sends key, model, schema, and browser header when asked', async () => {
  let captured;
  const fetchFn = mockFetch((url, init) => {
    captured = { url, init };
    return jsonResponse({ stop_reason: 'end_turn', content: [{ type: 'text', text: GOOD_JSON }] });
  });

  const result = await aiSecondOpinion('You won a lottery, send fees', { level: 'high', score: 60, signals: [{ id: 'prize' }] },
    { backend: 'claude', apiKey: 'sk-test', inBrowser: true, fetchFn });

  assert.equal(result.verdict, 'scam');
  assert.equal(result.backend, 'claude');
  assert.equal(result.model, DEFAULT_CLAUDE_MODEL);
  assert.equal(captured.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(captured.init.headers['x-api-key'], 'sk-test');
  assert.equal(captured.init.headers['anthropic-dangerous-direct-browser-access'], 'true');
  const body = JSON.parse(captured.init.body);
  assert.equal(body.model, DEFAULT_CLAUDE_MODEL);
  assert.equal(body.output_config.format.type, 'json_schema');
  assert.ok(body.messages[0].content.includes('prize')); // rule signals passed as context
  assert.ok(body.messages[0].content.includes('You won a lottery'));
});

test('claude backend: refusal stop_reason becomes a clear error, not a crash', async () => {
  const fetchFn = mockFetch(() => jsonResponse({ stop_reason: 'refusal', content: [] }));
  await assert.rejects(
    aiSecondOpinion('test', null, { backend: 'claude', apiKey: 'k', fetchFn }),
    /declined/
  );
});

test('claude backend: HTTP error surfaces status', async () => {
  const fetchFn = mockFetch(() => jsonResponse({ error: { message: 'invalid x-api-key' } }, 401));
  await assert.rejects(
    aiSecondOpinion('test', null, { backend: 'claude', apiKey: 'bad', fetchFn }),
    /401/
  );
});

test('ollama backend: posts to /api/chat with schema format and parses reply', async () => {
  let captured;
  const fetchFn = mockFetch((url, init) => {
    captured = { url, init };
    return jsonResponse({ message: { role: 'assistant', content: GOOD_JSON } });
  });

  const result = await aiSecondOpinion('suspicious text', null, { backend: 'ollama', fetchFn });
  assert.equal(result.backend, 'ollama');
  assert.equal(result.verdict, 'scam');
  assert.ok(captured.url.endsWith('/api/chat'));
  const body = JSON.parse(captured.init.body);
  assert.equal(body.stream, false);
  assert.equal(typeof body.format, 'object'); // JSON-schema structured output
});

test('missing/unknown backend is an explicit error (privacy choice is never implicit)', async () => {
  await assert.rejects(aiSecondOpinion('text', null, {}), /Unknown AI backend/);
  await assert.rejects(aiSecondOpinion('text', null, { backend: 'claude' }), /API key/);
});

test('ollamaAvailable: false when unreachable', async () => {
  const fetchFn = mockFetch(() => { throw new Error('ECONNREFUSED'); });
  assert.equal(await ollamaAvailable('http://localhost:11434', fetchFn), false);
});

test('VERDICTS never includes an unqualified "safe"', () => {
  assert.ok(!VERDICTS.includes('safe'));
  assert.ok(VERDICTS.includes('likely_safe'));
});
