#!/usr/bin/env node
// Zero-dependency static file server for the web UI. Needed because
// browsers block `<script type="module">` imports over file:// via CORS —
// this serves web/ and src/ over http://localhost so ES modules load.

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, extname, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(fileURLToPath(import.meta.url), '..', '..');
const PORT = Number(process.env.PORT) || 4173;
const HOST = '127.0.0.1'; // loopback only — this is a privacy tool; never expose it to the LAN

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8'
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    let path = decodeURIComponent(url.pathname);
    if (path === '/') path = '/web/index.html';

    const resolved = normalize(join(ROOT, path));
    // Must be ROOT itself or a real path *inside* ROOT — a plain string
    // prefix check would wrongly admit a sibling like "ROOT-secrets".
    if (resolved !== ROOT && !resolved.startsWith(ROOT + sep)) {
      res.writeHead(403).end('Forbidden');
      return;
    }

    const info = await stat(resolved);
    if (!info.isFile()) throw new Error('not a file');

    const body = await readFile(resolved);
    res.writeHead(200, { 'Content-Type': MIME[extname(resolved)] || 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  }
});

server.listen(PORT, HOST, () => {
  console.log(`ScamLens web UI running at http://localhost:${PORT} (loopback-only — not reachable from your network)`);
  console.log('Press Ctrl+C to stop. Nothing you type is ever sent over the network.');
});
