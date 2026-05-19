#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

function fail(msg) {
  process.stderr.write(`[compose-check] ${msg}\n`);
  process.exit(1);
}

const root = path.resolve(__dirname, '..');
const composePath = path.join(root, 'docker-compose.yml');
const manifestPath = path.join(root, 'umbrel-app.yml');

if (!fs.existsSync(composePath)) fail(`missing ${composePath}`);
if (!fs.existsSync(manifestPath)) fail(`missing ${manifestPath}`);

const compose = fs.readFileSync(composePath, 'utf8');
fs.readFileSync(manifestPath, 'utf8');

const webBlockMatch = compose.match(/(?:^|\n)\s{2}web:\n([\s\S]*?)(?:\n\s{2}[a-zA-Z0-9_-]+:|$)/);
if (!webBlockMatch) fail('could not find web service block in docker-compose.yml');
const webBlock = webBlockMatch[1];

const imageMatch = webBlock.match(/\s+image:\s+ghcr\.io\/miniweed\/umbrel-tunnel-web:([^\s]+)\s*(?:\n|$)/m);

if (!imageMatch) {
  fail('web service image must be ghcr.io/miniweed/umbrel-tunnel-web:<version>');
}

process.stdout.write('[compose-check] OK\n');
