// Tell Bing (and so Copilot) that pages changed, instead of waiting to be
// crawled. IndexNow is a documented protocol Bing and Yandex both accept;
// Google has said it does not use it. Run it after a content change, not on
// a schedule — resubmitting unchanged URLs is what the protocol asks you not
// to do.
//
//   node submit-indexnow.mjs                    # the pages in the sitemap
//   node submit-indexnow.mjs /consultation      # just these
//
// The key file must stay reachable at https://<host>/<key>.txt — that is how
// the endpoint verifies the submission is ours.

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

const HOST = 'nutritallinn.fitfoodestonia.ee';
const ENDPOINT = 'https://api.indexnow.org/IndexNow';
const DEFAULT_PATHS = ['/', '/consultation'];

const candidates = (await readdir('public')).filter(f => /^[0-9a-f]{32}\.txt$/.test(f));
if (candidates.length !== 1) {
  console.error(candidates.length
    ? `Expected one IndexNow key file in public/, found ${candidates.length}: ${candidates.join(', ')}`
    : 'No IndexNow key file in public/ — expected <32 hex chars>.txt');
  process.exit(1);
}
const [keyFile] = candidates;
const key = (await readFile(join('public', keyFile), 'utf8')).trim();

// The protocol keys off the filename, so a file whose contents do not match
// its own name is rejected after the endpoint has already answered 202.
if (key !== keyFile.slice(0, -4)) {
  console.error(`${keyFile} contains "${key}" — the contents must equal the filename without .txt`);
  process.exit(1);
}

const paths = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_PATHS;
const urlList = paths.map(p => `https://${HOST}${p.startsWith('/') ? p : '/' + p}`);

// Check what the host actually serves, not just that something is there: a
// stale copy from an earlier build returns 200 and still fails validation,
// silently, well after the endpoint has answered.
const check = await fetch(`https://${HOST}/${keyFile}`);
if (!check.ok) {
  console.error(`Key file not reachable: https://${HOST}/${keyFile} returned ${check.status}`);
  console.error('Upload the cPanel build before submitting.');
  process.exit(1);
}
const served = (await check.text()).trim();
if (served !== key) {
  console.error(`https://${HOST}/${keyFile} serves "${served.slice(0, 40)}", expected "${key}"`);
  console.error('The deployed copy is stale — upload the current cPanel build.');
  process.exit(1);
}

const res = await fetch(ENDPOINT, {
  method: 'POST',
  headers: { 'content-type': 'application/json; charset=utf-8' },
  body: JSON.stringify({ host: HOST, key, keyLocation: `https://${HOST}/${keyFile}`, urlList }),
});

// 200 and 202 both mean accepted; the body is empty either way.
console.log(`${res.status} ${res.statusText}`);
for (const u of urlList) console.log('  ' + u);
if (!res.ok) {
  console.error(await res.text());
  process.exit(1);
}
