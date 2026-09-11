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

const keyFile = (await readdir('public')).find(f => /^[0-9a-f]{32}\.txt$/.test(f));
if (!keyFile) {
  console.error('No IndexNow key file in public/ — expected <32 hex chars>.txt');
  process.exit(1);
}
const key = (await readFile(join('public', keyFile), 'utf8')).trim();

const paths = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_PATHS;
const urlList = paths.map(p => `https://${HOST}${p.startsWith('/') ? p : '/' + p}`);

// Verify the key is actually served before submitting: a 404 here is the most
// common reason a submission is rejected, and the endpoint's own error is terse.
const check = await fetch(`https://${HOST}/${keyFile}`);
if (!check.ok) {
  console.error(`Key file not reachable: https://${HOST}/${keyFile} returned ${check.status}`);
  console.error('Upload the cPanel build before submitting.');
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
