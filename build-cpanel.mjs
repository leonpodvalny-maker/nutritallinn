// Builds the copy of the site that lives on cPanel, from public/.
//
// The pages there are static: their forms must post to the Worker by absolute
// URL, and Apache needs an .htaccess to serve /order as order.html. Everything
// else is copied verbatim.
//
//   node build-cpanel.mjs        → dist-cpanel/ plus dist-cpanel.zip
//
// Upload the zip through the cPanel file manager, extract, delete the zip.

import { readdir, readFile, writeFile, mkdir, copyFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { createWriteStream } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const SRC = 'public';
const OUT = 'dist-cpanel';
const API = 'https://site.nutritallinn.workers.dev';
const SITE = 'https://nutritallinn.fitfoodestonia.ee';

const HTACCESS = `# Serve /order as order.html, the way the Worker does.
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]

# www serves the same pages, so send it to the canonical host rather than
# leaving a second copy of every URL for search engines to weigh up.
RewriteCond %{HTTP_HOST} ^www\. [NC]
RewriteRule ^(.*)$ https://nutritallinn.fitfoodestonia.ee/$1 [R=301,L]

RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^([^.]+)$ $1.html [L]

<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set X-Frame-Options "DENY"
</IfModule>

ErrorDocument 404 /error.html
`;

const ROBOTS = `User-agent: *
Allow: /
Disallow: /order
Disallow: /success
Disallow: /error
Disallow: /survey
Disallow: /survey-sent

Sitemap: ${SITE}/sitemap.xml
`;

const SITEMAP = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${SITE}/</loc>
    <changefreq>monthly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>${SITE}/consultation</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>
`;

await rm(OUT, { recursive: true, force: true });
await mkdir(OUT, { recursive: true });

let rewritten = 0;
for (const name of await readdir(SRC)) {
  const from = join(SRC, name);
  const to = join(OUT, name);
  if (!name.endsWith('.html')) {
    await copyFile(from, to);
    continue;
  }
  const html = await readFile(from, 'utf8');
  // Rewriting the retired host silently is what hid a dead canonical URL in
  // the source for weeks: the built pages were right, so nothing looked wrong.
  // Fail instead, and fix it where it is written.
  if (html.includes('nutritallinn.onrender.com')) {
    console.error(`${name} still references the retired Render host — fix public/${name}`);
    process.exit(1);
  }
  const out = html.replaceAll('action="/api/', `action="${API}/api/`);
  if (out !== html) rewritten++;
  await writeFile(to, out);
}

await writeFile(join(OUT, '.htaccess'), HTACCESS);
await writeFile(join(OUT, 'robots.txt'), ROBOTS);
await writeFile(join(OUT, 'sitemap.xml'), SITEMAP);

// Fail loudly rather than shipping pages whose forms still post to a path that
// does not exist on the static host.
const forms = [];
for (const name of ['order.html', 'survey.html']) {
  const html = await readFile(join(OUT, name), 'utf8');
  for (const [, action] of html.matchAll(/action="([^"]+)"/g)) forms.push([name, action]);
}
const broken = forms.filter(([, action]) => !action.startsWith(API));
if (broken.length) {
  console.error('Form actions still relative:', broken);
  process.exit(1);
}

await promisify(execFile)('powershell', ['-NoProfile', '-Command',
  `Compress-Archive -Path '${OUT}/*' -DestinationPath '${OUT}.zip' -Force`]);

console.log(`${OUT}/ built — ${rewritten} pages rewritten, forms point at the Worker`);
for (const [page, action] of forms) console.log(`  ${page} → ${action}`);
console.log(`\nUpload ${OUT}.zip to /public_html/nutritallinn, extract, delete the zip.`);
