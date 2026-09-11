// The pages shipped phone-camera JPEGs — one of them 2048px wide for an 88px
// avatar, nearly a megabyte of photos in all. This re-encodes each at the size
// it is actually displayed at; the originals live in originals/, untracked and
// never deployed.
//
//   node optimize-images.mjs
import sharp from 'sharp';
import { stat } from 'node:fs/promises';

const JOBS = [
  // hero: full-bleed portrait, the LCP image
  { from: 'originals/IMG-20260502-WA0003.jpg', to: 'public/hero.webp',    width: 900 },
  // about: same treatment, appears lower
  { from: 'originals/IMG-20260502-WA0000.jpg', to: 'public/about.webp',   width: 900 },
  // process: sticky column, never wider than half the viewport
  { from: 'originals/IMG-20260502-WA0007.jpg', to: 'public/process.webp', width: 800 },
  // quote avatar: rendered at 88px, so 176 covers 2x screens
  // quote avatar: a round 88px crop, so square at 2x. The source is a wide
  // shot with the face left of centre, so crop to the face rather than to the
  // frame — "top" would land on the handrail behind her.
  { from: 'originals/IMG-20260502-WA0014.jpg', to: 'public/avatar.webp', width: 176,
    crop: { left: 620, top: 120, width: 560, height: 560 } },
];

let before = 0, after = 0;
for (const { from, to, width, crop } of JOBS) {
  const img = crop
    ? sharp(from).extract(crop).resize({ width, height: width })
    : sharp(from).resize({ width, withoutEnlargement: true });
  await img.webp({ quality: 82 }).toFile(to);
  const b = (await stat(from)).size, a = (await stat(to)).size;
  before += b; after += a;
  const meta = await sharp(to).metadata();
  console.log(`${to.padEnd(22)} ${meta.width}x${meta.height}  ${b} -> ${a} bytes  (-${Math.round((1-a/b)*100)}%)`);
}
console.log(`\ntotal ${before} -> ${after} bytes, saved ${Math.round((1-after/before)*100)}%`);
