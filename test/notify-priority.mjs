// The owner's mail decides whether a paid booking was seen; the customer's is
// a courtesy. Getting that order wrong is silent and expensive — a bad
// customer address would fail the notification, and the retry would send the
// owner a second copy of a booking already in their inbox.
//
// This drives the real sendOrderEmails through a stubbed fetch, so a change to
// the function breaks the test rather than leaving it agreeing with a copy of
// logic that no longer runs.
//
//   node test/notify-priority.mjs

import assert from 'node:assert';
import { readFile } from 'node:fs/promises';

const src = await readFile(new URL('../src/index.js', import.meta.url), 'utf8');

// The Worker has no exports, so lift the function under test out of the file.
// Crude, but it beats testing a hand-copied paraphrase of it.
const cut = (name) => {
  const start = src.indexOf(`async function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found — did it get renamed?`);
  let depth = 0, i = src.indexOf('{', start);
  for (let j = i; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}' && --depth === 0) return src.slice(start, j + 1);
  }
  throw new Error(`unbalanced braces in ${name}`);
};

const { sendOrderEmails } = await import(
  'data:text/javascript;base64,' + Buffer.from(
    `${cut('sendMail')}\n${cut('sendOrderEmails')}\n` +
    // Presentation helpers the mails call; irrelevant to delivery order.
    'const wrapper = (t, b) => b;\n' +
    'const row = (k, v) => `${k}:${v}`;\n' +
    'const escHtml = (s) => String(s);\n' +
    'export { sendOrderEmails };'
  ).toString('base64')
);

const ORDER = {
  name: 'Test', surname: 'Case', age: '40', phone: '+372',
  email: 'customer@example.com', planName: 'Повторная консультация', amount: '75.00',
};
const ENV = { RESEND_API_KEY: 'k', RECIPIENT_EMAIL: 'owner@example.com', RESEND_FROM: 'x@y.ee' };

// Stub Resend: fail whichever recipient the case names, record the order sent.
function stubFetch({ failOwner = false, failCustomer = false, stallCustomer = false }) {
  const sent = [];
  globalThis.fetch = async (_url, init) => {
    const to = JSON.parse(init.body).to;
    sent.push(to);
    // A customer request that never settles — the case the split exists for.
    if (to === ORDER.email && stallCustomer) await new Promise(() => {});
    const bad = (to === ENV.RECIPIENT_EMAIL && failOwner) || (to === ORDER.email && failCustomer);
    return bad
      ? new Response('{"message":"rejected"}', { status: 422 })
      : new Response('{"id":"1"}', { status: 200 });
  };
  return sent;
}

const run = async (opts) => {
  const sent = stubFetch(opts);
  let threw = null;
  try { await sendOrderEmails(ENV, ORDER, 'NTL-test'); } catch (err) { threw = err; }
  return { sent, threw };
};

// 1. Both fine: owner first, then customer.
{
  const { sent, threw } = await run({});
  assert.strictEqual(threw, null, 'should not throw when both succeed');
  assert.deepStrictEqual(sent, [ENV.RECIPIENT_EMAIL, ORDER.email], 'owner must be mailed first');
  console.log('ok  both sent, owner first');
}

// 2. Customer address bad: the booking is still safely delivered, so no retry.
{
  const { sent, threw } = await run({ failCustomer: true });
  assert.strictEqual(threw, null, 'a bad customer address must not fail the notification');
  assert.deepStrictEqual(sent, [ENV.RECIPIENT_EMAIL, ORDER.email]);
  console.log('ok  customer failed, notification still succeeds');
}

// 3. Owner mail fails: must throw, and must not have mailed the customer —
//    otherwise the retry sends them a duplicate confirmation.
{
  const { sent, threw } = await run({ failOwner: true });
  assert.ok(threw, 'owner failure must throw so the provider retries');
  assert.deepStrictEqual(sent, [ENV.RECIPIENT_EMAIL], 'customer must not be mailed after an owner failure');
  console.log('ok  owner failed, throws and customer untouched');
}

// 4. The customer request never settles. sendOrderEmails must still resolve:
//    the owner has the booking, and holding the response open for a courtesy
//    mail is what lets the provider retry and mail the owner a second time.
{
  stubFetch({ stallCustomer: true });
  // Race the call itself, not a wrapper around it: awaiting the wrapper would
  // report "resolved" for a call that is still hanging inside.
  let timer;
  const settled = await Promise.race([
    sendOrderEmails(ENV, ORDER, 'NTL-test').then(() => 'resolved', () => 'threw'),
    new Promise(r => { timer = setTimeout(() => r('hung'), 1000); }),
  ]);
  clearTimeout(timer);
  assert.strictEqual(settled, 'resolved', 'a stalled customer send must not block the caller');
  console.log('ok  customer send stalls, caller is not blocked');
  // The stalled fetch is still pending and would keep the process alive.
  process.exitCode = 0;
}

console.log('\nowner mail decides the retry; a retry cannot duplicate the customer mail,');
console.log('and a stalled confirmation cannot delay the answer to the provider');
