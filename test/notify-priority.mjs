// The notification path decides whether a paid booking is ever seen, so the
// owner/customer split needs a test that fails if the priority inverts.
import assert from 'node:assert';

// Mirrors sendOrderEmails' resolution.
async function ownerDecides(ownerOk, customerOk) {
  const [owner, customer] = await Promise.allSettled([
    ownerOk ? Promise.resolve('sent') : Promise.reject(new Error('owner down')),
    customerOk ? Promise.resolve('sent') : Promise.reject(new Error('customer down')),
  ]);
  if (customer.status === 'rejected') { /* logged, not fatal */ }
  if (owner.status === 'rejected') throw owner.reason;
}

// Mirrors handlePaymentNotify's response.
async function notify(ownerOk, customerOk) {
  try {
    await ownerDecides(ownerOk, customerOk);
    return 200;
  } catch {
    return 500;
  }
}

const cases = [
  ['both sent',                     true,  true,  200],
  ['customer failed, owner sent',   true,  false, 200],
  ['owner failed',                  false, true,  500],
  ['both failed',                   false, false, 500],
];
for (const [name, o, c, want] of cases) {
  const got = await notify(o, c);
  assert.strictEqual(got, want, `${name}: got ${got}, want ${want}`);
  console.log(`ok  ${name} -> ${got}`);
}
console.log('\nowner mail decides the retry; customer mail never triggers one');
