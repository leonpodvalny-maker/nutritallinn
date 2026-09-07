// Cloudflare Worker — the API half of the site.
// Static files are served by Cloudflare's asset handler; only these routes run here.

const PLANS = {
  '100': { amount: '100.00', name: 'Консультация по питанию' },
  '75':  { amount: '75.00',  name: 'Повторная консультация' },
  '150': { amount: '150.00', name: 'Индивидуальный рацион на 7 дней' },
};
const DEFAULT_PLAN = '100';
const isValidPlan = (plan) => Object.hasOwn(PLANS, plan);
const ORDER_TTL_SECONDS = 30 * 60;
const MAKSEKESKUS_HOST = 'payment.maksekeskus.ee';

// Express refused to boot without these; a Worker has no startup hook, so the
// handlers check before doing anything that would report a false success.
function assertMailConfig(env) {
  const missing = ['RESEND_API_KEY', 'RECIPIENT_EMAIL'].filter(k => !env[k]);
  if (missing.length) throw new Error(`Missing config: ${missing.join(', ')}`);
}

// ── MAC (Maksekeskus uses plain SHA-512 over sorted JSON + secret, not HMAC) ──

async function composeMac(data, secretKey) {
  const sorted = Object.keys(data).sort().reduce((acc, k) => { acc[k] = data[k]; return acc; }, {});
  const bytes = new TextEncoder().encode(JSON.stringify(sorted) + secretKey);
  const digest = await crypto.subtle.digest('SHA-512', bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function macEquals(expected, actual) {
  if (typeof actual !== 'string' || expected.length !== actual.length) return false;
  // Constant-time compare: XOR every char, never short-circuit.
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ actual.charCodeAt(i);
  return diff === 0;
}

// Maksekeskus documents hashing the JSON string exactly as received, while
// this code has always hashed a re-serialised sorted object. Both require the
// secret, so accepting either widens the accepted serialisation without
// weakening authentication — and avoids losing a notification to a formatting
// difference we cannot observe until a real payment arrives.
async function verifyMac(payload, secretKey, rawJson) {
  const { mac, ...data } = payload;
  if (typeof mac !== 'string') return false;

  if (macEquals(await composeMac(data, secretKey), mac)) return true;

  if (typeof rawJson === 'string') {
    const bytes = new TextEncoder().encode(rawJson + secretKey);
    const digest = await crypto.subtle.digest('SHA-512', bytes);
    const overRaw = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    if (macEquals(overRaw, mac)) return true;
  }
  return false;
}

// ── Security headers ─────────────────────────────────────────────────────────

// Carried over from the Express helmet config. 'unsafe-inline' stays because
// the pages use inline <style> and <script>; formAction lets the checkout form
// post through to the payment provider.
const SECURITY_HEADERS = {
  'content-security-policy': [
    "default-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "script-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self' https://payment.maksekeskus.ee",
  ].join('; '),
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-frame-options': 'DENY',
  'strict-transport-security': 'max-age=15552000; includeSubDomains',
};

function withSecurityHeaders(response) {
  const out = new Response(response.body, response);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) out.headers.set(name, value);
  return out;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const escHtml = (str) => String(str)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const redirect = (location) => new Response(null, { status: 302, headers: { location } });

function validateOrderFields(body) {
  const { name, surname, age, phone, email, plan } = body;
  if (typeof plan !== 'string' || !isValidPlan(plan)) return 'Invalid plan';
  if (!name || typeof name !== 'string' || !name.trim() || name.length > 100) return 'Invalid name';
  if (!surname || typeof surname !== 'string' || !surname.trim() || surname.length > 100) return 'Invalid surname';
  const ageNum = parseInt(age, 10);
  if (isNaN(ageNum) || ageNum < 16 || ageNum > 99) return 'Invalid age';
  if (!phone || typeof phone !== 'string' || phone.length > 30) return 'Invalid phone';
  if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 200) return 'Invalid email';
  for (const field of ['goal', 'expectations']) {
    const value = body[field];
    if (value !== undefined && (typeof value !== 'string' || value.length > 1000)) return `Invalid ${field}`;
  }
  return null;
}

const MAX_BODY_BYTES = 10 * 1024;

class BadRequest extends Error {}
class TooManyRequests extends Error {}

// Matches the Express limiter this replaced: 10 posts per IP per 15 minutes.
// ponytail: KV counter, not a Durable Object — approximate under a burst of
// parallel requests, which is fine for stopping a script hammering the form.
const RATE_LIMIT = { max: 10, windowSeconds: 15 * 60 };

async function enforceRateLimit(env, request, bucket) {
  const ip = request.headers.get('cf-connecting-ip');
  if (!ip) return; // no IP to key on: let it through rather than block everyone
  const key = `rl:${bucket}:${ip}`;

  let count = 0;
  try {
    count = Number(await env.ORDERS.get(key)) || 0;
  } catch (err) {
    console.error('Rate limit read failed:', err.message);
    return; // fail open: a limiter outage must not close the form
  }

  if (count >= RATE_LIMIT.max) throw new TooManyRequests('Too many requests');

  // KV allows roughly one write per second per key, and the daily free-tier
  // write quota is finite — a failed counter update must never fail the
  // request it was counting.
  try {
    await env.ORDERS.put(key, String(count + 1), { expirationTtl: RATE_LIMIT.windowSeconds });
  } catch (err) {
    console.error('Rate limit write failed:', err.message);
  }
}

async function readBody(request) {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw new BadRequest('Body too large');

  const raw = await request.arrayBuffer();
  if (raw.byteLength > MAX_BODY_BYTES) throw new BadRequest('Body too large');

  const type = request.headers.get('content-type') || '';
  const shaped = new Request(request.url, { method: 'POST', headers: request.headers, body: raw });
  try {
    if (type.includes('application/json')) return await shaped.json();
    return Object.fromEntries(await shaped.formData());
  } catch {
    throw new BadRequest('Malformed body');
  }
}

// ── Email via Resend ──────────────────────────────────────────────────────────

const row = (label, value, wrap) => value
  ? `<tr style="border-bottom:1px solid #E5E0D8;">
       <td style="padding:10px 0;color:#6B6860;width:180px;vertical-align:top;">${label}</td>
       <td style="padding:10px 0;${wrap ? 'white-space:pre-wrap;' : ''}">${escHtml(value)}</td>
     </tr>`
  : '';

async function sendMail(env, message) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ from: env.RESEND_FROM || 'onboarding@resend.dev', ...message }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res;
}

const wrapper = (title, inner) => `
  <div style="font-family:Calibri,sans-serif;max-width:600px;margin:0 auto;padding:32px;color:#1C1C1A;">
    <h2 style="color:#C8A96E;margin-bottom:24px;">${title}</h2>
    ${inner}
  </div>`;

async function sendOrderEmails(env, order, orderId) {
  const { name, surname, age, phone, email, planName, amount, goal, expectations } = order;
  await Promise.all([
    sendMail(env, {
      to: env.RECIPIENT_EMAIL,
      reply_to: email,
      subject: `Новая запись: ${planName} — ${name} ${surname}`,
      html: wrapper('Новая запись на консультацию', `
        <table style="width:100%;border-collapse:collapse;">
          ${row('Услуга', planName)}
          ${row('Сумма', `${amount} €`)}
          ${row('Имя', `${name} ${surname}`)}
          ${row('Возраст', age)}
          ${row('Телефон', phone)}
          ${row('E-mail', email)}
          ${row('Ожидаемый результат', goal, true)}
          ${row('Ожидания от работы', expectations, true)}
          ${row('Номер заказа', orderId)}
        </table>
        <p style="margin-top:32px;font-size:0.85em;color:#999;">Оплата подтверждена через Maksekeskus</p>`),
    }),
    sendMail(env, {
      to: email,
      subject: `Запись подтверждена — ${planName}`,
      html: wrapper('Спасибо за запись!', `
        <p style="margin-bottom:16px;">Здравствуйте, ${escHtml(name)}!</p>
        <p style="margin-bottom:24px;color:#6B6860;">Ваша запись на <strong style="color:#1C1C1A;">${escHtml(planName)}</strong> получена. Специалист свяжется с вами по телефону или e-mail в течение дня.</p>
        <table style="width:100%;border-collapse:collapse;">
          ${row('Услуга', planName)}
          ${row('Сумма', `${amount} €`)}
          ${row('Номер заказа', orderId)}
        </table>
        <p style="margin-top:32px;font-size:0.85em;color:#999;">Nutritallinn — нутрициолог в Таллине</p>`),
    }),
  ]);
}

// Fallback when the paid order is not in KV: only the payment provider's own
// fields are available, so write to the owner and flag what is missing.
async function sendOwnerOnlyEmail(env, order, orderId) {
  assertMailConfig(env);
  const { name, phone, planName, amount } = order;
  await sendMail(env, {
    to: env.RECIPIENT_EMAIL,
    subject: `Оплачен заказ ${orderId} — данные неполные`,
    html: wrapper('Оплата получена, но данные формы не найдены', `
      <table style="width:100%;border-collapse:collapse;">
        ${row('Номер заказа', orderId)}
        ${row('Сумма', amount ? `${amount} €` : '—')}
        ${row('Услуга', planName)}
        ${row('Имя', name)}
        ${row('Телефон', phone)}
      </table>
      <p style="margin-top:32px;color:#6B6860;">Оплата прошла, но данные формы не сохранились. Свяжитесь с клиентом по контактам из Maksekeskus.</p>`),
  });
}

async function sendSurveyEmail(env, entry) {
  const { name, surname, age, phone, email, goal, expectations } = entry;
  await sendMail(env, {
    to: env.RECIPIENT_EMAIL,
    reply_to: email,
    subject: `Анкета: ${name} ${surname}`,
    html: wrapper('Новая анкета с сайта', `
      <table style="width:100%;border-collapse:collapse;">
        ${row('Имя', `${name} ${surname}`)}
        ${row('Возраст', age)}
        ${row('Телефон', phone)}
        ${row('E-mail', email)}
        ${row('Ожидаемый результат', goal, true)}
        ${row('Ожидания от работы', expectations, true)}
      </table>
      <p style="margin-top:32px;font-size:0.85em;color:#999;">Анкета отправлена без оплаты — свяжитесь с клиентом.</p>`),
  });
}

// ── Routes ────────────────────────────────────────────────────────────────────

function robots(request, env) {
  const site = env.SITE_URL || new URL(request.url).origin;
  return new Response(
    'User-agent: *\nAllow: /\n' +
    ['/order', '/success', '/error', '/survey', '/survey-sent', '/api/', '/payment-return']
      .map(p => `Disallow: ${p}\n`).join('') +
    `\nSitemap: ${site}/sitemap.xml\n`,
    { headers: { 'content-type': 'text/plain; charset=utf-8' } }
  );
}

// Served from the Worker so the host is always the one actually in use.
function sitemap(request, env) {
  const site = env.SITE_URL || new URL(request.url).origin;
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${site}/</loc>
    <changefreq>monthly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>
`,
    { headers: { 'content-type': 'application/xml; charset=utf-8' } }
  );
}

async function handleCheckout(request, env) {
  await enforceRateLimit(env, request, 'checkout');
  const body = await readBody(request);
  if (validateOrderFields(body)) {
    const plan = isValidPlan(body.plan) ? body.plan : DEFAULT_PLAN;
    return redirect(`/order?plan=${plan}&error=1`);
  }

  const { name, surname, age, phone, email, plan, goal, expectations } = body;
  const { amount, name: planName } = PLANS[plan];
  const onError = redirect(`/error?plan=${encodeURIComponent(plan)}`);
  // Maksekeskus documents a 20-character limit on the transaction reference;
  // NTL- plus 16 hex characters fits exactly. Random bytes rather than a
  // sliced UUID, whose version nibble would cost 4 bits of entropy.
  const random = crypto.getRandomValues(new Uint8Array(8));
  const orderId = `NTL-${[...random].map(b => b.toString(16).padStart(2, '0')).join('')}`;
  const siteUrl = env.SITE_URL || new URL(request.url).origin;
  const order = { name, surname, age, phone, email, plan, planName, amount, goal, expectations };

  try {
    assertMailConfig(env);
  } catch (err) {
    console.error('Checkout blocked:', err.message);
    return onError;
  }

  // Demo mode when payment keys are absent, same as the Express version.
  if (!env.MAKSEKESKUS_SHOP_ID || !env.MAKSEKESKUS_SECRET_KEY) {
    try {
      await env.ORDERS.put(orderId, JSON.stringify(order), { expirationTtl: ORDER_TTL_SECONDS });
    } catch (err) {
      console.error('Demo order storage failed:', err.message);
      return onError;
    }
    return redirect(`/success?demo=1&orderId=${encodeURIComponent(orderId)}`);
  }

  try {
    const auth = btoa(`${env.MAKSEKESKUS_SHOP_ID}:${env.MAKSEKESKUS_SECRET_KEY}`);
  const res = await fetch('https://api.maksekeskus.ee/v1/transactions', {
    method: 'POST',
    headers: { authorization: `Basic ${auth}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      transaction: {
        amount,
        currency: 'EUR',
        reference: orderId,
        return_url: `${siteUrl}/payment-return`,
        cancel_url: `${siteUrl}/order?plan=${plan}&cancelled=1`,
        notification_url: `${siteUrl}/api/payment-notify`,
      },
      customer: { email, country: 'ee', locale: 'ru', ip: request.headers.get('cf-connecting-ip') || '127.0.0.1' },
    }),
  });

    if (!res.ok) {
      console.error('Checkout failed:', res.status, await res.text());
      return onError;
    }

    const tx = await res.json();
    const offered = (tx.payment_methods?.other || []).find(m => m.name === 'redirect')?.url;
    let paymentUrl = `https://${MAKSEKESKUS_HOST}/pay.html?trx=${tx.id}`;
    try {
      if (offered && new URL(offered).hostname === MAKSEKESKUS_HOST) paymentUrl = offered;
    } catch { /* keep the fallback */ }

    // The transaction exists by now, so a storage failure must not lose the
    // customer's details silently — log it and let the payment proceed.
    try {
      await env.ORDERS.put(orderId, JSON.stringify(order), { expirationTtl: ORDER_TTL_SECONDS });
    } catch (err) {
      console.error('Order storage failed for live transaction', orderId, err.message);
    }
    return new Response(null, { status: 303, headers: { location: paymentUrl } });
  } catch (err) {
    console.error('Checkout error:', err.message);
    return onError;
  }
}

async function handlePaymentNotify(request, env, ctx) {
  if (!env.MAKSEKESKUS_SECRET_KEY) return new Response('Configuration error', { status: 500 });
  try {
    assertMailConfig(env);
  } catch (err) {
    // Answering anything but 2xx makes Maksekeskus retry, which is what we
    // want while the mail configuration is broken.
    console.error('Payment notification blocked:', err.message);
    return new Response('Configuration error', { status: 500 });
  }

  const body = await readBody(request);
  // Maksekeskus posts the payload as a `json` form field; keep the raw string
  // so the signature can also be checked against it verbatim.
  const rawJson = typeof body.json === 'string' ? body.json : null;
  let payload;
  try {
    payload = rawJson ? JSON.parse(rawJson) : body;
  } catch {
    return new Response('Malformed payload', { status: 400 });
  }
  if (!payload || typeof payload !== 'object') return new Response('Malformed payload', { status: 400 });

  const mac = body.mac || payload.mac;
  if (!(await verifyMac({ ...payload, mac }, env.MAKSEKESKUS_SECRET_KEY, rawJson))) {
    console.warn('Invalid MAC in payment notification');
    return new Response('Invalid MAC', { status: 400 });
  }

  const orderId = payload.reference;
  if (payload.status === 'COMPLETED') {
    let stored = null;
    try {
      stored = await env.ORDERS.get(orderId, 'json');
    } catch (err) {
      console.error('Order lookup failed for', orderId, err.message);
    }

    const order = stored || {
      name: payload.customer_name || '—', surname: '', age: '—',
      phone: payload.customer_phone || '—', email: payload.customer_email || '',
      planName: payload.description || '—', amount: payload.amount,
    };

    // Without the stored order there is no verified customer address, so the
    // confirmation would bounce; notify the owner alone and say why.
    const notify = stored
      ? sendOrderEmails(env, order, orderId).then(() => env.ORDERS.delete(orderId))
      : sendOwnerOnlyEmail(env, order, orderId);

    // Answer Maksekeskus immediately; the mail can finish after the response.
    ctx.waitUntil(notify.catch(err => console.error('Order email error:', err.message)));
  }
  return new Response('OK');
}

async function handleSurvey(request, env) {
  await enforceRateLimit(env, request, 'survey');
  const body = await readBody(request);
  if (validateOrderFields({ ...body, plan: DEFAULT_PLAN })) return redirect('/survey?error=1');
  try {
    assertMailConfig(env);
    await sendSurveyEmail(env, body);
    return redirect('/survey-sent');
  } catch (err) {
    console.error('Survey email error:', err.message);
    return redirect('/survey?error=1');
  }
}

async function handleSuccess(request, env) {
  const { searchParams } = new URL(request.url);
  const orderId = searchParams.get('orderId');
  const keysConfigured = !!(env.MAKSEKESKUS_SHOP_ID && env.MAKSEKESKUS_SECRET_KEY);

  // Demo mode only — with real keys the notification hook sends the mail.
  if (searchParams.get('demo') === '1' && !keysConfigured && orderId) {
    const order = await env.ORDERS.get(orderId, 'json');
    if (order) {
      try {
        await sendOrderEmails(env, order, orderId);
        await env.ORDERS.delete(orderId); // only once the mail actually went out
      } catch (err) {
        console.error('Demo email error:', err.message);
      }
    }
  }
  return env.ASSETS.fetch(new Request(new URL('/success.html', request.url), request));
}

export default {
  async fetch(request, env, ctx) {
    // One wrapper so every response carries the headers — pages, assets,
    // redirects and error paths alike.
    return withSecurityHeaders(await route(request, env, ctx));
  },
};

async function route(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === 'POST') {
      try {
        if (pathname === '/api/checkout') return await handleCheckout(request, env);
        if (pathname === '/api/payment-notify') return await handlePaymentNotify(request, env, ctx);
        if (pathname === '/api/survey') return await handleSurvey(request, env);
      } catch (err) {
        if (err instanceof BadRequest) return new Response(err.message, { status: 400 });
        if (err instanceof TooManyRequests) {
          return new Response('Слишком много запросов. Попробуйте через 15 минут.', {
            status: 429,
            headers: { 'retry-after': String(RATE_LIMIT.windowSeconds), 'content-type': 'text/plain; charset=utf-8' },
          });
        }
        throw err;
      }
    }

    // API paths exist only for POST; say so rather than falling through to a
    // 404 from the asset handler or a page-shaped 405.
    if (pathname.startsWith('/api/')) {
      return new Response('Method Not Allowed', { status: 405, headers: { allow: 'POST' } });
    }

    // Everything below is a page or a generated file: GET/HEAD only, as the
    // Express routes were, so no side effect hangs off another method.
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method Not Allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
    }

    if (pathname === '/robots.txt') return robots(request, env);
    if (pathname === '/sitemap.xml') return sitemap(request, env);
    if (pathname === '/success') return handleSuccess(request, env);

    if (pathname === '/payment-return') {
      const status = url.searchParams.get('status');
      return status === 'COMPLETED' || status === 'SUCCESS'
        ? redirect(`/success?orderId=${encodeURIComponent(url.searchParams.get('reference') || '')}`)
        : redirect('/order?cancelled=1');
    }

    // Extensionless page routes map onto their .html files.
    const pages = { '/': '/index.html', '/order': '/order.html', '/error': '/error.html',
                    '/survey': '/survey.html', '/survey-sent': '/survey-sent.html' };
    if (pages[pathname]) {
      return env.ASSETS.fetch(new Request(new URL(pages[pathname], request.url), request));
    }

    return env.ASSETS.fetch(request);
}
