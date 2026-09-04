// Cloudflare Worker — the API half of the site.
// Static files are served by Cloudflare's asset handler; only these routes run here.

const PLANS = {
  '100': { amount: '100.00', name: 'Консультация по питанию' },
  '75':  { amount: '75.00',  name: 'Повторная консультация' },
  '150': { amount: '150.00', name: 'Индивидуальный рацион на 7 дней' },
};
const DEFAULT_PLAN = '100';
const ORDER_TTL_SECONDS = 30 * 60;
const MAKSEKESKUS_HOST = 'payment.maksekeskus.ee';

// ── MAC (Maksekeskus uses plain SHA-512 over sorted JSON + secret, not HMAC) ──

async function composeMac(data, secretKey) {
  const sorted = Object.keys(data).sort().reduce((acc, k) => { acc[k] = data[k]; return acc; }, {});
  const bytes = new TextEncoder().encode(JSON.stringify(sorted) + secretKey);
  const digest = await crypto.subtle.digest('SHA-512', bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function verifyMac(payload, secretKey) {
  const { mac, ...data } = payload;
  const expected = await composeMac(data, secretKey);
  const actual = mac || '';
  if (expected.length !== actual.length) return false;
  // Constant-time compare: XOR every char, never short-circuit.
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ actual.charCodeAt(i);
  return diff === 0;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const escHtml = (str) => String(str)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const redirect = (location) => new Response(null, { status: 302, headers: { location } });

function validateOrderFields(body) {
  const { name, surname, age, phone, email, plan } = body;
  if (!PLANS[plan]) return 'Invalid plan';
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

async function readBody(request) {
  const type = request.headers.get('content-type') || '';
  if (type.includes('application/json')) return await request.json();
  return Object.fromEntries(await request.formData());
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
  if (!res.ok) throw new Error(`Resend ${res.status}: ${await res.text()}`);
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
  const body = await readBody(request);
  if (validateOrderFields(body)) {
    const plan = PLANS[body.plan] ? body.plan : DEFAULT_PLAN;
    return redirect(`/order?plan=${plan}&error=1`);
  }

  const { name, surname, age, phone, email, plan, goal, expectations } = body;
  const { amount, name: planName } = PLANS[plan];
  const orderId = `NTL-${crypto.randomUUID()}`;
  const siteUrl = env.SITE_URL || new URL(request.url).origin;
  const order = { name, surname, age, phone, email, plan, planName, amount, goal, expectations };

  // Demo mode when payment keys are absent, same as the Express version.
  if (!env.MAKSEKESKUS_SHOP_ID || !env.MAKSEKESKUS_SECRET_KEY) {
    await env.ORDERS.put(orderId, JSON.stringify(order), { expirationTtl: ORDER_TTL_SECONDS });
    return redirect(`/success?demo=1&orderId=${encodeURIComponent(orderId)}`);
  }

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
    return redirect(`/error?plan=${encodeURIComponent(plan)}`);
  }

  const tx = await res.json();
  const fallback = `https://${MAKSEKESKUS_HOST}/pay.html?trx=${tx.id}`;
  const offered = (tx.payment_methods?.other || []).find(m => m.name === 'redirect')?.url;
  let paymentUrl = fallback;
  try {
    if (offered && new URL(offered).hostname === MAKSEKESKUS_HOST) paymentUrl = offered;
  } catch { /* keep the fallback */ }

  await env.ORDERS.put(orderId, JSON.stringify(order), { expirationTtl: ORDER_TTL_SECONDS });
  return new Response(null, { status: 303, headers: { location: paymentUrl } });
}

async function handlePaymentNotify(request, env, ctx) {
  if (!env.MAKSEKESKUS_SECRET_KEY) return new Response('Configuration error', { status: 500 });

  const body = await readBody(request);
  // Maksekeskus posts the payload as a `json` form field.
  const payload = typeof body.json === 'string' ? JSON.parse(body.json) : body;
  const mac = body.mac || payload.mac;

  if (!(await verifyMac({ ...payload, mac }, env.MAKSEKESKUS_SECRET_KEY))) {
    console.warn('Invalid MAC in payment notification');
    return new Response('Invalid MAC', { status: 400 });
  }

  const orderId = payload.reference;
  if (payload.status === 'COMPLETED') {
    const stored = await env.ORDERS.get(orderId, 'json');
    const order = stored || {
      name: payload.customer_name || '—', surname: '', age: '—',
      phone: payload.customer_phone || '—', email: payload.customer_email || '—',
      planName: payload.description || '—', amount: payload.amount,
    };
    // Answer Maksekeskus immediately; the mail can finish after the response.
    ctx.waitUntil(
      sendOrderEmails(env, order, orderId)
        .then(() => env.ORDERS.delete(orderId))
        .catch(err => console.error('Order email error:', err.message))
    );
  }
  return new Response('OK');
}

async function handleSurvey(request, env) {
  const body = await readBody(request);
  if (validateOrderFields({ ...body, plan: DEFAULT_PLAN })) return redirect('/survey?error=1');
  try {
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
      await sendOrderEmails(env, order, orderId).catch(err => console.error('Demo email error:', err.message));
      await env.ORDERS.delete(orderId);
    }
  }
  return env.ASSETS.fetch(new Request(new URL('/success.html', request.url), request));
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === 'POST') {
      if (pathname === '/api/checkout') return handleCheckout(request, env);
      if (pathname === '/api/payment-notify') return handlePaymentNotify(request, env, ctx);
      if (pathname === '/api/survey') return handleSurvey(request, env);
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
  },
};
