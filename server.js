require('dotenv').config();
const express = require('express');
const crypto  = require('crypto');
const axios   = require('axios');
const { Resend } = require('resend');
const path    = require('path');
const helmet  = require('helmet');
const rateLimit = require('express-rate-limit');

const app    = express();
const resend = new Resend(process.env.RESEND_API_KEY);

const RECIPIENT_EMAIL = process.env.RECIPIENT_EMAIL;
if (!RECIPIENT_EMAIL) {
  console.error('FATAL: RECIPIENT_EMAIL env var is not set');
  process.exit(1);
}
if (!process.env.RESEND_API_KEY) {
  console.error('FATAL: RESEND_API_KEY env var is not set');
  process.exit(1);
}
const VALID_PLANS = new Set(['50', '175']);

// ── Security middleware ───────────────────────────────────────────────────────

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
      scriptSrc:  ["'self'"],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc:   ["'none'"],
      objectSrc:  ["'none'"],
    },
  },
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please try again later.',
}));

const checkoutLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please try again later.',
});

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory order store — entries expire after 30 minutes
const pendingOrders = {};
const ORDER_TTL_MS = 30 * 60 * 1000;

function storePendingOrder(orderId, data) {
  pendingOrders[orderId] = data;
  setTimeout(() => delete pendingOrders[orderId], ORDER_TTL_MS);
}

// ── MAC helpers (Maksekeskus uses SHA-512, not HMAC) ─────────────────────────

function composeMac(data, secretKey) {
  const sorted  = Object.keys(data).sort().reduce((acc, k) => { acc[k] = data[k]; return acc; }, {});
  const jsonStr = JSON.stringify(sorted);
  return crypto.createHash('sha512').update(jsonStr + secretKey).digest('hex').toUpperCase();
}

function verifyMac(payload, secretKey) {
  const { mac, ...data } = payload;
  const expected = composeMac(data, secretKey);
  const actual   = mac || '';
  // Timing-safe comparison (pad to same length first)
  const a = Buffer.from(expected.padEnd(256));
  const b = Buffer.from(actual.padEnd(256));
  return expected.length === actual.length && crypto.timingSafeEqual(a, b);
}

// ── HTML escaping for email template ─────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Input validation helper ───────────────────────────────────────────────────

function validateOrderFields(body) {
  const { name, surname, age, phone, email, plan } = body;
  if (!VALID_PLANS.has(plan)) return 'Invalid plan';
  if (!name || typeof name !== 'string' || name.trim().length < 1 || name.length > 100) return 'Invalid name';
  if (!surname || typeof surname !== 'string' || surname.trim().length < 1 || surname.length > 100) return 'Invalid surname';
  const ageNum = parseInt(age, 10);
  if (isNaN(ageNum) || ageNum < 16 || ageNum > 99) return 'Invalid age';
  if (!phone || typeof phone !== 'string' || phone.length > 30) return 'Invalid phone';
  if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 200) return 'Invalid email';
  return null;
}

// ── Static pages ─────────────────────────────────────────────────────────────

app.get('/',        (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/order',   (req, res) => res.sendFile(path.join(__dirname, 'order.html')));
app.get('/success', async (req, res) => {
  const { demo, name, surname, age, phone, email, plan, orderId } = req.query;

  // Demo mode only allowed when payment keys are not configured
  const keysConfigured = !!(process.env.MAKSEKESKUS_SHOP_ID && process.env.MAKSEKESKUS_SECRET_KEY);
  if (demo === '1' && !keysConfigured) {
    if (!VALID_PLANS.has(plan)) return res.redirect('/');
    const planName = plan === '175' ? 'Месячное ведение (4 недели)' : 'Консультация по питанию';
    const safeOrder = {
      name:     String(name || '').slice(0, 100),
      surname:  String(surname || '').slice(0, 100),
      age:      String(age || '').slice(0, 3),
      phone:    String(phone || '').slice(0, 30),
      email:    String(email || '').slice(0, 200),
      planName,
      amount:   plan,
    };
    await sendEmail(safeOrder, String(orderId || '').slice(0, 50));
  }
  res.sendFile(path.join(__dirname, 'success.html'));
});

// ── Checkout: form → Maksekeskus transaction ──────────────────────────────────

app.post('/api/checkout', checkoutLimiter, async (req, res) => {
  const validationError = validateOrderFields(req.body);
  if (validationError) {
    const plan = req.body.plan && VALID_PLANS.has(req.body.plan) ? req.body.plan : '50';
    return res.redirect(`/order?plan=${plan}&error=1`);
  }

  const { name, surname, age, phone, email, plan } = req.body;
  const rawIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const customerIp = /^[\d.:\w]+$/.test(rawIp) ? rawIp : '127.0.0.1';

  const amount   = plan === '175' ? '175.00' : '50.00';
  const planName = plan === '175' ? 'Месячное ведение (4 недели)' : 'Консультация по питанию';
  const orderId  = `NTL-${crypto.randomUUID()}`;
  const siteUrl  = process.env.SITE_URL || 'http://localhost:3000';

  // Demo mode if keys not set
  if (!process.env.MAKSEKESKUS_SHOP_ID || !process.env.MAKSEKESKUS_SECRET_KEY) {
    const params = new URLSearchParams({ name, surname, age, phone, email, plan, orderId, demo: '1' });
    return res.redirect(`/success?${params}`);
  }

  try {
    const shopId    = process.env.MAKSEKESKUS_SHOP_ID;
    const secretKey = process.env.MAKSEKESKUS_SECRET_KEY;
    const apiBase   = 'https://api.maksekeskus.ee';

    const txData = {
      transaction: {
        amount,
        currency:  'EUR',
        reference: orderId,
      },
      customer: {
        email,
        country: 'ee',
        locale:  'ru',
        ip:      customerIp,
      },
    };

    console.log('Creating transaction for order:', orderId);

    const txResponse = await axios.post(
      `${apiBase}/v1/transactions`,
      txData,
      {
        auth:    { username: shopId, password: secretKey },
        headers: { 'Content-Type': 'application/json' },
        timeout: 10000,
      }
    );

    const txId = txResponse.data.id;
    console.log('Transaction created:', txId);

    const redirectMethod = (txResponse.data.payment_methods?.other || []).find(m => m.name === 'redirect');
    const paymentUrl = redirectMethod?.url || `https://payment.maksekeskus.ee/pay.html?trx=${txId}`;

    storePendingOrder(orderId, { name, surname, age, phone, email, plan, planName, amount });
    res.redirect(paymentUrl);

  } catch (err) {
    console.error('Checkout error status:', err.response?.status);
    console.error('Checkout error:', err.response?.data ? JSON.stringify(err.response.data) : err.message);
    res.status(500).send(`
      <p style="font-family:sans-serif;padding:2rem;max-width:600px;">
        Ошибка при создании платежа. Пожалуйста, попробуйте ещё раз.<br><br>
        <a href="/order?plan=${encodeURIComponent(plan)}">← Попробуйте ещё раз</a>
      </p>
    `);
  }
});

// ── Maksekeskus server-to-server notification ─────────────────────────────────

app.post('/api/payment-notify', async (req, res) => {
  const secretKey = process.env.MAKSEKESKUS_SECRET_KEY;

  if (!secretKey) {
    console.warn('Payment notification received but secret key not configured');
    return res.status(500).send('Configuration error');
  }

  if (!verifyMac(req.body, secretKey)) {
    console.warn('Invalid MAC in payment notification');
    return res.status(400).send('Invalid MAC');
  }

  const { reference: orderId, status } = req.body;
  console.log(`Payment notification: orderId=${orderId} status=${status}`);

  if (status === 'COMPLETED') {
    const order = pendingOrders[orderId] || {
      name:     req.body.customer_name || '—',
      surname:  '',
      age:      '—',
      phone:    req.body.customer_phone || '—',
      email:    req.body.customer_email || '—',
      planName: req.body.description || '—',
      amount:   req.body.amount,
    };
    await sendEmail(order, orderId);
    delete pendingOrders[orderId];
  }

  res.send('OK');
});

// ── Browser return after payment ──────────────────────────────────────────────

app.get('/payment-return', (req, res) => {
  const { reference, status } = req.query;
  if (status === 'COMPLETED' || status === 'SUCCESS') {
    res.redirect(`/success?orderId=${encodeURIComponent(reference || '')}`);
  } else {
    res.redirect('/order?cancelled=1');
  }
});

// ── Email via Resend ──────────────────────────────────────────────────────────

async function sendEmail(order, orderId) {
  const { name, surname, age, phone, email, planName, amount } = order;
  const e = escHtml;
  try {
    await resend.emails.send({
      from:    'onboarding@resend.dev',
      to:      RECIPIENT_EMAIL,
      subject: `Новая запись: ${e(planName)} — ${e(name)} ${e(surname)}`,
      html: `
        <div style="font-family:Calibri,sans-serif;max-width:600px;margin:0 auto;padding:32px;color:#1C1C1A;">
          <h2 style="color:#C8A96E;margin-bottom:24px;">Новая запись на консультацию</h2>
          <table style="width:100%;border-collapse:collapse;">
            <tr style="border-bottom:1px solid #E5E0D8;">
              <td style="padding:10px 0;color:#6B6860;width:140px;">Услуга</td>
              <td style="padding:10px 0;font-weight:600;">${e(planName)}</td>
            </tr>
            <tr style="border-bottom:1px solid #E5E0D8;">
              <td style="padding:10px 0;color:#6B6860;">Сумма</td>
              <td style="padding:10px 0;">${e(amount)} €</td>
            </tr>
            <tr style="border-bottom:1px solid #E5E0D8;">
              <td style="padding:10px 0;color:#6B6860;">Имя</td>
              <td style="padding:10px 0;">${e(name)} ${e(surname)}</td>
            </tr>
            <tr style="border-bottom:1px solid #E5E0D8;">
              <td style="padding:10px 0;color:#6B6860;">Возраст</td>
              <td style="padding:10px 0;">${e(age)}</td>
            </tr>
            <tr style="border-bottom:1px solid #E5E0D8;">
              <td style="padding:10px 0;color:#6B6860;">Телефон</td>
              <td style="padding:10px 0;">${e(phone)}</td>
            </tr>
            <tr style="border-bottom:1px solid #E5E0D8;">
              <td style="padding:10px 0;color:#6B6860;">E-mail</td>
              <td style="padding:10px 0;">${e(email)}</td>
            </tr>
            <tr>
              <td style="padding:10px 0;color:#6B6860;">Номер заказа</td>
              <td style="padding:10px 0;font-size:0.85em;color:#999;">${e(orderId)}</td>
            </tr>
          </table>
          <p style="margin-top:32px;font-size:0.85em;color:#999;">Оплата подтверждена через Maksekeskus</p>
        </div>
      `,
    });
    console.log('Email sent for order', orderId);
  } catch (err) {
    console.error('Email error:', err.message);
  }
}

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
