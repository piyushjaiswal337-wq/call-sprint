// netlify/functions/razorpay-webhook.js
//
// Receives Razorpay's "payment.captured" webhook, verifies its signature,
// works out which Call Sprint user paid (by phone number), and marks
// them Premium in Firestore for 30 days.
//
// Required Netlify environment variables (Site settings -> Environment variables):
//   RAZORPAY_WEBHOOK_SECRET   - the secret you set when creating the webhook
//   FIREBASE_SERVICE_ACCOUNT_B64 - your Firebase service account JSON,
//                                   base64-encoded (see setup notes)

const crypto = require('crypto');
const admin = require('firebase-admin');

const PREMIUM_DAYS = 30;

function getFirestore() {
  if (!admin.apps.length) {
    const raw = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8');
    const serviceAccount = JSON.parse(raw);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  }
  return admin.firestore();
}

function verifySignature(rawBody, signature, secret) {
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  // constant-time compare
  const a = Buffer.from(expected);
  const b = Buffer.from(signature || '');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function normalizePhone(contact) {
  if (!contact) return null;
  const digits = String(contact).replace(/\D/g, '');
  return digits.length >= 10 ? digits.slice(-10) : null;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
  const signature = event.headers['x-razorpay-signature'] || event.headers['X-Razorpay-Signature'];
  const rawBody = event.body || '';

  if (!secret || !verifySignature(rawBody, signature, secret)) {
    console.error('Invalid or missing Razorpay signature');
    return { statusCode: 400, body: 'Invalid signature' };
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (e) {
    return { statusCode: 400, body: 'Bad JSON' };
  }

  // We only care about successful captures.
  if (payload.event !== 'payment.captured') {
    return { statusCode: 200, body: 'Ignored (not payment.captured)' };
  }

  const payment = payload.payload && payload.payload.payment && payload.payload.payment.entity;
  if (!payment) {
    return { statusCode: 400, body: 'No payment entity in payload' };
  }

  const phone = normalizePhone(payment.contact);
  if (!phone) {
    console.error('Could not extract a valid phone from payment', payment.id);
    return { statusCode: 200, body: 'No usable phone number, skipped' };
  }

  try {
    const db = getFirestore();
    const docRef = db.collection('premiumUsers').doc(phone);
    const existing = await docRef.get();

    const now = Date.now();
    const existingUntil = existing.exists && existing.data().premiu
