// Utilidades compartilhadas de autenticação (CommonJS)
const jwt = require('jsonwebtoken');
const { createClient } = require('@vercel/kv');

// Aceita tanto as vars da integração "Vercel KV" (KV_*) quanto as do
// Marketplace Upstash (UPSTASH_*), pra funcionar com qualquer uma.
const kv = createClient({
  url: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN,
});

const SECRET = process.env.JWT_SECRET || 'dev-insecure-change-me';

function sign(username) {
  return jwt.sign({ u: username }, SECRET, { expiresIn: '7d' });
}

function verify(req) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return null;
  try {
    return jwt.verify(t, SECRET);
  } catch (e) {
    return null;
  }
}

// Lê o corpo JSON da requisição (Vercel às vezes já parseia, às vezes não)
function readBody(req) {
  return new Promise((resolve) => {
    if (req.body !== undefined && req.body !== null) {
      if (typeof req.body === 'string') {
        try { return resolve(JSON.parse(req.body || '{}')); } catch (e) { return resolve({}); }
      }
      return resolve(req.body);
    }
    let d = '';
    req.on('data', (c) => { d += c; });
    req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch (e) { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

const norm = (s) => String(s || '').trim().toLowerCase();

module.exports = { kv, sign, verify, readBody, norm };
