const { kv, verify, readBody } = require('../lib/auth');

// Sincronização dos dados financeiros do usuário autenticado.
// GET  -> { data: { <chave mvf3_*>: <valor string>, ... } }
// PUT  -> grava o blob enviado em { data: {...} }
module.exports = async (req, res) => {
  const auth = verify(req);
  if (!auth) return res.status(401).json({ error: 'Não autorizado.' });
  const key = 'data:' + auth.u;

  if (req.method === 'GET') {
    const d = await kv.get(key);
    return res.status(200).json({ data: d || {} });
  }
  if (req.method === 'PUT' || req.method === 'POST') {
    const body = await readBody(req);
    const data = body && typeof body.data === 'object' && body.data ? body.data : {};
    await kv.set(key, data);
    return res.status(200).json({ ok: true });
  }
  return res.status(405).json({ error: 'Método não permitido.' });
};
