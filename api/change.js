const bcrypt = require('bcryptjs');
const { kv, verify, readBody } = require('../lib/auth');

// Troca de senha do usuário autenticado (precisa da senha atual).
module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método não permitido.' });
  const auth = verify(req);
  if (!auth) return res.status(401).json({ error: 'Não autorizado.' });
  const { current, password } = await readBody(req);
  const rec = await kv.get('user:' + auth.u);
  if (!rec) return res.status(404).json({ error: 'Usuário não encontrado.' });
  const ok = await bcrypt.compare(String(current || ''), rec.passHash);
  if (!ok) return res.status(401).json({ error: 'Senha atual incorreta.' });
  if (String(password || '').length < 6) return res.status(400).json({ error: 'Nova senha precisa de ao menos 6 caracteres.' });
  rec.passHash = await bcrypt.hash(String(password), 10);
  await kv.set('user:' + auth.u, rec);
  return res.status(200).json({ ok: true });
};
