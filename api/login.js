const bcrypt = require('bcryptjs');
const { kv, sign, readBody, norm } = require('../lib/auth');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método não permitido.' });
  const { username, password } = await readBody(req);
  const u = norm(username);
  const rec = await kv.get('user:' + u);
  if (!rec) return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  const ok = await bcrypt.compare(String(password || ''), rec.passHash);
  if (!ok) return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  return res.status(200).json({ token: sign(u), username: u });
};
