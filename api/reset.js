const bcrypt = require('bcryptjs');
const { kv, sign, readBody, norm } = require('../lib/auth');

// Passo 2 do "esqueci a senha": valida resposta de segurança e troca a senha
module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método não permitido.' });
  const { username, answer, password } = await readBody(req);
  const u = norm(username);
  const rec = await kv.get('user:' + u);
  if (!rec) return res.status(404).json({ error: 'Usuário não encontrado.' });
  const ok = await bcrypt.compare(norm(answer), rec.ansHash);
  if (!ok) return res.status(401).json({ error: 'Resposta de segurança incorreta.' });
  if (String(password || '').length < 6) return res.status(400).json({ error: 'Nova senha precisa de ao menos 6 caracteres.' });
  rec.passHash = await bcrypt.hash(String(password), 10);
  await kv.set('user:' + u, rec);
  return res.status(200).json({ token: sign(u), username: u });
};
