const bcrypt = require('bcryptjs');
const { kv, sign, readBody, norm } = require('../lib/auth');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método não permitido.' });
  const { username, password, question, answer } = await readBody(req);
  const u = norm(username);
  if (!u || !password || !question || !answer) return res.status(400).json({ error: 'Preencha todos os campos.' });
  if (u.length < 3) return res.status(400).json({ error: 'Usuário precisa de ao menos 3 caracteres.' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Senha precisa de ao menos 6 caracteres.' });

  const exists = await kv.get('user:' + u);
  if (exists) return res.status(409).json({ error: 'Esse usuário já existe.' });

  const passHash = await bcrypt.hash(String(password), 10);
  const ansHash = await bcrypt.hash(norm(answer), 10);
  await kv.set('user:' + u, { username: u, passHash, question: String(question).trim(), ansHash, createdAt: Date.now() });

  return res.status(200).json({ token: sign(u), username: u });
};
