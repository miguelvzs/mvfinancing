const { kv, readBody, norm } = require('../lib/auth');

// Retorna a pergunta de segurança do usuário (passo 1 do "esqueci a senha")
module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método não permitido.' });
  const { username } = await readBody(req);
  const u = norm(username);
  const rec = await kv.get('user:' + u);
  if (!rec) return res.status(404).json({ error: 'Usuário não encontrado.' });
  return res.status(200).json({ question: rec.question });
};
