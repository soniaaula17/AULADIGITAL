const { getStore } = require('@netlify/blobs');
const { json, verifyPassword, genToken } = require('./_utils');

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return json(200, {});
  if (event.httpMethod !== 'POST') return json(405, { error: 'Método no permitido.' });

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (e) {
    return json(400, { error: 'Solicitud inválida.' });
  }

  const correo = String(body.correo || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!correo || !password) return json(400, { error: 'Completa correo y contraseña.' });

  const users = getStore('users');
  const user = await users.get(correo, { type: 'json' });
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return json(401, { error: 'Correo o contraseña incorrectos.' });
  }

  const token = genToken();
  const tokens = getStore('tokens');
  await tokens.set(token, correo);

  return json(200, { token, perfil: { correo: user.correo, nombre: user.nombre } });
};
