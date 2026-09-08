const { getStore } = require('@netlify/blobs');
const { json, hashPassword, genToken, safeHandler } = require('./_utils');

exports.handler = safeHandler(async (event) => {
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
  const nombre = String(body.nombre || '').trim();

  if (!correo || !password) return json(400, { error: 'Completa correo y contraseña.' });
  if (password.length < 4) return json(400, { error: 'La contraseña debe tener al menos 4 caracteres.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)) return json(400, { error: 'Ingresa un correo válido.' });

  const users = getStore('users');
  const existing = await users.get(correo, { type: 'json' });
  if (existing) return json(409, { error: 'Ya existe una cuenta con ese correo.' });

  const user = {
    correo,
    nombre,
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString(),
  };
  await users.setJSON(correo, user);

  // Cada usuario arranca con su propio estado vacío: total aislamiento entre cuentas.
  const states = getStore('states');
  await states.setJSON(correo, {});

  const token = genToken();
  const tokens = getStore('tokens');
  await tokens.set(token, correo);

  return json(200, { token, perfil: { correo: user.correo, nombre: user.nombre } });
});
