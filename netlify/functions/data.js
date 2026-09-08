const { getStore } = require('@netlify/blobs');
const { json, getTokenFromEvent } = require('./_utils');

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return json(200, {});

  const token = getTokenFromEvent(event);
  if (!token) return json(401, { error: 'No autorizado.' });

  const tokens = getStore('tokens');
  const correo = await tokens.get(token);
  if (!correo) return json(401, { error: 'Sesión expirada, inicia sesión de nuevo.' });

  const states = getStore('states');

  if (event.httpMethod === 'GET') {
    const state = await states.get(correo, { type: 'json' });
    return json(200, { state: state || {} });
  }

  if (event.httpMethod === 'POST') {
    let body;
    try {
      body = JSON.parse(event.body || '{}');
    } catch (e) {
      return json(400, { error: 'Solicitud inválida.' });
    }
    await states.setJSON(correo, body.state || {});
    return json(200, { ok: true });
  }

  return json(405, { error: 'Método no permitido.' });
};
