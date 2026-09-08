// Funciones compartidas por signup.js, login.js y data.js
// (el prefijo "_" hace que Netlify NO despliegue este archivo como endpoint propio)
const crypto = require('crypto');

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    },
    body: JSON.stringify(body),
  };
}

// Contraseñas: nunca se guardan en texto plano.
// scrypt (nativo de Node, sin dependencias externas) + salt aleatorio por usuario.
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, hash] = String(stored).split(':');
    const check = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
  } catch (e) {
    return false;
  }
}

function genToken() {
  return crypto.randomBytes(32).toString('hex');
}

// El token puede llegar por header Authorization (fetch normal)
// o por query string (sendBeacon, que no puede mandar headers custom).
function getTokenFromEvent(event) {
  const auth = event.headers.authorization || event.headers.Authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
  if (event.queryStringParameters && event.queryStringParameters.token) {
    return event.queryStringParameters.token;
  }
  return null;
}

module.exports = { json, hashPassword, verifyPassword, genToken, getTokenFromEvent };
