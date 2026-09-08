// Funciones compartidas por signup.js, login.js y data.js
// (el prefijo "_" hace que Netlify NO despliegue este archivo como endpoint propio)
const crypto = require('crypto');
const { connectLambda } = require('@netlify/blobs');

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

function safeHandler(fn) {
  return async (event, context) => {
    try {
      connectLambda(event);
      return await fn(event, context);
    } catch (err) {
      console.error('Error interno en función:', err);
      return json(500, { error: 'Error interno del servidor: ' + (err && err.message ? err.message : String(err)) });
    }
  };
}

function getTokenFromEvent(event) {
  const auth = event.headers.authorization || event.headers.Authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
  if (event.queryStringParameters && event.queryStringParameters.token) {
    return event.queryStringParameters.token;
  }
  return null;
}

module.exports = { json, hashPassword, verifyPassword, genToken, getTokenFromEvent, safeHandler };
