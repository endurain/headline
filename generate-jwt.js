// generate-jwt.js
const jwt = require('jsonwebtoken');
const [id, secret] = process.env.GHOST_ADMIN_API_KEY.split(':');
const payload = {
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + (5 * 60),
  aud: '/v5/admin/'
};
const token = jwt.sign(payload, Buffer.from(secret, 'hex'), {
  keyid: id,
  algorithm: 'HS256'
});
console.log(token);
