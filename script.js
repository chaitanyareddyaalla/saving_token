const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = 'jwt_secret_key_here';
const ENCRYPTION_KEY = crypto.randomBytes(32);
const IV = crypto.randomBytes(16);

const encrypt = (payload) => {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    token: encrypted,
    iv: IV.toString('hex')
  };
};

const decrypt = ({ token, iv }) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(token, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return jwt.verify(decrypted, JWT_SECRET);
};

module.exports = {
  encrypt,
  decrypt
};
