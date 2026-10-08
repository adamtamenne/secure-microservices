const jwt = require('jsonwebtoken');

const JWT_SECRET = 'supersecret123';

module.exports = function authenticate(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token.', details: err.message });
  }
};
