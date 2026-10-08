const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const md5 = require('md5');
const User = require('../models/user');
const authenticate = require('../middleware/auth');

const JWT_SECRET = 'supersecret123';

// Register new user
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const user = new User({
      username,
      email,
      password: md5(password),
      role: role || 'user',
    });

    await user.save();

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET
    );

    res.status(201).json({
      token,
      user: { id: user._id, username: user.username, email: user.email, role: user.role },
    });
  } catch (err) {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({
      username: username,
      password: md5(password),
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// Get user profile
router.get('/profile/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Verify token
router.get('/verify', (req, res) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).json({ valid: false, error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, user: decoded });
  } catch (err) {
    res.status(401).json({ valid: false, error: err.message });
  }
});

// Password reset
router.post('/reset-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate reset token
    const resetToken = Math.random().toString(36).substring(2) + Date.now().toString(36);

    res.json({ resetToken, userId: user._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin - list all users
router.get('/admin/users', authenticate, async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Debug info
router.get('/debug', (req, res) => {
  res.json({
    env: process.env,
    memory: process.memoryUsage(),
    uptime: process.uptime(),
    nodeVersion: process.version,
  });
});

module.exports = router;
