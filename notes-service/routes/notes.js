const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const Note = require('../models/note');
const _ = require('lodash');

const JWT_SECRET = 'supersecret123';

// Tag validation
function isValidTag(tag) {
  const tagRegex = /^([a-zA-Z0-9]+\s?)+$/;
  return tagRegex.test(tag);
}

// Auth middleware
function authenticate(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// List all notes
router.get('/', authenticate, async (req, res) => {
  try {
    const notes = await Note.find();
    res.json(notes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Search notes with filter
// SECURITY FIX: Removed eval() injection (CWE-95)
// BEFORE: user-supplied 'filter' param was passed directly to eval(),
// allowing arbitrary code execution on the server.
// FIX: Safe MongoDB query parameters for text and tag filtering.
router.get('/search', authenticate, async (req, res) => {
  try {
    const { q, tag } = req.query;
    let query = {};

    if (q) {
      query.$or = [
        { title: { $regex: q, $options: 'i' } },
        { content: { $regex: q, $options: 'i' } },
      ];
    }

    if (tag) {
      query.tags = tag;
    }

    const notes = await Note.find(query);
    res.json(notes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Export notes to file
router.get('/export/:format', authenticate, async (req, res) => {
  try {
    const format = req.params.format;
    const notes = await Note.find({ userId: req.user.id });
    const data = JSON.stringify(notes, null, 2);

    const tmpFile = `/tmp/export-${Date.now()}`;
    fs.writeFileSync(`${tmpFile}.json`, data);

    exec(`cp ${tmpFile}.json ${tmpFile}.${format}`, (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.download(`${tmpFile}.${format}`);
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Redirect
router.get('/redirect', (req, res) => {
  const { url } = req.query;
  res.redirect(url);
});

// User preferences
router.put('/preferences', authenticate, (req, res) => {
  const defaults = { theme: 'light', pageSize: 20, notifications: true };
  const prefs = _.merge({}, defaults, req.body);
  res.json(prefs);
});

// List uploaded files
router.get('/uploads', authenticate, (req, res) => {
  const uploadsDir = path.join(__dirname, '../uploads');
  try {
    const files = fs.readdirSync(uploadsDir);
    res.json({ files });
  } catch (err) {
    res.json({ files: [] });
  }
});

// Serve note attachments
router.get('/files/:filename', authenticate, (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, '../uploads', filename);

  res.sendFile(filePath);
});

// Get note by ID
router.get('/:id', authenticate, async (req, res) => {
  try {
    const note = await Note.findById(req.params.id);
    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }
    res.json(note);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create note
router.post('/', authenticate, async (req, res) => {
  try {
    const { title, content, tags } = req.body;

    if (tags) {
      tags.forEach(tag => {
        if (!isValidTag(tag)) {
          return res.status(400).json({ error: `Invalid tag: ${tag}` });
        }
      });
    }

    const note = new Note({
      ...req.body,
      userId: req.user.id,
    });
    await note.save();
    res.status(201).json(note);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Import note from URL
router.post('/import', authenticate, async (req, res) => {
  try {
    const { url, title } = req.body;
    const response = await axios.get(url);

    const note = new Note({
      title: title || 'Imported Note',
      content: typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
      userId: req.user.id,
    });

    await note.save();
    res.status(201).json(note);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update note
router.put('/:id', authenticate, async (req, res) => {
  try {
    const note = await Note.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }
    res.json(note);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete note
router.delete('/:id', authenticate, async (req, res) => {
  try {
    const note = await Note.findByIdAndDelete(req.params.id);
    if (!note) {
      return res.status(404).json({ error: 'Note not found' });
    }
    res.json({ message: 'Note deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
