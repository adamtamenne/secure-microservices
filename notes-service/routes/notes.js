const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
// child_process.exec() spawns a system shell (/bin/sh) and runs
// the string you pass as a shell command. Any user input concatenated
// into that string is interpreted by the shell
// const { exec } = require('child_process');
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
// Command injection via exec() (CWE-78)
// BEFORE: format param went straight into exec(`cp ... ${format}`), so
// requesting /export/json;rm+-rf+/ ran that as a shell command. Classic RCE.
// FIX: Allowlist the format, use fs.copyFileSync (no shell involved), clean up tmp files.
router.get('/export/:format', authenticate, async (req, res) => {
  try {
    // Only accept known formats. Allowlist > denylist because you can't
    // anticipate every shell metacharacter trick.
    const allowedFormats = ['json', 'csv', 'txt'];
    const format = req.params.format;

    if (!allowedFormats.includes(format)) {
      return res.status(400).json({ error: `Invalid format. Allowed: ${allowedFormats.join(', ')}` });
    }

    const notes = await Note.find({ userId: req.user.id });
    const data = JSON.stringify(notes, null, 2);

    const tmpFile = `/tmp/export-${Date.now()}`;
    const srcPath = `${tmpFile}.json`;
    const destPath = `${tmpFile}.${format}`;

    fs.writeFileSync(srcPath, data);
    // copyFileSync talks to the OS directly, no shell spawned, nothing to inject into.
    fs.copyFileSync(srcPath, destPath);

    res.download(destPath, (err) => {
      // Clean up so we don't leak temp files forever.
      try { fs.unlinkSync(srcPath); } catch (_) {}
      try { fs.unlinkSync(destPath); } catch (_) {}
      if (err && !res.headersSent) {
        res.status(500).json({ error: 'Download failed' });
      }
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
// SECURITY FIX: Server-Side Request Forgery (CWE-918)
// BEFORE: any URL the user sent was fetched by the server with no checks,
// so an attacker could hit internal services, cloud metadata endpoints,
// or localhost to steal credentials and map the internal network.
// FIX: Only allow http/https, block private/reserved IPs after resolving
// the hostname (prevents DNS rebinding too), cap response size.
router.post('/import', authenticate, async (req, res) => {
  try {
    const { url, title } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    // Only allow http and https. Without this, an attacker could use
    // file://, gopher://, etc. to read local files or talk to internal services.
    let parsed;
    try {
      parsed = new URL(url);
    } catch (_) {
      return res.status(400).json({ error: 'Invalid URL' });
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return res.status(400).json({ error: 'Only HTTP and HTTPS URLs are allowed' });
    }

    // Resolve the hostname to an IP and check it before making the request.
    // This stops requests to 169.254.169.254 (AWS metadata), 10.x, 172.16.x,
    // 192.168.x, localhost, etc. We resolve first so attackers can't just
    // point a DNS name at an internal IP to bypass string checks on the hostname.
    const dns = require('dns').promises;
    const { address } = await dns.lookup(parsed.hostname);
    const blocked = [
      /^127\./,                    // loopback
      /^10\./,                     // private class A
      /^172\.(1[6-9]|2\d|3[01])\./, // private class B
      /^192\.168\./,               // private class C
      /^169\.254\./,               // link-local / cloud metadata
      /^0\./,                      // "this" network
      /^::1$/,                     // IPv6 loopback
      /^f[cd]/i,                   // IPv6 private
    ];

    if (blocked.some(rx => rx.test(address))) {
      return res.status(400).json({ error: 'URLs pointing to internal/private networks are not allowed' });
    }

    // Cap response size so an attacker can't make the server download a 10GB file.
    const response = await axios.get(parsed.href, {
      maxContentLength: 5 * 1024 * 1024, // 5MB
      timeout: 10000, // 10s so it can't be used to hold connections open
    });

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
