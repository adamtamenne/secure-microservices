const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const notesRoutes = require('./routes/notes');

const app = express();

app.use(cors());
app.use(bodyParser.json());

const MONGO_URI = 'mongodb://admin:password123@mongodb:27017/notes?authSource=admin';
const INTERNAL_API_KEY = 'internal-service-key-a1b2c3d4e5';

// S3 bucket for note attachments
const AWS_ACCESS_KEY_ID = 'AKIAZ3MSJV2WBEX4MPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzmEXAMPLEK';

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('Notes service connected to MongoDB');
});

app.use('/api/notes', notesRoutes);

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: err.message,
    stack: err.stack
  });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Notes service listening on port ${PORT}`);
});

module.exports = app;
