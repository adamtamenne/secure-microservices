const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');

const app = express();

app.use(cors());
app.use(bodyParser.json());

const MONGO_URI = 'mongodb://admin:password123@mongodb:27017/auth?authSource=admin';

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('Auth service connected to MongoDB');
});

app.use('/api/auth', authRoutes);

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    details: err
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Auth service listening on port ${PORT}`);
});

module.exports = app;
