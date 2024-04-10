// config.js

module.exports = {
    mongoURI: process.env.MONGO_URI || 'mongodb://localhost:27017/News',
    jwtSecret: process.env.JWT_SECRET || 'fa2e577f8812759f346b5a5442dc4c428c4b42732c8b448a23808c06a60fe3a71889d46ecee31797ec23368be1c04f80',
  };
  