const mongoose = require('mongoose');
const moment = require('moment');
const userSchema = new mongoose.Schema({
  email: { type: String,  unique: true },
  password: { type: String, },
  UserName: String,
  phoneNumber: String,
   address: String,
});

const User = mongoose.model('NewUser', userSchema);

module.exports = User;
