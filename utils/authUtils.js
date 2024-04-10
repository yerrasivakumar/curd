// const jwt = require('jsonwebtoken');
// const config = require('../config');

// exports.verifyToken = (req, res, next) => {
//   const token = req.headers.authorization;

//   if (!token) {
//     return res.status(401).json({ message: 'Unauthorized: Token not provided' });
//   }

//   jwt.verify(token, config.jwtSecret, (err, decoded) => {
//     if (err) {
//       return res.status(401).json({ message: 'Unauthorized: Invalid token' });
//     }

//     req.user = { userId: decoded.userId };
//     next();
//   });
// };
