/**
 * middleware/verifyToken.js
 * Verifica JWT Bearer en peticiones al Resource Server.
 */

import jwt from 'jsonwebtoken';
import 'dotenv/config';

export function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Token Bearer no proporcionado'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded  = jwt.verify(token, process.env.JWT_SECRET);
    req.deviceInfo = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'token_expired', message: 'El token ha expirado' });
    }
    return res.status(401).json({ error: 'invalid_token', message: 'Token inválido' });
  }
}