/**
 * routes/authRoutes.js
 * Prefijo: /authserver
 */

import { Router } from 'express';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import 'dotenv/config';

import {
  generateKeyPair,
  signData,
  verifySignature,
  exportPublicKey,
  exportPrivateKey,
  importPrivateKey
} from '../helpers/rsaHelpers.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const router    = Router();

const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL || 'http://localhost:3000'; // ← AÑADIDO

// ── Paths ──────────────────────────────────────────────────────────
const DATA_DIR        = join(__dirname, '../data');
const KEYS_DIR        = join(__dirname, '../keys');
const VIEWS_DIR       = join(__dirname, '../views');
const USERS_FILE      = join(DATA_DIR, 'users.json');
const AUTH_CODES_FILE = join(DATA_DIR, 'authorizationCodes.json');
const DEVICES_FILE    = join(DATA_DIR, 'registeredDevices.json');
const PUB_KEY_FILE    = join(KEYS_DIR, 'auth-public.json');
const PRIV_KEY_FILE   = join(KEYS_DIR, 'auth-private.json');

// ── Helpers JSON ───────────────────────────────────────────────────
function readJSON(fp, def = []) {
  try { return existsSync(fp) ? JSON.parse(readFileSync(fp, 'utf8')) : def; }
  catch { return def; }
}
function writeJSON(fp, data) {
  writeFileSync(fp, JSON.stringify(data, null, 2), 'utf8');
}

// ── Obtener claves ─────────────────────────────────────────────────
function getAuthPublicKey() {
  return readJSON(PUB_KEY_FILE, null);
}

function getAuthPrivateKey() {
  const raw = readJSON(PRIV_KEY_FILE, null);
  if (!raw) throw new Error('Clave privada del Auth Server no encontrada');
  return importPrivateKey(raw);
}

// ── Solicitudes pendientes en memoria ─────────────────────────────
const pendingRequests = {};

// ══════════════════════════════════════════════════════════════════
// GET /authserver/public-key
// ══════════════════════════════════════════════════════════════════
router.get('/public-key', (req, res) => {
  const pubKey = getAuthPublicKey();
  if (!pubKey) return res.status(500).json({ error: 'Clave pública no disponible aún' });
  res.json({ publicKey: pubKey });
});

// ══════════════════════════════════════════════════════════════════
// POST /authserver/bootstrap-manufacturer-cert
// ══════════════════════════════════════════════════════════════════
router.post('/bootstrap-manufacturer-cert', (req, res) => {
  const { deviceId, publicKey, manufacturer } = req.body;

  if (!deviceId || !publicKey || !manufacturer) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Campos requeridos: deviceId, publicKey, manufacturer'
    });
  }

  const payload = {
    deviceId,
    publicKey,
    manufacturer,
    issuedAt: new Date().toISOString()
  };

  const privateKey = getAuthPrivateKey();
  const signature  = signData(payload, privateKey);

  console.log(`[AuthServer] Bootstrap manufacturer cert: ${deviceId}`);
  res.json({ manufacturerCertificate: { payload, signature } });
});

// ══════════════════════════════════════════════════════════════════
// POST /authserver/register-device
// ══════════════════════════════════════════════════════════════════
router.post('/register-device', (req, res) => {
  const { manufacturerCertificate, deviceId, publicKey, redirect_uri } = req.body;

  if (!manufacturerCertificate || !deviceId || !publicKey || !redirect_uri) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Campos requeridos: manufacturerCertificate, deviceId, publicKey, redirect_uri'
    });
  }

  if (!manufacturerCertificate.payload || !manufacturerCertificate.signature) {
    return res.status(400).json({ error: 'invalid_certificate', message: 'Estructura del cert inválida' });
  }

  const { payload, signature } = manufacturerCertificate;

  if (
    payload.deviceId !== deviceId ||
    JSON.stringify(payload.publicKey) !== JSON.stringify(publicKey)
  ) {
    return res.status(400).json({
      error: 'certificate_mismatch',
      message: 'Los datos del body no coinciden con el manufacturer certificate'
    });
  }

  const authPublicKey = getAuthPublicKey();
  const isValid = verifySignature(payload, signature, authPublicKey);

  if (!isValid) {
    return res.status(401).json({ error: 'invalid_signature', message: 'Firma del manufacturer cert inválida' });
  }

  const requestId = uuidv4();
  pendingRequests[requestId] = {
    deviceId,
    publicKey,
    manufacturer: payload.manufacturer,
    issuedAt:     payload.issuedAt,
    redirect_uri,
    requestId,
    createdAt:    new Date().toISOString()
  };

  console.log(`[AuthServer] Device ${deviceId} validado. RequestId: ${requestId}`);
  req.session.pendingRequestId = requestId;
  res.redirect(`${AUTH_SERVER_URL}/authserver/login?requestId=${requestId}`); // ← CORREGIDO
});

// ══════════════════════════════════════════════════════════════════
// GET /authserver/login
// ══════════════════════════════════════════════════════════════════
router.get('/login', (req, res) => {
  const { requestId } = req.query;
  if (!requestId || !pendingRequests[requestId]) {
    return res.status(400).sendFile(join(VIEWS_DIR, 'error.html'));
  }
  let html = readFileSync(join(VIEWS_DIR, 'login.html'), 'utf8');
  html = html.replace(/\{\{REQUEST_ID\}\}/g, requestId).replace('{{ERROR}}', '');
  res.send(html);
});

// ══════════════════════════════════════════════════════════════════
// POST /authserver/login
// ══════════════════════════════════════════════════════════════════
router.post('/login', (req, res) => {
  const { username, password, requestId } = req.body;

  if (!requestId || !pendingRequests[requestId]) {
    return res.status(400).sendFile(join(VIEWS_DIR, 'error.html'));
  }

  const users = readJSON(USERS_FILE, []);
  const user  = users.find(u => u.username === username && u.password === password);

  if (!user) {
    let html = readFileSync(join(VIEWS_DIR, 'login.html'), 'utf8');
    html = html
      .replace(/\{\{REQUEST_ID\}\}/g, requestId)
      .replace('{{ERROR}}', '<div class="alert alert-danger mt-3">Credenciales incorrectas</div>');
    return res.status(401).send(html);
  }

  req.session.authenticatedUser = username;
  req.session.pendingRequestId  = requestId;
  res.redirect(`${AUTH_SERVER_URL}/authserver/consent?requestId=${requestId}`); // ← CORREGIDO
});

// ══════════════════════════════════════════════════════════════════
// GET /authserver/consent
// ══════════════════════════════════════════════════════════════════
router.get('/consent', (req, res) => {
  const { requestId } = req.query;

  if (!req.session.authenticatedUser) {
    return res.redirect(`${AUTH_SERVER_URL}/authserver/login?requestId=${requestId}`); // ← CORREGIDO
  }
  if (!requestId || !pendingRequests[requestId]) {
    return res.status(400).sendFile(join(VIEWS_DIR, 'error.html'));
  }

  const pending       = pendingRequests[requestId];
  const pubKeyPreview = `n: ${String(pending.publicKey.n).substring(0, 48)}...  e: ${pending.publicKey.e}`;

  let html = readFileSync(join(VIEWS_DIR, 'consent.html'), 'utf8');
  html = html
    .replace(/\{\{REQUEST_ID\}\}/g, requestId)
    .replace('{{DEVICE_ID}}',       pending.deviceId)
    .replace('{{MANUFACTURER}}',    pending.manufacturer)
    .replace('{{PUBLIC_KEY}}',      pubKeyPreview)
    .replace('{{USER}}',            req.session.authenticatedUser);
  res.send(html);
});

// ══════════════════════════════════════════════════════════════════
// POST /authserver/approve
// ══════════════════════════════════════════════════════════════════
router.post('/approve', (req, res) => {
  const { requestId } = req.body;

  if (!req.session.authenticatedUser) {
    return res.status(401).sendFile(join(VIEWS_DIR, 'error.html'));
  }
  if (!requestId || !pendingRequests[requestId]) {
    return res.status(400).sendFile(join(VIEWS_DIR, 'error.html'));
  }

  const pending = pendingRequests[requestId];
  const user    = req.session.authenticatedUser;

  const authCode  = uuidv4();
  const authCodes = readJSON(AUTH_CODES_FILE, []);
  authCodes.push({
    code:      authCode,
    user,
    deviceId:  pending.deviceId,
    createdAt: new Date().toISOString(),
    used:      false
  });
  writeJSON(AUTH_CODES_FILE, authCodes);

  const sensorPayload = {
    deviceId:     pending.deviceId,
    publicKey:    pending.publicKey,
    manufacturer: pending.manufacturer,
    issuedAt:     new Date().toISOString(),
    signedBy:     'AuthServer'
  };

  const privateKey = getAuthPrivateKey();
  const signature  = signData(sensorPayload, privateKey);

  const devices = readJSON(DEVICES_FILE, []);
  const idx     = devices.findIndex(d => d.deviceId === pending.deviceId);
  const record  = {
    deviceId:     pending.deviceId,
    publicKey:    pending.publicKey,
    manufacturer: pending.manufacturer,
    user,
    registeredAt: new Date().toISOString()
  };
  if (idx >= 0) devices[idx] = record; else devices.push(record);
  writeJSON(DEVICES_FILE, devices);

  delete pendingRequests[requestId];
  req.session.authenticatedUser = null;

  console.log(`[AuthServer] Aprobado: ${pending.deviceId} por ${user}`);

const redirectUrl = `${pending.redirect_uri}?code=${authCode}&signature=${encodeURIComponent(signature)}&issuedAt=${encodeURIComponent(sensorPayload.issuedAt)}`;
console.log('>>> REDIRECT URL:', redirectUrl);
res.redirect(redirectUrl);
});

// ══════════════════════════════════════════════════════════════════
// POST /authserver/reject
// ══════════════════════════════════════════════════════════════════
router.post('/reject', (req, res) => {
  const { requestId } = req.body;
  if (requestId && pendingRequests[requestId]) {
    const pending = pendingRequests[requestId];
    delete pendingRequests[requestId];
    return res.redirect(`${pending.redirect_uri}?error=access_denied`);
  }
  res.sendFile(join(VIEWS_DIR, 'error.html'));
});

// ══════════════════════════════════════════════════════════════════
// POST /authserver/token
// ══════════════════════════════════════════════════════════════════
router.post('/token', (req, res) => {
  const { authorizationCode, sensorCertificate } = req.body;

  if (!authorizationCode || !sensorCertificate) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Se requieren authorizationCode y sensorCertificate'
    });
  }

  if (!sensorCertificate.payload || !sensorCertificate.signature) {
    return res.status(400).json({ error: 'invalid_certificate', message: 'Estructura del sensor cert inválida' });
  }

  const { payload, signature } = sensorCertificate;

  const authPublicKey = getAuthPublicKey();
  const isValidSig    = verifySignature(payload, signature, authPublicKey);

  if (!isValidSig) {
    return res.status(401).json({ error: 'invalid_signature', message: 'Firma del sensor certificate inválida' });
  }

  if (payload.signedBy !== 'AuthServer') {
    return res.status(401).json({ error: 'invalid_certificate', message: 'El cert no fue firmado por AuthServer' });
  }

  const authCodes  = readJSON(AUTH_CODES_FILE, []);
  const codeRecord = authCodes.find(c => c.code === authorizationCode && !c.used);

  if (!codeRecord) {
    return res.status(401).json({ error: 'invalid_grant', message: 'Authorization code inválido o ya utilizado' });
  }

  if (codeRecord.deviceId !== payload.deviceId) {
    return res.status(401).json({ error: 'device_mismatch', message: 'deviceId no coincide con el cert' });
  }

  const devices = readJSON(DEVICES_FILE, []);
  if (!devices.find(d => d.deviceId === payload.deviceId)) {
    return res.status(401).json({ error: 'device_not_registered', message: 'Dispositivo no registrado' });
  }

  const cIdx = authCodes.findIndex(c => c.code === authorizationCode);
  authCodes[cIdx].used = true;
  writeJSON(AUTH_CODES_FILE, authCodes);

  const certFingerprint = signData(
    JSON.stringify(payload),
    getAuthPrivateKey()
  ).substring(0, 32);

  const tokenPayload = {
    deviceId:               payload.deviceId,
    user:                   codeRecord.user,
    certificateFingerprint: certFingerprint,
    manufacturer:           payload.manufacturer,
    createdAt:              new Date().toISOString()
  };

  const accessToken = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '1h' });

  console.log(`[AuthServer] JWT emitido → ${payload.deviceId} (${codeRecord.user})`);
  res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
});

export default router;