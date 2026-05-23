/**
 * routes/resourceRoutes.js
 * Prefijo: /resourceserver
 *
 * POST /metrics  → recibe métricas protegidas por JWT
 * GET  /metrics  → lista últimas métricas (debug)
 */

import { Router } from 'express';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { verifyToken } from '../middleware/verifyToken.js';
import { decryptData } from '../helpers/rsaHelpers.js';

const __dirname    = dirname(fileURLToPath(import.meta.url));
const router       = Router();
const METRICS_FILE = join(__dirname, '../data/metrics.json');
const PRIV_KEY_FILE = join(__dirname, '../keys/auth-private.json');

function readJSON(fp, d = []) {
  try { return existsSync(fp) ? JSON.parse(readFileSync(fp, 'utf8')) : d; }
  catch { return d; }
}
function writeJSON(fp, data) {
  writeFileSync(fp, JSON.stringify(data, null, 2), 'utf8');
}

// ══════════════════════════════════════════════════════════════════
// POST /resourceserver/metrics
// ══════════════════════════════════════════════════════════════════
router.post('/metrics', verifyToken, (req, res) => {
  const { encryptedData } = req.body;

  if (!encryptedData) {
    return res.status(400).json({ error: 'invalid_request', message: 'Falta encryptedData' });
  }

  let deviceId, zone, location, timestamp, energyConsumption;
  try {
    const privKeyRaw = readJSON(PRIV_KEY_FILE, null);
    const decrypted  = decryptData(encryptedData, privKeyRaw);
    ({ deviceId, zone, location, timestamp, energyConsumption } = JSON.parse(decrypted));
  } catch (err) {
    return res.status(400).json({ error: 'decrypt_error', message: 'Error descifrando payload' });
  }

  if (!deviceId || !zone || !location || !timestamp || energyConsumption === undefined) {
    return res.status(400).json({ error: 'invalid_request', message: 'Faltan campos en el payload' });
  }

  if (req.deviceInfo.deviceId !== deviceId) {
    return res.status(403).json({ error: 'forbidden', message: 'deviceId no coincide con el token' });
  }

  const record = {
    deviceId,
    user:             req.deviceInfo.user,
    zone,
    location,
    timestamp,
    energyConsumption,
    receivedAt:       new Date().toISOString()
  };

  const metrics = readJSON(METRICS_FILE, []);
  metrics.push(record);
  if (metrics.length > 500) metrics.splice(0, metrics.length - 500);
  writeJSON(METRICS_FILE, metrics);

  console.log(`[ResourceServer] Métrica descifrada de ${deviceId}: ${energyConsumption} kWh`);
  res.json({ status: 'ok', message: 'Métrica registrada', receivedAt: record.receivedAt });
});

// ══════════════════════════════════════════════════════════════════
// GET /resourceserver/metrics
// ══════════════════════════════════════════════════════════════════
router.get('/metrics', (req, res) => {
  const metrics = readJSON(METRICS_FILE, []);
  res.json({ count: metrics.length, metrics: metrics.slice(-50).reverse() });
});

export default router;