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
import { decryptData, importPublicKey,verifySignature } from '../helpers/rsaHelpers.js';
import { createHash ,randomBytes } from 'crypto';

const __dirname    = dirname(fileURLToPath(import.meta.url));
const router       = Router();
const METRICS_FILE = join(__dirname, '../data/metrics.json');
const BLIND_METRICS_FILE = join(__dirname, '../data/metrics_blind.json');
const PRIV_KEY_FILE = join(__dirname, '../keys/auth-private.json');
const PUB_KEY_FILE    = join(__dirname, '../keys/auth-public.json');
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




router.post('/metrics-blind', (req, res) => {
  const { encryptedData, ephemeralPubKey, ephemeralSignature, metricSignature } = req.body;

  // ── 1. Validar campos ──────────────────────────────────────────
  if (!encryptedData || !ephemeralPubKey || !ephemeralSignature || !metricSignature) {
    return res.status(400).json({
      error:   'missing_fields',
      message: 'Se requieren encryptedData, ephemeralPubKey, ephemeralSignature y metricSignature'
    });
  }

  // ── 2. Descifrar datos sensibles ───────────────────────────────
  let anonymousId, zone, timestamp, energyConsumption;
  try {
    const privKeyRaw = readJSON(PRIV_KEY_FILE);
    if (!privKeyRaw) throw new Error('Clave privada no encontrada');
    const decrypted = decryptData(encryptedData, privKeyRaw);
    ({ anonymousId, zone, timestamp, energyConsumption } = JSON.parse(decrypted));
  } catch (err) {
    return res.status(400).json({ error: 'decrypt_error', message: 'Error descifrando payload' });
  }

  if (!anonymousId || !zone || !timestamp || !energyConsumption) {
    return res.status(400).json({ error: 'missing_fields', message: 'Faltan campos en el payload descifrado' });
  }

  // ── 3. Reconstruir ephCert y hacer hash ────────────────────────
  let m, s, n, e;
  try {
    const authPubKeyRaw = readJSON(PUB_KEY_FILE);
    if (!authPubKeyRaw) throw new Error('Clave pública del auth-server no encontrada');

    n = BigInt(authPubKeyRaw.n);
    e = BigInt(authPubKeyRaw.e);

    const ephCert    = { anonymousId, zone, ephemeralPubKey };
    const ephCertStr = JSON.stringify(ephCert);

    const hashHex = createHash('sha256').update(ephCertStr, 'utf8').digest('hex');
    m = BigInt('0x' + hashHex) % n;
    s = BigInt(ephemeralSignature);

  } catch (err) {
    console.error('[MetricsBlind] Error preparando verificación:', err.message);
    return res.status(500).json({ error: 'server_error', message: err.message });
  }

  // ── 4. Verificar firma ciega: s^e mod n == m ───────────────────
  try {
    const recovered = modPow(s, e, n);
    if (recovered !== m) {
      return res.status(401).json({
        error:   'blind_signature_invalid',
        message: 'La firma ciega del cert efímero no es válida'
      });
    }
  } catch (err) {
    return res.status(400).json({ error: 'verify_error', message: 'Error verificando firma ciega' });
  }

  // ── 5. Verificar posesión de la clave efímera privada ──────────
  try {
    const ephPubKey     = importPublicKey(ephemeralPubKey);
    const metricPayload = {
      anonymousId,
      zone,
      energyConsumption,
      timestamp,
      ephemeralPubKey,
      ephemeralSignature
    };
    const isMetricValid = verifySignature(metricPayload, metricSignature, ephPubKey);
    if (!isMetricValid) {
      return res.status(401).json({
        error:   'invalid_metric_signature',
        message: 'El emisor no puede probar posesión de la clave efímera privada'
      });
    }
  } catch (err) {
    return res.status(400).json({ error: 'verify_error', message: 'Error verificando firma de métrica' });
  }

  // ── 6. Guardar ─────────────────────────────────────────────────
  const certRecord = {
    anonymousId,
    zone,
    timestamp,
    energyConsumption,
    verifiedAt: new Date().toISOString()
  };

  try {
    const existing = readJSON(BLIND_METRICS_FILE) || [];
    existing.push(certRecord);
    writeJSON(BLIND_METRICS_FILE, existing);
  } catch (err) {
    console.error('[MetricsBlind] Error guardando registro:', err.message);
    return res.status(500).json({ error: 'storage_error', message: 'Error guardando el registro' });
  }

  console.log(`[ResourceServer] Cert ciego verificado → anonymousId: ${anonymousId} | zone: ${zone}`);

  return res.json({
    status:      'ok',
    anonymousId,
    message:     'Cert efímero verificado y registrado correctamente'
  });
});
// ══════════════════════════════════════════════════════════════════
// GET /resourceserver/metrics
// ══════════════════════════════════════════════════════════════════
router.get('/metrics', (req, res) => {
  const metrics = readJSON(METRICS_FILE, []);
  res.json({ count: metrics.length, metrics: metrics.slice(-50).reverse() });
});
function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = result * base % mod;
    exp = exp / 2n;
    base = base * base % mod;
  }
  return result;
}

export default router;