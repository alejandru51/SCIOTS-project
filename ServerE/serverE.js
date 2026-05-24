'use strict';
import express from 'express';
import fs      from 'fs/promises';
import crypto  from 'crypto';
import * as paillierBigint from 'paillier-bigint';
import { modPow } from 'bigint-crypto-utils';
import * as rsa from 'sciots-rsa';

const PORT           = 3000;
const KEY_BITS       = 512;
const DATA_FILE      = 'sensor-data.json';
const IDS_FILE       = 'signed-ids.json';
const SENSORS_FILE   = 'sensors.json';

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  if (req.body === undefined) req.body = {};
  next();
});

// ── Claves ─────────────────────────────────────────────────────────────────
let publicKey     = null;
let privateKey    = null;
let publicKeyRSA  = null;
let privateKeyRSA = null;

// Sesiones activas: { sessionId → { sensorId, challenge, verified } }
const sessions = new Map();

// ── Credenciales del sensor único ─────────────────────────────────────────
// Debe coincidir con SENSOR en sensor-client.js
const SENSOR_CREDENTIALS = {
  'sensor-001': 'secret123',
};

// ── Usuarios para cliente firma ciega ─────────────────────────────────────
const USERS = {
  'alice': 'alice51',
  'bob':   'bob51',
};

// ═══════════════════════════════════════════════════════════════════════════
// PERSISTENCIA
// ═══════════════════════════════════════════════════════════════════════════

async function loadData() {
  try { return JSON.parse(await fs.readFile(DATA_FILE, 'utf-8')); }
  catch { return {}; }
}
async function saveData(data) {
  const safe = JSON.stringify(data, (_, v) =>
    typeof v === 'bigint' ? Number(v) : v
  , 2);
  await fs.writeFile(DATA_FILE, safe, 'utf-8');
}
async function loadIds() {
  try { return JSON.parse(await fs.readFile(IDS_FILE, 'utf-8')); }
  catch { return []; }
}
async function saveIds(ids) {
  await fs.writeFile(IDS_FILE, JSON.stringify(ids, null, 2), 'utf-8');
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function hourKey(timestamp) {
  const d = new Date(timestamp);
  d.setMinutes(0, 0, 0);
  return d.toISOString();
}

const SENSOR_TYPE_NAMES = {
  1: 'light',
  2: 'water',
  3: 'humidity',
  4: 'temperature',
};

function unpackMessage(m) {
  const consumptionBits = m & 0xFFFFFFFFFFn;
  const tsBits          = (m >> 40n) & 0xFFFFFFFFFFn;
  const typeBits        = (m >> 80n) & 0xFFFFn;
  return {
    sensorType:  SENSOR_TYPE_NAMES[Number(typeBits)],
    timestamp:   Number(tsBits),
    consumption: Number(consumptionBits),
  };
}

function generateSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

// ═══════════════════════════════════════════════════════════════════════════
// ENDPOINTS — CLIENTE FIRMA CIEGA (sin cambios)
// ═══════════════════════════════════════════════════════════════════════════

app.post('/rsa-public-key', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || !password)
    return res.status(401).json({ error: 'Credenciales no proporcionadas' });

  if (USERS[username] !== password) {
    console.log(`[AUTH] Intento fallido — usuario: ${username}`);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  console.log(`[AUTH] Acceso concedido — usuario: ${username}`);
  res.json({ n: publicKeyRSA.n.toString(), e: publicKeyRSA.e.toString() });
});

app.post('/blind-sign', (req, res) => {
  const { blindedMessage } = req.body;
  if (!blindedMessage)
    return res.status(400).json({ error: 'Falta campo: blindedMessage' });

  const blindSignature = privateKeyRSA.sign(BigInt(blindedMessage));
  console.log(`[SIGN] Mensaje cegado firmado (usuario)`);
  res.json({ blindSignature: blindSignature.toString() });
});

app.post('/verify-signature', async (req, res) => {
  const { id, signature } = req.body;
  if (!id || !signature)
    return res.status(400).json({ error: 'Faltan campos: id o signature' });

  try {
    const hashHex    = crypto.createHash('sha256').update(id).digest('hex');
    const hashBigInt = BigInt('0x' + hashHex) % publicKeyRSA.n;
    const recovered  = publicKeyRSA.verify(BigInt(signature));

    if (recovered !== hashBigInt) {
      console.log(`[VERIFY] Firma inválida para ID: ${id}`);
      return res.status(401).json({ error: 'Firma inválida' });
    }

    const ids = await loadIds();
    if (ids.includes(id)) {
      console.log(`[VERIFY] ID duplicado: ${id}`);
      return res.status(409).json({ error: 'ID ya registrado — no válido' });
    }

    ids.push(id);
    await saveIds(ids);
    console.log(`[VERIFY] ID registrado: ${id}`);
    res.json({ ok: true, registered: id });

  } catch (err) {
    console.error('Error en verificación:', err.message);
    res.status(500).json({ error: 'Error interno', detail: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ENDPOINTS — PAILLIER
// ═══════════════════════════════════════════════════════════════════════════

app.get('/hello', (req, res) => {
  res.send("hello");
});

app.get('/paillier-public-key', (req, res) => {
  if (!publicKey)
    return res.status(503).json({ error: 'Claves aún no generadas' });
  res.json({ n: publicKey.n.toString(), g: publicKey.g.toString() });
});

app.post('/paillier-decrypt', async (req, res) => {
  const { ciphertext, aggregated, zone, sentAt } = req.body;
  if (!ciphertext)
    return res.status(400).json({ error: 'Falta campo: ciphertext' });

  try {
    const m = privateKey.decrypt(BigInt(ciphertext));
    const { sensorType, timestamp, consumption } = unpackMessage(m);
    const data = await loadData();

    if (aggregated && zone) {
      const hour = hourKey(new Date(sentAt).getTime());
      if (!data.zones)             data.zones = {};
      if (!data.zones[zone])       data.zones[zone] = {};
      if (!data.zones[zone][hour]) data.zones[zone][hour] = [];
      data.zones[zone][hour].push({ consumption, count: 100, sentAt });
      console.log(`[PAILLIER] Agregado: zona=${zone} | consumption=${consumption} | ${hour}`);
    } else {
      const hour = hourKey(timestamp);
      if (!data[sensorType])       data[sensorType] = {};
      if (!data[sensorType][hour]) data[sensorType][hour] = [];
      data[sensorType][hour].push({ consumption, receivedAt: new Date(timestamp).toISOString() });
      console.log(`[PAILLIER] Individual: ${sensorType} | ${consumption} | ${hour}`);
    }

    
    try {
  await saveData(data);
  console.log('[SAVE] OK');
} catch (err) {
  console.error('[SAVE] ERROR:', err);
}
    res.json({ ok: true });

  } catch (err) {
    console.error('Error al descifrar:', err.message);
    res.status(500).json({ error: 'Error al descifrar', detail: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ENDPOINTS — SENSORES BLIND (modificados: sin sensors.json ni sensor-keys.json)
// ═══════════════════════════════════════════════════════════════════════════

// Mapa en memoria de claves públicas recibidas de sensores registrados
// { sensorId → { n, e } }
const registeredSensorKeys = new Map();

// PASO 1: Registro del sensor
// Verifica credenciales en memoria, guarda clave pública en memoria,
// genera challenge cifrado con la clave pública del sensor,
// y prueba identidad del servidor firmando hash(sessionId).
app.post('/sensor/register', (req, res) => {
  const { id, password, publicKeyN, publicKeyE } = req.body;

  if (!id || !password || !publicKeyN || !publicKeyE)
    return res.status(400).json({ error: 'Faltan campos: id, password, publicKeyN, publicKeyE' });

  // Verifica credenciales contra el mapa en memoria
  if (SENSOR_CREDENTIALS[id] !== password) {
    console.log(`[SENSOR AUTH] Credenciales inválidas — id: ${id}`);
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  // Guarda/actualiza clave pública del sensor en memoria
  registeredSensorKeys.set(id, { n: publicKeyN, e: publicKeyE });

  // Genera challenge y lo cifra con la clave pública del sensor
  const challengeRaw    = crypto.randomBytes(16).toString('hex');
  const challengeBigInt = BigInt('0x' + challengeRaw);
  const encryptedChallenge = modPow(
    challengeBigInt,
    BigInt(publicKeyE),
    BigInt(publicKeyN)
  );

  // Abre sesión pendiente de verificación
  const sessionId = generateSessionId();
  sessions.set(sessionId, {
    sensorId:  id,
    challenge: challengeRaw,
    verified:  false,
  });

  // Prueba de identidad del servidor: firma hash(sessionId)
  const sessionHashHex  = crypto.createHash('sha256').update(sessionId).digest('hex');
  const sessionHashBI   = BigInt('0x' + sessionHashHex) % publicKeyRSA.n;
  const serverSignature = privateKeyRSA.sign(sessionHashBI);

  console.log(`[SENSOR AUTH] Credenciales OK — id: ${id} | sesión: ${sessionId}`);

  res.json({
    sessionId,
    encryptedChallenge: encryptedChallenge.toString(),
    serverSignature:    serverSignature.toString(),
  });
});

// PASO 2: El sensor responde al challenge
app.post('/sensor/verify-challenge', (req, res) => {
  const { sessionId, challengeResponse } = req.body;

  if (!sessionId || !challengeResponse)
    return res.status(400).json({ error: 'Faltan campos: sessionId, challengeResponse' });

  const session = sessions.get(sessionId);
  if (!session)
    return res.status(404).json({ error: 'Sesión no encontrada o expirada' });
  if (session.verified)
    return res.status(409).json({ error: 'Sesión ya verificada' });

  if (challengeResponse !== session.challenge) {
    console.log(`[CHALLENGE] Reto fallido — id: ${session.sensorId}`);
    sessions.delete(sessionId);
    return res.status(401).json({ error: 'Challenge incorrecto — identidad no verificada' });
  }

  session.verified = true;
  console.log(`[CHALLENGE] Canal seguro establecido — sensor: ${session.sensorId}`);
  res.json({ ok: true });
});

// PASO 3: Firma ciega de la clave efímera del sensor
app.post('/sensor/blind-sign-ephemeral', (req, res) => {
  const { sessionId, blindedEphemeralHash } = req.body;

  if (!sessionId || !blindedEphemeralHash)
    return res.status(400).json({ error: 'Faltan campos: sessionId, blindedEphemeralHash' });

  const session = sessions.get(sessionId);
  if (!session)
    return res.status(404).json({ error: 'Sesión no encontrada' });
  if (!session.verified)
    return res.status(403).json({ error: 'Canal no verificado — completa el reto primero' });

  const blindSignature = privateKeyRSA.sign(BigInt(blindedEphemeralHash));
  console.log(`[BLIND SIGN] Clave efímera firmada ciegamente — sensor: ${session.sensorId}`);

  // La sesión ya cumplió su propósito: se elimina para no acumular estado
  sessions.delete(sessionId);

  res.json({ blindSignature: blindSignature.toString() });
});

// PASO 4: Envío anónimo de consumo
// Solo verifica que la firma efímera es válida (emitida por este servidor).
// No hay rastro del sensor de origen.
app.post('/sensor/consumption', async (req, res) => {
  const { ciphertext, zone, ephemeralSignature, ephemeralPubKeyHashHex } = req.body;

  if (!ciphertext || !zone || !ephemeralSignature || !ephemeralPubKeyHashHex)
    return res.status(400).json({ error: 'Faltan campos requeridos' });

  try {
    // Verifica firma efímera
    const hashBigInt = BigInt('0x' + ephemeralPubKeyHashHex) % publicKeyRSA.n;
    const recovered  = publicKeyRSA.verify(BigInt(ephemeralSignature));

    if (recovered !== hashBigInt) {
      console.log(`[CONSUMPTION] Firma efímera inválida`);
      return res.status(401).json({ error: 'Firma efímera inválida' });
    }

    // Descifra y guarda por zona/hora
    const m = privateKey.decrypt(BigInt(ciphertext));
    const { consumption, timestamp } = unpackMessage(m);
    const hour = hourKey(timestamp);

    const data = await loadData();
    if (!data.zones)             data.zones = {};
    if (!data.zones[zone])       data.zones[zone] = {};
    if (!data.zones[zone][hour]) data.zones[zone][hour] = [];

    data.zones[zone][hour].push({
      consumption,
      receivedAt: new Date().toISOString(),
    });

    await saveData(data);
    console.log(`[CONSUMPTION] zona=${zone} | consumption=${consumption} | ${hour}`);
    res.json({ ok: true });

  } catch (err) {
    console.error('[CONSUMPTION] Error:', err.message);
    res.status(500).json({ error: 'Error interno', detail: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ARRANQUE
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
  console.log(`Generando claves Paillier de ${KEY_BITS} bits...`);
  ({ publicKey, privateKey } = await paillierBigint.generateRandomKeys(KEY_BITS));
  console.log('Claves Paillier generadas.\n');

  console.log(`Generando claves RSA de ${KEY_BITS} bits...`);
  ({ publicKey: publicKeyRSA, privateKey: privateKeyRSA } = await rsa.generateKeyPair(KEY_BITS));
  console.log('Claves RSA generadas.\n');

  app.listen(PORT, () => {
    console.log(`Servidor escuchando en http://localhost:${PORT}`);
    console.log(`Usuarios válidos (cliente): ${Object.keys(USERS).join(', ')}`);
    console.log(`Sensor registrado: ${Object.keys(SENSOR_CREDENTIALS).join(', ')}`);
  });
}

main().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});