'use strict';
import express from 'express';
import fs      from 'fs/promises';
import crypto  from 'crypto';
import * as paillierBigint from 'paillier-bigint';
import * as rsa from 'sciots-rsa';

const PORT      = 3000;
const KEY_BITS  = 3072;
const DATA_FILE = 'sensor-data.json';
const IDS_FILE  = 'signed-ids.json';

const app = express();
app.use(express.json());

// ── Claves separadas: Paillier para sensores, RSA para firma ciega ─────────
let publicKey     = null;   // Paillier
let privateKey    = null;   // Paillier
let publicKeyRSA  = null;   // RSA
let privateKeyRSA = null;   // RSA

const USERS = {
  'alice': 'alice51',
  'bob':   'bob51',
};

// ─── Persistencia ─────────────────────────────────────────────────────────
async function loadData() {
  try { return JSON.parse(await fs.readFile(DATA_FILE, 'utf-8')); }
  catch { return {}; }
}

async function saveData(data) {
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

async function loadIds() {
  try { return JSON.parse(await fs.readFile(IDS_FILE, 'utf-8')); }
  catch { return []; }
}

async function saveIds(ids) {
  await fs.writeFile(IDS_FILE, JSON.stringify(ids, null, 2), 'utf-8');
}

// ─── Helpers ──────────────────────────────────────────────────────────────
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

// ─── RSA: entrega clave pública tras autenticar ────────────────────────────
app.get('/rsa-public-key', (req, res) => {
  const username = req.headers['x-username'];
  const password = req.headers['x-password'];

  if (!username || !password) {
    return res.status(401).json({ error: 'Credenciales no proporcionadas' });
  }
  if (USERS[username] !== password) {
    console.log(`[AUTH] Intento fallido — usuario: ${username}`);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  console.log(`[AUTH] Acceso concedido — usuario: ${username}`);
  res.json({
    n: publicKeyRSA.n.toString(),
    e: publicKeyRSA.e.toString(),
  });
});

// ─── RSA: firma el mensaje cegado sin ver el ID real ──────────────────────
app.post('/blind-sign', (req, res) => {
  const { blindedMessage } = req.body;
  if (!blindedMessage) {
    return res.status(400).json({ error: 'Falta campo: blindedMessage' });
  }

  // S' = blindedMessage^d mod n
  const blindSignature = privateKeyRSA.sign(BigInt(blindedMessage));
  console.log(`[SIGN] Mensaje cegado firmado.`);
  res.json({ blindSignature: blindSignature.toString() });
});

// ─── RSA: verifica firma desencegada y registra ID ────────────────────────
app.post('/verify-signature', async (req, res) => {
  const { id, signature } = req.body;
  if (!id || !signature) {
    return res.status(400).json({ error: 'Faltan campos: id o signature' });
  }

  try {
    // 1. Recalcula hash(id) mod n
    const hashHex    = crypto.createHash('sha256').update(id).digest('hex');
    const hashBigInt = BigInt('0x' + hashHex) % publicKeyRSA.n;

    // 2. Verifica: S^e mod n debe coincidir con hash(id)
    const recovered = publicKeyRSA.verify(BigInt(signature));
    if (recovered !== hashBigInt) {
      console.log(`[VERIFY] Firma inválida para ID: ${id}`);
      return res.status(401).json({ error: 'Firma inválida' });
    }

    // 3. Comprueba duplicados
    const ids = await loadIds();
    if (ids.includes(id)) {
      console.log(`[VERIFY]  ID duplicado: ${id}`);
      return res.status(409).json({ error: 'ID ya registrado — no válido' });
    }

    // 4. Registra el ID
    ids.push(id);
    await saveIds(ids);

    console.log(`[VERIFY] ID registrado: ${id}`);
    res.json({ ok: true, registered: id });

  } catch (err) {
    console.error('Error en verificación:', err.message);
    res.status(500).json({ error: 'Error interno', detail: err.message });
  }
});

// ─── Paillier: entrega clave pública a sensores/agregador ─────────────────
app.get('/paillier-public-key', (req, res) => {
  if (!publicKey) {
    return res.status(503).json({ error: 'Claves aún no generadas' });
  }
  res.json({
    n: publicKey.n.toString(),
    g: publicKey.g.toString(),
  });
});

// ─── Paillier: descifra lecturas de sensores (individuales o agregadas) ───
app.post('/paillier-decrypt', async (req, res) => {
  const { ciphertext, aggregated, zone, sentAt } = req.body;

  if (!ciphertext) {
    return res.status(400).json({ error: 'Falta campo: ciphertext' });
  }

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
      console.log(`Agregado: zona=${zone} | consumption=${consumption} | ${hour}`);

    } else {
      const hour = hourKey(timestamp);
      if (!data[sensorType])       data[sensorType] = {};
      if (!data[sensorType][hour]) data[sensorType][hour] = [];

      data[sensorType][hour].push({
        consumption,
        receivedAt: new Date(timestamp).toISOString(),
      });
      console.log(`Individual: ${sensorType} | ${consumption} | ${hour}`);
    }

    await saveData(data);
    res.json({ ok: true });

  } catch (err) {
    console.error('Error al descifrar:', err.message);
    res.status(500).json({ error: 'Error al descifrar', detail: err.message });
  }
});

// ─── Arranque ─────────────────────────────────────────────────────────────
async function main() {
  console.log(`Generando claves Paillier de ${KEY_BITS} bits...`);
  ({ publicKey, privateKey } = await paillierBigint.generateRandomKeys(KEY_BITS));
  console.log('Claves Paillier generadas.\n');

  console.log(`Generando claves RSA de ${KEY_BITS} bits...`);
  ({ publicKey: publicKeyRSA, privateKey: privateKeyRSA } = await rsa.generateKeyPair(KEY_BITS));
  console.log('Claves RSA generadas.\n');

  app.listen(PORT, () => {
    console.log(`Servidor escuchando en http://localhost:${PORT}`);
    console.log(`Usuarios válidos: ${Object.keys(USERS).join(', ')}\n`);
  });
}

main().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});