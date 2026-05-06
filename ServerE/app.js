'use-strict';
import express from 'express';
import fs from 'fs/promises';
import * as paillierBigint from 'paillier-bigint';

const PORT      = 3000;
const KEY_BITS  = 3072;
const DATA_FILE = 'sensor-data.json';

const app = express();
app.use(express.json());

let publicKey  = null;
let privateKey = null;

async function loadData() {
  try {
    const raw = await fs.readFile(DATA_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

async function saveData(data) {
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

// Devuelve la hora redondeada a la hora en punto como clave
// Ej: 2026-05-06T10:00:00.000Z
function hourKey(timestamp) {
  const d = new Date(timestamp);
  d.setMinutes(0, 0, 0);
  return d.toISOString();
}

// Extrae los 3 campos del BigInt empaquetado
function unpackMessage(m) {
  const consumptionBits = m & 0xFFFFFn;                          // bits 0-19
  const tsBits    = (m >> 20n) & 0xFFFFFFFFFFn;            // bits 20-59
  const typeBits    = (m >> 60n) & 0xFFFFn;                  // bits 60-75
  
  return {
    sensorType:  Number(typeBits),
    timestamp:  Number(tsBits),
    consumption:  Number(consumptionBits),
  };
}
function bigIntToText(n){
  let hex = n.toString(16);
  if(hex.length % 2 !== 0){
    hex = '0'+hex;
  }
  const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte,16)));
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}

app.get('/paillier-public-key', (req, res) => {
  if (!publicKey) {
    return res.status(503).json({ error: 'Claves aún no generadas' });
  }
  res.json({
    n: publicKey.n.toString(),
    g: publicKey.g.toString(),
  });
});

app.post('/paillier-decrypt', async (req, res) => {
  const { ciphertext } = req.body;

  if (!ciphertext) {
    return res.status(400).json({ error: 'Faltan campos: ciphertetxt' });
  }

  try {
    // Descifra el valor
    const m = privateKey.decrypt(BigInt(ciphertext));
    
    const {sensorType, timestamp, consumption} = unpackMessage(m);
    const sensorTypeString = bigIntToText(sensorType);
    const hour  = hourKey(timestamp);
    const data = await loadData();

    // Estructura: data[type][hour] = [ valor, valor, valor, ... ]
    if (!data[sensorTypeString]) {
      data[sensorTypeString] = {};
    }
    if (!data[sensorTypeString][hour]) {
      data[sensorTypeString][hour] = [];
    }

    data[sensorTypeString][hour].push({
      consumption,
      receivedAt: new Date(timestamp).toISOString(),
    });

    await saveData(data);

    console.log(`Recibido: ${sensorTypeString} | ${consumption} | ${hour}`);

    res.json({ ok: true });

  } catch (err) {
    console.error('Error al descifrar:', err.message);
    res.status(500).json({ error: 'Error al descifrar', detail: err.message });
  }
});


async function main() {
  console.log(`Generando claves Paillier de ${KEY_BITS} bits.`);
  ({ publicKey, privateKey } = await paillierBigint.generateRandomKeys(KEY_BITS));
  console.log('Claves generadas.\n');

  app.listen(PORT, () => {
    console.log(`Servidor escuchando en http://localhost:${PORT}`);
  });
}

main().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});