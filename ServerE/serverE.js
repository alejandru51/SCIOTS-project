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
const SENSOR_TYPE_NAMES = {
  1: 'light',
  2: 'water',
  3: 'humidity',
  4: 'temperature',
};
// Extrae los 3 campos del BigInt empaquetado
function unpackMessage(m) {
  const consumptionBits = m & 0xFFFFFFFFFFn;                          // bits 0-19
  const tsBits    = (m >> 40n) & 0xFFFFFFFFFFn;            // bits 20-59
  const typeBits    = (m >> 80n) & 0xFFFFn;                  // bits 60-75
  
  return {
    sensorType:  SENSOR_TYPE_NAMES[Number(typeBits)],
    timestamp:  Number(tsBits),
    consumption:  Number(consumptionBits),
  };
}
/* function bigIntToText(n){
  let hex = n.toString(16);
  if(hex.length % 2 !== 0){
    hex = '0'+hex;
  }
  const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte,16)));
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
} */

app.get('/paillier-public-key', (req, res) => {
  if (!publicKey) {
    return res.status(503).json({ error: 'Claves aún no generadas' });
  }
  res.json({
    n: publicKey.n.toString(),
    g: publicKey.g.toString(),
  });
});

// server.js — sustituye SOLO este handler, nada más cambia

app.post('/paillier-decrypt', async (req, res) => {
  const { ciphertext, aggregated, zone, sentAt } = req.body;

  if (!ciphertext) {
    return res.status(400).json({ error: 'Falta campo: ciphertext' });
  }

  try {
    const m = privateKey.decrypt(BigInt(ciphertext));
    const { consumption } = unpackMessage(m, aggregated === true);
    const data = await loadData();

    if (aggregated && zone) {
      // ── Mensaje agregado del agregador ───────────────────────────────
      // Estructura: data.zones[zone][hora] = [{ consumption, count, sentAt }, ...]
      const hour = hourKey(new Date(sentAt).getTime());

      if (!data.zones)         data.zones = {};
      if (!data.zones[zone])   data.zones[zone] = {};
      if (!data.zones[zone][hour]) data.zones[zone][hour] = [];

      data.zones[zone][hour].push({
        consumption,          // suma de los 100 sensores
        count: 100,
        sentAt,
      });

      console.log(`Agregado: zona=${zone} | consumption=${consumption} | ${hour}`);

    } else {
      // ── Mensaje individual directo (compatibilidad) ───────────────────
      const { sensorType, timestamp } = unpackMessage(m, false);
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