'use strict';

import express from 'express';
import * as paillierBigint from 'paillier-bigint';

const AGGREGATOR_PORT = 3001;
const SERVER_BASE_URL = 'http://localhost:3000';
const BATCH_SIZE      = 100;
const FLUSH_INTERVAL  = 30_000;

const app = express();
app.use(express.json());

let publicKey = null;

// Pool separado por zona: { "zona-1": [BigInt, ...], "zona-2": [...], ... }
const pool = {};

const stats = { received: 0, flushed: 0, batches: 0 };

async function fetchPublicKey() {
  const res = await fetch(`${SERVER_BASE_URL}/paillier-public-key`);
  if (!res.ok) throw new Error(`Error obteniendo clave pública: ${res.status}`);
  const { n, g } = await res.json();
  return new paillierBigint.PublicKey(BigInt(n), BigInt(g));
}

async function flushZone(zone) {
  if (!pool[zone] || pool[zone].length === 0) return;

  const batch = pool[zone].splice(0, BATCH_SIZE);

  let aggregated = batch[0];
  for (let i = 1; i < batch.length; i++) {
    aggregated = publicKey.addition(aggregated, batch[i]);
  }

  const sentAt = new Date().toISOString();

  try {
    const res = await fetch(`${SERVER_BASE_URL}/paillier-decrypt`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        ciphertext: aggregated.toString(),
        aggregated: true,
        zone,           // en claro
        sentAt,         // fecha del momento del flush
      }),
    });

    if (!res.ok) throw new Error(`Servidor respondió ${res.status}`);

    stats.batches++;
    stats.flushed += batch.length;
    console.log(
      `[${sentAt}] FLUSH zona=${zone} | lote=${batch.length} | ` +
      `total_flushed=${stats.flushed} | batches=${stats.batches}`
    );

  } catch (err) {
    console.error(`[ERROR] flush zona=${zone}: ${err.message} — reinsertando ${batch.length} cifrados`);
    pool[zone].unshift(...batch);
  }
}

app.get('/paillier-public-key', (req, res) => {
  if (!publicKey) return res.status(503).json({ error: 'Clave pública aún no disponible' });
  res.json({ n: publicKey.n.toString(), g: publicKey.g.toString() });
});

app.post('/paillier-decrypt', async (req, res) => {
  const { ciphertext, zone } = req.body;

  if (!ciphertext || !zone) {
    return res.status(400).json({ error: 'Faltan campos: ciphertext, zone' });
  }

  if (!pool[zone]) pool[zone] = [];
  pool[zone].push(BigInt(ciphertext));
  stats.received++;

  if (stats.received % 50 === 0) {
    const poolSizes = Object.entries(pool)
      .map(([z, arr]) => `${z}:${arr.length}`)
      .join(' | ');
    console.log(`[${new Date().toISOString()}] recibidos=${stats.received} | pool=[${poolSizes}]`);
  }

  if (pool[zone].length >= BATCH_SIZE) {
    flushZone(zone).catch(err =>
      console.error(`[ERROR] flush background zona=${zone}: ${err.message}`)
    );
  }

  res.json({ ok: true, zone, queued: pool[zone]?.length ?? 0 });
});

setInterval(async () => {
  for (const zone of Object.keys(pool)) {
    if (pool[zone]?.length > 0) {
      console.log(`[PERIODIC FLUSH] zona=${zone} | ${pool[zone].length} pendientes`);
      await flushZone(zone).catch(console.error);
    }
  }
}, FLUSH_INTERVAL);

async function main() {
  console.log('Obteniendo clave pública del servidor principal...');
  publicKey = await fetchPublicKey();
  console.log('Clave pública lista.\n');

  app.listen(AGGREGATOR_PORT, () => {
    console.log(`Agregador escuchando en http://localhost:${AGGREGATOR_PORT}`);
    console.log(`Batch size     : ${BATCH_SIZE} mensores por zona`);
    console.log(`Flush periódico: cada ${FLUSH_INTERVAL / 1000}s\n`);
  });
}

main().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});