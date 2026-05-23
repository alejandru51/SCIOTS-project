'use strict';

import crypto   from 'crypto';
import fs       from 'fs/promises';
import * as paillierBigint from 'paillier-bigint';
import { modPow, modInv }  from 'bigint-crypto-utils';
import * as rsa from 'sciots-rsa';

const SERVER_BASE_URL  = 'http://localhost:3000';
const SENSOR_KEYS_DIR  = './sensor-keys';       // carpeta donde se guardan las claves RSA de cada sensor
const SENSORS_FILE     = './sensors.json';
const RSA_BITS         = 2048;
const AVG_PER_SECOND   = 1;
const LOG_EVERY_N      = 5;

const SENSOR_TYPE_CODES = {
  light:       0b0001,
  water:       0b0010,
  humidity:    0b0011,
  temperature: 0b0100,
};

// ─── Utilidades ───────────────────────────────────────────────────────────

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomDelay(avgMs) {
  return -Math.log(Math.random()) * avgMs;
}

function randomBlindingFactor(n) {
  let r;
  do {
    const bytes = crypto.randomBytes(Math.floor(n.toString(2).length / 8));
    r = BigInt('0x' + bytes.toString('hex')) % n;
  } while (r < 2n);
  return r;
}

// ─── Persistencia de claves RSA por sensor ────────────────────────────────
// Cada sensor guarda su par de claves en disco la primera vez
// En ejecuciones posteriores las reutiliza (identidad persistente)

async function loadOrGenerateSensorKeys(sensorId) {
  await fs.mkdir(SENSOR_KEYS_DIR, { recursive: true });
  const keyFile = `${SENSOR_KEYS_DIR}/${sensorId}.json`;

  try {
    const raw  = JSON.parse(await fs.readFile(keyFile, 'utf-8'));
    const pub  = new rsa.RsaPublicKey(BigInt(raw.n), BigInt(raw.e));
    const priv = new rsa.RsaPrivateKey(BigInt(raw.n), BigInt(raw.d));
    return { publicKey: pub, privateKey: priv };
  } catch {
    // Primera vez: genera y guarda
    const { publicKey, privateKey } = await rsa.generateKeyPair(RSA_BITS);
    await fs.writeFile(keyFile, JSON.stringify({
      n: publicKey.n.toString(),
      e: publicKey.e.toString(),
      d: privateKey.d.toString(),
    }, null, 2));
    console.log(`[KEYGEN] Claves generadas para ${sensorId}`);
    return { publicKey, privateKey };
  }
}

// ─── PASO 1: Registro — credenciales + clave pública ─────────────────────
async function registerSensor(sensor, sensorPrivKey, sensorPubKey, serverPubKey) {
  const res = await fetch(`${SERVER_BASE_URL}/sensor/register`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({
      id:        sensor.id,
      password:  sensor.password,
      publicKeyN: sensorPubKey.n.toString(),
      publicKeyE: sensorPubKey.e.toString(),
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(`Register fallido: ${err.error}`);
  }

  const { sessionId, encryptedChallenge, serverSignature } = await res.json();

  // ── Verifica identidad del servidor ───────────────────────────────────
  // El servidor firma hash(sessionId) con su clave privada RSA
  // El sensor verifica con la clave pública RSA del servidor
  const sessionHashHex  = crypto.createHash('sha256').update(sessionId).digest('hex');
  const sessionHashBInt = BigInt('0x' + sessionHashHex) % serverPubKey.n;
  const recoveredSig    = serverPubKey.verify(BigInt(serverSignature));

  if (recoveredSig !== sessionHashBInt) {
    throw new Error(`Identidad del servidor NO verificada para sesión ${sessionId}`);
  }

  // ── Descifra el challenge con la clave privada del sensor ─────────────
  const challengeBigInt = sensorPrivKey.decrypt(BigInt(encryptedChallenge));
  const challengeHex    = challengeBigInt.toString(16).padStart(32, '0');

  return { sessionId, challengeHex };
}

// ─── PASO 2: Responde al reto ─────────────────────────────────────────────
async function verifyChallenge(sessionId, challengeHex) {
  const res = await fetch(`${SERVER_BASE_URL}/sensor/verify-challenge`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ sessionId, challengeResponse: challengeHex }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(`Challenge fallido: ${err.error}`);
  }
}

// ─── PASO 3: Firma ciega de clave efímera ────────────────────────────────
// Genera un par efímero, hace hash de la clave pública efímera,
// lo ciega y pide al servidor que lo firme ciegamente
async function getEphemeralBlindSignature(sessionId, serverPubKey) {
  // Genera par efímero
  const ephemeral = await rsa.generateKeyPair(RSA_BITS);
  const ephPubStr = ephemeral.publicKey.n.toString() + ':' + ephemeral.publicKey.e.toString();

  // Hash de la clave pública efímera
  const hashHex    = crypto.createHash('sha256').update(ephPubStr).digest('hex');
  const hashBigInt = BigInt('0x' + hashHex) % serverPubKey.n;

  // Ciega el hash: B = hash * r^e mod n
  const r              = randomBlindingFactor(serverPubKey.n);
  const rE             = modPow(r, serverPubKey.e, serverPubKey.n);
  const blindedMessage = (hashBigInt * rE) % serverPubKey.n;

  // Pide firma ciega al servidor dentro del canal seguro
  const res = await fetch(`${SERVER_BASE_URL}/sensor/blind-sign-ephemeral`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({
      sessionId,
      blindedEphemeralHash: blindedMessage.toString(),
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(`Blind sign fallido: ${err.error}`);
  }

  const { blindSignature } = await res.json();

  // Descega: S = S' * r^-1 mod n = hash^d
  const rInv      = modInv(r, serverPubKey.n);
  const signature = (BigInt(blindSignature) * rInv) % serverPubKey.n;

  return { ephemeralSignature: signature, ephemeralPubKeyHashHex: hashHex };
}

// ─── PASO 4: Envío anónimo de consumo cifrado con Paillier ───────────────
async function sendConsumption(paillierPubKey, sensor, ephemeralSignature, ephemeralPubKeyHashHex) {
  const consumption = randInt(sensor.min_cons, sensor.max_cons);
  const timestamp   = Date.now();

  const typeBits        = BigInt(SENSOR_TYPE_CODES[sensor.type]) & 0xFn;
  const tsBits          = (BigInt(timestamp) & 0xFFFFFFFFFFn) << 40n;
  const consumptionBits = BigInt(consumption) & 0xFFFFFFFFFFn;
  const m               = (typeBits << 80n) | tsBits | consumptionBits;

  const ciphertext = paillierPubKey.encrypt(m);

  const res = await fetch(`${SERVER_BASE_URL}/sensor/consumption`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({
      ciphertext:            ciphertext.toString(),
      zone:                  sensor.zone,
      ephemeralSignature:    ephemeralSignature.toString(),
      ephemeralPubKeyHashHex,
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(`Consumption rechazado: ${err.error}`);
  }

  return consumption;
}

// ─── Obtiene clave pública Paillier del servidor ──────────────────────────
async function fetchPaillierPublicKey() {
  const res = await fetch(`${SERVER_BASE_URL}/paillier-public-key`);
  if (!res.ok) throw new Error(`Error obteniendo clave Paillier: ${res.status}`);
  const { n, g } = await res.json();
  return new paillierBigint.PublicKey(BigInt(n), BigInt(g));
}

// ─── Obtiene clave pública RSA del servidor ───────────────────────────────
async function fetchServerRsaPublicKey() {
  const res = await fetch(`${SERVER_BASE_URL}/rsa-public-key`, {
    headers: {
      // Usamos un usuario admin para obtener la clave pública del servidor
      // En producción esto sería un endpoint público sin auth
      'X-Username': 'alice',
      'X-Password': 'alice51',
    },
  });
  if (!res.ok) throw new Error(`Error obteniendo clave RSA servidor: ${res.status}`);
  const { n, e } = await res.json();
  return new rsa.RsaPublicKey(BigInt(n), BigInt(e));
}

// ─── Ciclo de vida completo de un sensor ─────────────────────────────────
async function runSensor(sensor, paillierPubKey, serverRsaPubKey, avgIntervalMs, logCounter) {
  // Carga o genera claves RSA persistentes
  const { publicKey: sensorPubKey, privateKey: sensorPrivKey } =
    await loadOrGenerateSensorKeys(sensor.id);

  // Autenticación mutua + canal seguro
  let sessionId, ephemeralSignature, ephemeralPubKeyHashHex;
  try {
    const reg = await registerSensor(sensor, sensorPrivKey, sensorPubKey, serverRsaPubKey);
    sessionId = reg.sessionId;
    await verifyChallenge(sessionId, reg.challengeHex);

    const eph = await getEphemeralBlindSignature(sessionId, serverRsaPubKey);
    ephemeralSignature    = eph.ephemeralSignature;
    ephemeralPubKeyHashHex = eph.ephemeralPubKeyHashHex;

    console.log(`[${sensor.id}] Canal seguro + firma efímera OK`);
  } catch (err) {
    console.error(`[${sensor.id}] ERROR en setup: ${err.message}`);
    return; // Este sensor no arranca si falla el setup
  }

  // Bucle de envío de consumo
  while (true) {
    const delay = randomDelay(avgIntervalMs);
    await new Promise(resolve => setTimeout(resolve, delay));

    try {
      const consumption = await sendConsumption(
        paillierPubKey, sensor, ephemeralSignature, ephemeralPubKeyHashHex
      );

      logCounter.count++;
      if (logCounter.count % LOG_EVERY_N === 0) {
        console.log(
          `[${new Date().toISOString()}] ${sensor.id} | ` +
          `${sensor.type}: ${consumption} | zona: ${sensor.zone} | ` +
          `total enviados: ${logCounter.count}`
        );
      }
    } catch (err) {
      console.error(`[${sensor.id}] ERROR enviando consumo: ${err.message}`);
    }
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────
async function main() {
  // Carga sensores desde fichero
  let sensors;
  try {
    
    sensors = JSON.parse(await fs.readFile(SENSORS_FILE, 'utf-8'));
    console.error(`Se encontró`);
  } catch {
    console.error(`No se encontró ${SENSORS_FILE}. Colócalo junto a este script.`);
    process.exit(1);
  }

  console.log(`Cargados ${sensors.length} sensores desde ${SENSORS_FILE}`);

  // Obtiene claves del servidor
  console.log('Obteniendo clave pública Paillier del servidor...');
  const paillierPubKey = await fetchPaillierPublicKey();
  console.log('Obteniendo clave pública RSA del servidor...');
  const serverRsaPubKey = await fetchServerRsaPublicKey();
  console.log('Claves del servidor obtenidas.\n');

  const avgIntervalMs = (sensors.length / AVG_PER_SECOND) * 1000;
  console.log(`Arrancando ${sensors.length} sensores`);
  console.log(`Media global : ${AVG_PER_SECOND} envíos/segundo`);
  console.log(`Media por sensor: cada ${(avgIntervalMs / 1000).toFixed(1)}s\n`);

  const logCounter = { count: 0 };

  // Arranca todos los sensores en paralelo con un pequeño escalonado
  // para no saturar el servidor con 100 registros simultáneos
  for (let i = 0; i < sensors.length; i++) {
    const sensor = sensors[i];
    // Escalonado: 200ms entre arranques para no saturar el endpoint /register
    setTimeout(() => {
      runSensor(sensor, paillierPubKey, serverRsaPubKey, avgIntervalMs, logCounter)
        .catch(err => console.error(`[${sensor.id}] Error fatal: ${err.message}`));
    }, i * 200);
  }
}

main().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});