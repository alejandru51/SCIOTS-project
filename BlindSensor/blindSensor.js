'use strict';
//EJEMPLO BLINDSIGN
import crypto   from 'crypto';
import fs       from 'fs/promises';
import * as paillierBigint from 'paillier-bigint';
import { modPow, modInv }  from 'bigint-crypto-utils';
import * as rsa from 'sciots-rsa';
import coap     from 'coap';

const PROXY_HOST      = 'localhost';
const PROXY_PORT      = 5683;
const SENSOR_KEYS_DIR = './sensor-keys';
const RSA_BITS        = 2048;
const SEND_INTERVAL_MS = 5000;

// ─── Sensor único hardcodeado ──────────────────────────────────────────────
const SENSOR = {
  id:       'sensor-001',
  password: 'secret123',
  type:     'temperature',
  zone:     'zona-a',
  min_cons: 10,
  max_cons: 100,
};

const SENSOR_TYPE_CODES = {
  light:       0b0001,
  water:       0b0010,
  humidity:    0b0011,
  temperature: 0b0100,
};

// ─── Helper CoAP ─────────────────────────────────────────────────────────

function coapRequest({ method = 'POST', path, payload }) {
  return new Promise((resolve, reject) => {
    const req = coap.request({
      host:     PROXY_HOST,
      port:     PROXY_PORT,
      method,
      pathname: path,
      options:  { 'Content-Format': 'application/json' },
    });

    if (payload !== undefined) req.write(Buffer.from(JSON.stringify(payload)));

    req.on('response', (res) => {
      let raw = '';
      res.on('data', chunk => { raw += chunk.toString(); });
      res.on('end', () => {
        const [major] = res.code.split('.').map(Number);
        let body;
        try { body = JSON.parse(raw); } catch { body = { raw }; }
        resolve({ ok: major === 2, code: res.code, body });
      });
    });

    req.on('error', reject);
    req.end();
  });
}

// ─── Utilidades ───────────────────────────────────────────────────────────

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomBlindingFactor(n) {
  let r;
  do {
    const bytes = crypto.randomBytes(Math.floor(n.toString(2).length / 8));
    r = BigInt('0x' + bytes.toString('hex')) % n;
  } while (r < 2n);
  return r;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─── Persistencia de claves RSA del sensor ────────────────────────────────

async function loadOrGenerateSensorKeys(sensorId) {
  await fs.mkdir(SENSOR_KEYS_DIR, { recursive: true });
  const keyFile = `${SENSOR_KEYS_DIR}/${sensorId}.json`;

  try {
    const raw  = JSON.parse(await fs.readFile(keyFile, 'utf-8'));
    const pub  = new rsa.RsaPublicKey(BigInt(raw.n), BigInt(raw.e));
    const priv = new rsa.RsaPrivateKey(BigInt(raw.n), BigInt(raw.d));
    return { publicKey: pub, privateKey: priv };
  } catch {
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

// ─── PASO 1: Registro ─────────────────────────────────────────────────────

async function registerSensor(sensor, sensorPrivKey, sensorPubKey, serverPubKey) {
  const res = await coapRequest({
    path:    '/sensor/register',
    payload: {
      id:         sensor.id,
      password:   sensor.password,
      publicKeyN: sensorPubKey.n.toString(),
      publicKeyE: sensorPubKey.e.toString(),
    },
  });

  if (!res.ok) throw new Error(`Register fallido: ${res.body.error}`);

  const { sessionId, encryptedChallenge, serverSignature } = res.body;

  // Verifica identidad del servidor
  const sessionHashHex  = crypto.createHash('sha256').update(sessionId).digest('hex');
  const sessionHashBInt = BigInt('0x' + sessionHashHex) % serverPubKey.n;
  const recoveredSig    = serverPubKey.verify(BigInt(serverSignature));

  if (recoveredSig !== sessionHashBInt)
    throw new Error(`Identidad del servidor NO verificada para sesión ${sessionId}`);

  // Descifra el challenge con la clave privada del sensor
  const challengeBigInt = sensorPrivKey.decrypt(BigInt(encryptedChallenge));
  const challengeHex    = challengeBigInt.toString(16).padStart(32, '0');

  return { sessionId, challengeHex };
}

// ─── PASO 2: Responde al reto ─────────────────────────────────────────────

async function verifyChallenge(sessionId, challengeHex) {
  const res = await coapRequest({
    path:    '/sensor/verify-challenge',
    payload: { sessionId, challengeResponse: challengeHex },
  });

  if (!res.ok) throw new Error(`Challenge fallido: ${res.body.error}`);
}

// ─── PASO 3: Firma ciega de clave efímera ────────────────────────────────

async function getEphemeralBlindSignature(sessionId, serverPubKey) {
  const ephemeral = await rsa.generateKeyPair(RSA_BITS);
  const ephPubStr = ephemeral.publicKey.n.toString() + ':' + ephemeral.publicKey.e.toString();

  const hashHex    = crypto.createHash('sha256').update(ephPubStr).digest('hex');
  const hashBigInt = BigInt('0x' + hashHex) % serverPubKey.n;

  const r              = randomBlindingFactor(serverPubKey.n);
  const rE             = modPow(r, serverPubKey.e, serverPubKey.n);
  const blindedMessage = (hashBigInt * rE) % serverPubKey.n;

  const res = await coapRequest({
    path:    '/sensor/blind-sign-ephemeral',
    payload: { sessionId, blindedEphemeralHash: blindedMessage.toString() },
  });

  if (!res.ok) throw new Error(`Blind sign fallido: ${res.body.error}`);

  const { blindSignature } = res.body;

  const rInv      = modInv(r, serverPubKey.n);
  const signature = (BigInt(blindSignature) * rInv) % serverPubKey.n;

  return { ephemeralSignature: signature, ephemeralPubKeyHashHex: hashHex };
}

// ─── PASO 4: Envío de consumo cifrado ────────────────────────────────────

async function sendConsumption(paillierPubKey, sensor, ephemeralSignature, ephemeralPubKeyHashHex) {
  const consumption = randInt(sensor.min_cons, sensor.max_cons);
  const timestamp   = Date.now();

  const typeBits        = BigInt(SENSOR_TYPE_CODES[sensor.type]) & 0xFn;
  const tsBits          = (BigInt(timestamp) & 0xFFFFFFFFFFn) << 40n;
  const consumptionBits = BigInt(consumption) & 0xFFFFFFFFFFn;
  const m               = (typeBits << 80n) | tsBits | consumptionBits;

  const ciphertext = paillierPubKey.encrypt(m);

  const res = await coapRequest({
    path:    '/sensor/consumption',
    payload: {
      ciphertext:            ciphertext.toString(),
      zone:                  sensor.zone,
      ephemeralSignature:    ephemeralSignature.toString(),
      ephemeralPubKeyHashHex,
    },
  });

  if (!res.ok) throw new Error(`Consumption rechazado: ${res.body.error}`);

  return consumption;
}

// ─── Obtiene claves del servidor ──────────────────────────────────────────

async function fetchPaillierPublicKey() {
  const res = await coapRequest({ method: 'GET', path: '/paillier-public-key' });
  if (!res.ok) throw new Error(`Error obteniendo clave Paillier: ${res.code}`);
  const { n, g } = res.body;
  return new paillierBigint.PublicKey(BigInt(n), BigInt(g));
}

async function fetchServerRsaPublicKey() {
  const res = await coapRequest({
    path:    '/rsa-public-key',
    payload: { username: 'alice', password: 'alice51' },
  });
  if (!res.ok) throw new Error(`Error obteniendo clave RSA servidor: ${res.code}`);
  const { n, e } = res.body;
  return new rsa.RsaPublicKey(BigInt(n), BigInt(e));
}

// ─── Main ─────────────────────────────────────────────────────────────────

async function main() {
  console.log(`Sensor: ${SENSOR.id} | tipo: ${SENSOR.type} | zona: ${SENSOR.zone}`);

  console.log('\nObteniendo claves del servidor...');
  const paillierPubKey  = await fetchPaillierPublicKey();
  const serverRsaPubKey = await fetchServerRsaPublicKey();
  console.log('Claves obtenidas.\n');

  // Carga o genera claves RSA persistentes del sensor
  const { publicKey: sensorPubKey, privateKey: sensorPrivKey } =
    await loadOrGenerateSensorKeys(SENSOR.id);

  // Autenticación mutua + obtención de firma efímera (una sola vez al arrancar)
  console.log('Iniciando autenticación con el servidor...');
  let ephemeralSignature, ephemeralPubKeyHashHex;
  try {
    const { sessionId, challengeHex } =
      await registerSensor(SENSOR, sensorPrivKey, sensorPubKey, serverRsaPubKey);
    await verifyChallenge(sessionId, challengeHex);

    const eph = await getEphemeralBlindSignature(sessionId, serverRsaPubKey);
    ephemeralSignature     = eph.ephemeralSignature;
    ephemeralPubKeyHashHex = eph.ephemeralPubKeyHashHex;

    console.log('Canal seguro + firma efímera OK\n');
  } catch (err) {
    console.error(`Error en autenticación: ${err.message}`);
    process.exit(1);
  }

  // Bucle de envío periódico
  console.log(`Enviando consumo cada ${SEND_INTERVAL_MS / 1000}s...\n`);
  let totalEnviados = 0;

  while (true) {
    try {
      const consumption = await sendConsumption(
        paillierPubKey, SENSOR, ephemeralSignature, ephemeralPubKeyHashHex
      );
      totalEnviados++;
      console.log(
        `[${new Date().toISOString()}] ${SENSOR.id} | ` +
        `${SENSOR.type}: ${consumption} | zona: ${SENSOR.zone} | ` +
        `total enviados: ${totalEnviados}`
      );
    } catch (err) {
      console.error(`Error enviando consumo: ${err.message}`);
    }

    await sleep(SEND_INTERVAL_MS);
  }
}

main().catch(err => {
  console.error('Error fatal:', err);
  process.exit(1);
});