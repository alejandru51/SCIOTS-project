/**
 * server.js — Device Server (simulador sensor IoT screenless)
 *
 *
 * FLUJO COMPLETO:
 *  Arranque  → genera claves RSA del dispositivo (ASYNC, dentro de app.listen)
 *           → obtiene manufacturer cert del auth server (bootstrap)
 *  Paso 1   → POST /register → envía mfr cert al auth server → login/consent
 *  Paso 2   → GET /callback  → recibe code + signature
 *           → construye sensor cert LOCALMENTE
 *  Paso 3   → POST /get-token → intercambia cert + code por JWT
 *  Paso 4   → envío automático de métricas cada 10 segundos
 */

import 'dotenv/config';
import express      from 'express';
import bodyParser   from 'body-parser';
import cookieParser from 'cookie-parser';
import session      from 'express-session';
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import fetch        from 'node-fetch';
import { createHash,randomBytes } from 'crypto';
import { v4 as uuidv4 } from 'uuid';

import {
  generateKeyPair,
  exportPublicKey,
  exportPrivateKey,
  importPublicKey,
  importPrivateKey,
  verifySignature,
  encryptData,
  signData
} from './helpers/rsaHelpers.js';

// ── Captura errores no controlados para evitar silent exits ────────
process.on('uncaughtException', (err) => {
  console.error('💥 uncaughtException:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('💥 unhandledRejection:', reason);
  process.exit(1);
});

const __dirname = dirname(fileURLToPath(import.meta.url));
const app  = express();
const PORT = process.env.PORT || 4000;

const AUTH_SERVER_URL   = process.env.AUTH_SERVER_URL   || 'http://localhost:3000';
const DEVICE_SERVER_URL = process.env.DEVICE_SERVER_URL || 'http://localhost:4000';
const DEVICE_ID         = process.env.DEVICE_ID         || 'sensor-iot-001';
const MANUFACTURER      = process.env.MANUFACTURER      || 'AcmeSensors';
const ZONE              = process.env.ZONE              || 'ZoneA';
const LOCATION          = process.env.LOCATION          || 'Building-1-Floor-2';
const ANONIMOUS_ID         = process.env.ANONIMOUS_ID         || 'null';
// ── Directorios ────────────────────────────────────────────────────
const DATA_DIR = join(__dirname, 'data');
const KEYS_DIR = join(__dirname, 'keys');
[DATA_DIR, KEYS_DIR].forEach(d => { if (!existsSync(d)) mkdirSync(d, { recursive: true }); });

// ── Archivos persistentes ─────────────────────────────────────────
const TOKEN_FILE       = join(DATA_DIR, 'token.json');
const AUTH_CODE_FILE   = join(DATA_DIR, 'authorizationCode.json');
const SENSOR_CERT_FILE = join(DATA_DIR, 'sensorCertificate.json');
const MFR_CERT_FILE    = join(DATA_DIR, 'manufacturerCertificate.json');
const DEV_PUB_FILE     = join(KEYS_DIR, 'device-public.json');
const DEV_PRIV_FILE    = join(KEYS_DIR, 'device-private.json');
const AUTH_PUB_KEY_FILE = join(DATA_DIR, 'authPublicKey.json');
const EPHEMERAL_FILE = join(DATA_DIR, 'ephemeral.json');
// ── Helpers JSON ───────────────────────────────────────────────────
function readJSON(fp, def = null) {
  try { return existsSync(fp) ? JSON.parse(readFileSync(fp, 'utf8')) : def; }
  catch { return def; }
}
function writeJSON(fp, data) {
  writeFileSync(fp, JSON.stringify(data, null, 2), 'utf8');
}

// ── Estado interno ─────────────────────────────────────────────────
let metricsInterval    = null;
let metricsBlindInterval = null;
let DEVICE_PUBLIC_KEY_OBJ = null;  // se asigna en initKeys(), NO en top-level
const logs = [];

function addLog(msg, type = 'info') {
  const entry = { msg, type, ts: new Date().toISOString() };
  logs.unshift(entry);
  if (logs.length > 100) logs.pop();
  const icon = type === 'error' ? '❌' : type === 'success' ? '✅' : type === 'warn' ? '⚠️' : 'ℹ️';
  console.log(`[Device][${type.toUpperCase()}] ${icon} ${msg}`);
}
// ── Middlewares ────────────────────────────────────────────────────
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({ secret: 'device_secret', resave: false, saveUninitialized: false }));
// ══════════════════════════════════════════════════════════════════
// GET / — Panel Bootstrap del sensor
// ══════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  const token      = readJSON(TOKEN_FILE);
  const sensorCert = readJSON(SENSOR_CERT_FILE);
  const isReg      = !!sensorCert;
  const hasToken   = !!token;
  const isSending  = metricsInterval !== null;
  const isBlind    = metricsBlindInterval !== null;
  res.send(buildDashboard({ isReg, hasToken, isSending, isBlind, token, sensorCert }));
});
// ══════════════════════════════════════════════════════════════════
// INIT KEYS — genera o carga claves RSA del dispositivo
// Movido aquí para ejecutarse DENTRO de app.listen (no en top-level)
// así Node no muere silenciosamente si generateKeyPair tarda mucho
// ══════════════════════════════════════════════════════════════════
async function initKeys() {
  if (!existsSync(DEV_PUB_FILE) || !existsSync(DEV_PRIV_FILE)) {
    addLog('Generando claves RSA 2048 bits del dispositivo (sciots-rsa)...');
    addLog('Esto puede tardar unos segundos...');

    const { publicKey, privateKey } = await new Promise((resolve, reject) => {
      try {
        resolve(generateKeyPair(2048));
      } catch (err) {
        reject(err);
      }
    });

    writeJSON(DEV_PUB_FILE,  exportPublicKey(publicKey));
    writeJSON(DEV_PRIV_FILE, exportPrivateKey(privateKey));
    DEVICE_PUBLIC_KEY_OBJ = exportPublicKey(publicKey);
    addLog('Claves RSA del dispositivo generadas.', 'success');
  } else {
    DEVICE_PUBLIC_KEY_OBJ = readJSON(DEV_PUB_FILE);
    addLog('Claves RSA del dispositivo cargadas desde disco.');
  }
}

//SERVIDOR
// ══════════════════════════════════════════════════════════════════
// BOOTSTRAP: obtener manufacturer certificate del auth server
// ══════════════════════════════════════════════════════════════════
async function initManufacturerCertificate() {
  if (existsSync(MFR_CERT_FILE)) {
    addLog('Manufacturer certificate ya existe en disco.');
    return;
  }

  addLog('Solicitando manufacturer certificate al Auth Server...');
  try {
    const resp = await fetch(`${AUTH_SERVER_URL}/authserver/bootstrap-manufacturer-cert`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        deviceId:     DEVICE_ID,
        publicKey:    DEVICE_PUBLIC_KEY_OBJ,
        manufacturer: MANUFACTURER
      })
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.message || 'Error en bootstrap');
    }

    const { manufacturerCertificate } = await resp.json();

    const pubKeyResp = await fetch(`${AUTH_SERVER_URL}/authserver/public-key`);
    const { publicKey: authPubKey } = await pubKeyResp.json();

    const isValid = verifySignature(
      manufacturerCertificate.payload,
      manufacturerCertificate.signature,
      authPubKey
    );

    if (!isValid) throw new Error('La firma del manufacturer certificate no es válida');

    writeJSON(MFR_CERT_FILE, manufacturerCertificate);
    writeJSON(AUTH_PUB_KEY_FILE, authPubKey);  // ← NUEVO
    addLog('Manufacturer certificate y clave pública del servidor guardados.', 'success');
  } catch (err) {
    addLog(`Error obteniendo manufacturer certificate: ${err.message}`, 'error');
  }
}

// ══════════════════════════════════════════════════════════════════
// POST /register — Inicia el flujo de registro
// ══════════════════════════════════════════════════════════════════
app.post('/register', async (req, res) => {
  addLog('Iniciando registro del dispositivo...');

  if (!DEVICE_PUBLIC_KEY_OBJ) {
    addLog('Las claves RSA todavía no están listas. Espera unos segundos y vuelve a intentarlo.', 'warn');
    return res.redirect('/');
  }

  const mfrCert = readJSON(MFR_CERT_FILE);
  if (!mfrCert) {
    addLog('No se encontró manufacturer certificate. Reinicia el servidor.', 'error');
    return res.redirect('/');
  }

  try {
    // Firma el manufacturerCertificate con la clave privada del sensor
    const devicePrivateKey = readJSON(DEV_PRIV_FILE);
    const certSignature = signData(mfrCert, devicePrivateKey);

    const resp = await fetch(`${AUTH_SERVER_URL}/authserver/register-device`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        manufacturerCertificate: mfrCert,
        certSignature,
        deviceId:     DEVICE_ID,
        publicKey:    DEVICE_PUBLIC_KEY_OBJ,
        redirect_uri: `${DEVICE_SERVER_URL}/callback`
      }),
      redirect: 'manual'
    });

    if (resp.status === 302 || resp.status === 301) {
      const location = resp.headers.get('location');
      addLog('Auth Server validó el dispositivo. Redirigiendo a login...');
      return res.redirect(location);
    }

    const data = await resp.json();
    addLog(`Error en registro: ${data.message}`, 'error');
    res.redirect('/');
  } catch (err) {
    addLog(`Error de red con Auth Server: ${err.message}`, 'error');
    res.redirect('/');
  }
});
// ══════════════════════════════════════════════════════════════════
// GET /callback — Auth server redirige aquí tras aprobar/rechazar
// ══════════════════════════════════════════════════════════════════
app.get('/callback', (req, res) => {
  const { code, signature, issuedAt, error } = req.query;

  if (error) {
    addLog(`Registro rechazado: ${error}`, 'warn');
    return res.redirect('/');
  }

  if (!code || !signature || !issuedAt) { 
    addLog('Callback inválido: faltan code, signature o issuedAt', 'error');
    return res.redirect('/');
  }

  addLog(`Authorization code recibido: ${code.substring(0, 8)}...`);
  addLog('Construyendo sensor certificate LOCALMENTE...');

  writeJSON(AUTH_CODE_FILE, { code, receivedAt: new Date().toISOString() });

  const mfrCert = readJSON(MFR_CERT_FILE);
  const sensorPayload = {
    deviceId:     DEVICE_ID,
    publicKey:    DEVICE_PUBLIC_KEY_OBJ,
    manufacturer: mfrCert ? mfrCert.payload.manufacturer : MANUFACTURER,
    issuedAt:     decodeURIComponent(issuedAt),
    signedBy:     'AuthServer'
  };

  const sensorCertificate = {
    payload:   sensorPayload,
    signature: decodeURIComponent(signature)
  };

  writeJSON(SENSOR_CERT_FILE, sensorCertificate);
  addLog('Sensor certificate construido y guardado localmente. ✅', 'success');
  addLog('Estado: Dispositivo registrado. Puedes obtener el token.', 'success');

  res.redirect('/');
});

// ══════════════════════════════════════════════════════════════════
// POST /get-token — Intercambia auth code + sensor cert por JWT
// ══════════════════════════════════════════════════════════════════
app.post('/get-token', async (req, res) => {
  addLog('Solicitando JWT al Auth Server...');

  const authCodeData = readJSON(AUTH_CODE_FILE);
  const sensorCert   = readJSON(SENSOR_CERT_FILE);

  if (!authCodeData || !sensorCert) {
    addLog('Faltan authorizationCode o sensorCertificate en disco', 'error');
    return res.redirect('/');
  }

  try {
    // Firma el sensorCertificate con la clave privada del sensor
    const devicePrivateKey = readJSON(DEV_PRIV_FILE);
    const certSignature = signData(sensorCert, devicePrivateKey);

    const resp = await fetch(`${AUTH_SERVER_URL}/authserver/token`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        authorizationCode: authCodeData.code,
        sensorCertificate: sensorCert,
        certSignature
      })
    });

    const data = await resp.json();

    if (!resp.ok) {
      addLog(`Error obteniendo token: ${data.message}`, 'error');
      return res.redirect('/');
    }

    writeJSON(TOKEN_FILE, {
      access_token: data.access_token,
      token_type:   data.token_type,
      expires_in:   data.expires_in,
      obtainedAt:   new Date().toISOString()
    });

    addLog('JWT obtenido y guardado en token.json ✅', 'success');
    addLog('Iniciando envío automático de métricas cada 10 segundos...');
    startMetrics();
    res.redirect('/');
  } catch (err) {
    addLog(`Error de red con Auth Server: ${err.message}`, 'error');
    res.redirect('/');
  }
});

// ══════════════════════════════════════════════════════════════════
// POST /stop-metrics — Detiene el envío automático
// ══════════════════════════════════════════════════════════════════
app.post('/stop-metrics', (req, res) => {
  if (metricsInterval) {
    clearInterval(metricsInterval);
    metricsInterval = null;
    addLog('Envío de métricas detenido.', 'warn');
  }
  res.redirect('/');
});

// ══════════════════════════════════════════════════════════════════
// POST /reset — Borra todos los datos del dispositivo
// ══════════════════════════════════════════════════════════════════
app.post('/reset', (req, res) => {
  if (metricsInterval) { clearInterval(metricsInterval); metricsInterval = null; }
  if (metricsBlindInterval) { clearInterval(metricsBlindInterval); metricsBlindInterval = null; }
  [TOKEN_FILE, AUTH_CODE_FILE, SENSOR_CERT_FILE, EPHEMERAL_FILE].forEach(f => {
    if (existsSync(f)) unlinkSync(f);
  });
  logs.length = 0;
  addLog('Dispositivo reseteado. Estado: No registrado.', 'warn');
  res.redirect('/');
});

// ══════════════════════════════════════════════════════════════════
// POST /blind-sign-demo — Demostración de firma ciega RSA
//
// El dispositivo actúa como cliente del esquema:
//  1. Genera mensaje m = hash del deviceId + timestamp
//  2. Obtiene clave pública del servidor (n, e)
//  3. Genera factor ciego aleatorio r  (0 < r < n, gcd(r,n)=1)
//  4. Ciega:   m' = m * pow(r, e, n) mod n
//  5. Envía m' al auth-server → POST /authserver/blind-sign
//  6. Recibe firma ciega s'
//  7. Desciega: s = s' * modInverse(r, n) mod n
//  8. Verifica: pow(s, e, n) == m
// ══════════════════════════════════════════════════════════════════
app.post('/blind-sign-demo', async (req, res) => {
  addLog('🔏 Iniciando firma ciega RSA-Chaum...');

  const tokenData = readJSON(TOKEN_FILE);
  if (!tokenData) {
    addLog('Se necesita token JWT activo.', 'error');
    return res.redirect('/');
  }
  const authPubKeyRaw = readJSON(AUTH_PUB_KEY_FILE);
  if (!authPubKeyRaw) {
    addLog('Clave pública del servidor no encontrada.', 'error');
    return res.redirect('/');
  }

  try {
    const serverPubKey = importPublicKey(authPubKeyRaw);
    const n = serverPubKey.n;
    const e = serverPubKey.e;

    // ── 1. Claves NUEVAS ─────────────────────────────────────────
    addLog('Generando claves RSA NUEVAS (2048 bits)...');
    const { publicKey: ephPub, privateKey: ephPriv } = await new Promise((resolve, reject) => {
      try { resolve(generateKeyPair(2048)); } catch (err) { reject(err); }
    });
    const ephPubExported  = exportPublicKey(ephPub);
    const ephPrivExported = exportPrivateKey(ephPriv);
    addLog('Claves efímeras generadas.', 'success');

    // ── 2. Cert NUEVAS ────────────────────────────────────────────
    const anonymousId = uuidv4();
    
    const ephCert = {
      anonymousId:     anonymousId,
      zone:            ZONE,
      ephemeralPubKey: ephPubExported  // va dentro del hash; el servidor nunca la ve
    };
    const ephCertStr = JSON.stringify(ephCert);

    // ── 3. m = hash(ephCertStr) mod n_servidor ────────────────────
    const hashHex = createHash('sha256').update(ephCertStr, 'utf8').digest('hex');
    const m       = BigInt('0x' + hashHex) % n;
    addLog(`m = hash(ephCert): ${m.toString().substring(0, 40)}...`);

    // ── 4. Factor ciego r — uniforme en Z_n* ──────────────────────
    // FIX: randomBytes(256)
    // encryptData añade padding OAEP → resultado sesgado, no válido como factor ciego
    const r = BigInt('0x' + randomBytes(256).toString('hex')) % (n - 2n) + 2n;
    addLog('Factor ciego r generado.');

    // ── 5. Cegar con pubkey del SERVIDOR: m' = m * r^e mod n ──────
    // El servidor recibe m' y no puede deducir m ni el cert
    const rE     = modPow(r, e, n);
    const mPrime = (m * rE) % n;
    addLog(`Token cegado m': ${mPrime.toString().substring(0, 40)}...`);

    // ── 6. Enviar m' al servidor con JWT ──────────────────────────
    const blindResp = await fetch(`${AUTH_SERVER_URL}/authserver/blind-sign`, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Accept':        'application/json',
        'Authorization': `Bearer ${tokenData.access_token}`
      },
      body: JSON.stringify({
        requestId:    anonymousId,
        blindedToken: mPrime.toString()
      })
    });

    if (!blindResp.ok) {
      const err = await blindResp.json().catch(() => ({}));
      addLog(`Error del servidor: ${err.message || blindResp.status}`, 'error');
      return res.redirect('/');
    }

    const { blindSignature: sPrimeStr } = await blindResp.json();
    const sPrime = BigInt(sPrimeStr);
    addLog(`Firma ciega s' recibida: ${sPrime.toString().substring(0, 40)}...`, 'success');

    // ── 7. Descegar: s = s' * r⁻¹ mod n ──────────────────────────
    const rInv = modInverse(r, n);
    const s    = (sPrime * rInv) % n;
    addLog(`Firma descegada s: ${s.toString().substring(0, 40)}...`, 'success');

    // ── 8. Verificar: s^e mod n == m ──────────────────────────────
    // e y n son PÚBLICOS → el sensor puede verificar sin tocar la privada del servidor
    const recovered = modPow(s, e, n);
    if (recovered !== m) {
      addLog('❌ Verificación fallida: s^e mod n ≠ m', 'error');
      return res.redirect('/');
    }
    addLog('✅ FIRMA CIEGA VERIFICADA: s^e mod n == m', 'success');
    addLog('El servidor firmó ephPubKey+zone sin verlos nunca.', 'success');

    // ── 9. Guardar ────────────────────────────────────────────────
    writeJSON(EPHEMERAL_FILE, {
      anonymousId: anonymousId,
      ephemeralCert:      ephCert,
      ephemeralCertStr:   ephCertStr,
      ephemeralPrivKey:   ephPrivExported,
      ephemeralSignature: s.toString(),
      obtainedAt:         new Date().toISOString()
    });

    addLog('Cambiando a envío con firma ciega...', 'warn');
    startMetricsBlind();

  } catch (err) {
    addLog(`Error en firma ciega: ${err.message}`, 'error');
    console.error('[BlindSign]', err);
  }

  res.redirect('/');
});
// ── Helpers BigInt para firma ciega ───────────────────────────────

// Exponenciación modular: base^exp mod mod
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

// Inverso modular con algoritmo extendido de Euclides: a^-1 mod m
function modInverse(a, m) {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error('No existe inverso modular (gcd ≠ 1)');
  return ((old_s % m) + m) % m;
}

// ══════════════════════════════════════════════════════════════════
// GET /api/status — Estado JSON para polling desde UI
// ══════════════════════════════════════════════════════════════════
app.get('/api/status', (req, res) => {
  res.json({
    deviceId:     DEVICE_ID,
    isRegistered: existsSync(SENSOR_CERT_FILE),
    hasToken:     existsSync(TOKEN_FILE),
    isSending:    metricsInterval !== null,
    isBlind: metricsBlindInterval !== null,
    keysReady:    DEVICE_PUBLIC_KEY_OBJ !== null,
    logs:         logs.slice(0, 15)
  });
});

// ══════════════════════════════════════════════════════════════════
// Envío automático de métricas cada 10 segundos
// ══════════════════════════════════════════════════════════════════
function startMetrics() {
  if (metricsInterval) return;

  metricsInterval = setInterval(async () => {
    const tokenData = readJSON(TOKEN_FILE);
    if (!tokenData) {
      addLog('Token no encontrado. Deteniendo métricas.', 'error');
      clearInterval(metricsInterval);
      metricsInterval = null;
      return;
    }

    const authPubKey = readJSON(AUTH_PUB_KEY_FILE);  // ← NUEVO
    if (!authPubKey) {
      addLog('Clave pública del servidor no encontrada.', 'error');
      return;
    }

    const energy = parseFloat((Math.random() * 90 + 10).toFixed(2));

    const plainPayload = JSON.stringify({
      deviceId:          DEVICE_ID,
      zone:              ZONE,
      location:          LOCATION,
      timestamp:         new Date().toISOString(),
      energyConsumption: energy
    });

    const encryptedData = encryptData(plainPayload, authPubKey);

    try {
      const resp = await fetch(`${AUTH_SERVER_URL}/resourceserver/metrics`, {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${tokenData.access_token}`
        },
        body: JSON.stringify({ encryptedData })  // ← NUEVO
      });

      if (resp.ok) {
        addLog(`📊 Métrica cifrada enviada → ${energy} kWh`, 'success');
      } else {
        const err = await resp.json();
        addLog(`Error enviando métrica: ${err.message}`, 'error');
        if (err.error === 'token_expired') {
          addLog('Token expirado. Deteniendo métricas automáticas.', 'warn');
          clearInterval(metricsInterval);
          metricsInterval = null;
        }
      }
    } catch (err) {
      addLog(`Error de red enviando métrica: ${err.message}`, 'error');
    }
  }, 10000);
}
function startMetricsBlind() {
  if (metricsInterval) {
    clearInterval(metricsInterval);
    metricsInterval = null;
    addLog('Envío normal detenido.', 'warn');
  }

  if (metricsBlindInterval) return;

  metricsBlindInterval = setInterval(async () => {
    const ephData = readJSON(EPHEMERAL_FILE);
    if (!ephData) {
      addLog('Datos efímeros no encontrados. Deteniendo envío ciego.', 'error');
      clearInterval(metricsBlindInterval);
      metricsBlindInterval = null;
      return;
    }

    const authPubKey = readJSON(AUTH_PUB_KEY_FILE);
    if (!authPubKey) {
      addLog('Clave pública del servidor no encontrada.', 'error');
      return;
    }

    const energy    = parseFloat((Math.random() * 90 + 10).toFixed(2));
    const timestamp = new Date().toISOString();

    const metricPayload = {
      anonymousId:        ephData.ephemeralCert.anonymousId,
      zone:               ZONE,
      energyConsumption:  energy,
      timestamp,
      ephemeralPubKey:    ephData.ephemeralCert.ephemeralPubKey,
      ephemeralSignature: ephData.ephemeralSignature
    };

    const ephPrivKey      = importPrivateKey(ephData.ephemeralPrivKey);
    const metricSignature = signData(metricPayload, ephPrivKey);

    const encryptedData = encryptData(JSON.stringify({
      anonymousId:       ephData.ephemeralCert.anonymousId,
      zone:              ZONE,
      energyConsumption: energy,
      timestamp
    }), authPubKey);

    try {
      const resp = await fetch(`${AUTH_SERVER_URL}/resourceserver/metrics-blind`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          encryptedData,
          ephemeralPubKey:    ephData.ephemeralCert.ephemeralPubKey,
          ephemeralSignature: ephData.ephemeralSignature,
          metricSignature
        })
      });

      if (resp.ok) {
        addLog(`📊 Métrica ciega cifrada enviada → anonymousId: ${ephData.ephemeralCert.anonymousId.substring(0, 8)}...`, 'success');
      } else {
        const err = await resp.json();
        addLog(`Error enviando métrica ciega: ${err.message}`, 'error');
        if (err.error === 'blind_signature_invalid') {
          addLog('Firma ciega rechazada. Deteniendo envío.', 'warn');
          clearInterval(metricsBlindInterval);
          metricsBlindInterval = null;
        }
      }
    } catch (err) {
      addLog(`Error de red enviando métrica ciega: ${err.message}`, 'error');
    }
  }, 10000);
}
// ══════════════════════════════════════════════════════════════════
// ARRANQUE — app.listen es el único punto de entrada
// initKeys() DEBE ir antes que initManufacturerCertificate()
// porque el cert bootstrap necesita DEVICE_PUBLIC_KEY_OBJ listo
// ══════════════════════════════════════════════════════════════════
app.listen(PORT, async () => {
  console.log(`\n📡 Device Server → http://localhost:${PORT}\n`);

  try {
    await initKeys();                      // 1. Generar / cargar claves RSA
    await initManufacturerCertificate();   // 2. Bootstrap manufacturer cert

    // Si ya había token guardado → reanudar métricas
    if (existsSync(TOKEN_FILE)) {
      addLog('Token existente detectado. Reanudando métricas automáticas...');
      startMetrics();
    }
  } catch (err) {
    addLog(`Error crítico en arranque: ${err.message}`, 'error');
    console.error('💥 Error crítico en arranque:', err);
  }
});

// ══════════════════════════════════════════════════════════════════
// Panel Bootstrap del sensor
// ══════════════════════════════════════════════════════════════════
function buildDashboard({ isReg, hasToken, isSending,isBlind, token, sensorCert }) {

  const statusBadge = !isReg
    ? `<span class="badge bg-danger fs-6 px-3 py-2">❌ No registrado</span>`
    : !hasToken
      ? `<span class="badge bg-warning text-dark fs-6 px-3 py-2">⏳ Registrado — Sin token</span>`
      : `<span class="badge bg-success fs-6 px-3 py-2">✅ Activo — Token válido</span>`;

  const metricsBadge = isSending
    ? `<span class="badge bg-success">🔄 Enviando métricas c/10s</span>`
    : `<span class="badge bg-secondary">⏸ Sin envío</span>`;

  const btnRegister = !isReg
    ? `<form method="POST" action="/register" class="d-inline">
         <button class="btn btn-primary btn-lg px-4">📡 Registrar dispositivo</button>
       </form>` : '';

  const btnToken = isReg && !hasToken
    ? `<form method="POST" action="/get-token" class="d-inline ms-2">
         <button class="btn btn-info btn-lg text-white px-4">🔑 Conseguir token</button>
       </form>` : '';

  const btnStop = isSending
    ? `<form method="POST" action="/stop-metrics" class="d-inline ms-2">
         <button class="btn btn-warning btn-lg">⏹ Detener métricas</button>
       </form>` : '';

  const btnBlindSign = isSending
    ? `<form method="POST" action="/blind-sign-demo" class="d-inline ms-2">
         <button class="btn btn-lg fw-bold"
                 style="background:linear-gradient(135deg,#1e3a5f,#0f3460);border:1px solid #2a5298;color:#58a6ff;"
                 title="Firma ciega RSA-Chaum: el servidor firma sin ver el mensaje">
           🔏 Firma Ciega (RSA-Chaum)
         </button>
       </form>` : '';

  const certHTML = sensorCert
    ? `<div class="font-monospace small text-success bg-dark p-3 rounded" style="word-break:break-all;max-height:140px;overflow-y:auto">
         <div><b class="text-white">deviceId:</b> ${sensorCert.payload.deviceId}</div>
         <div><b class="text-white">manufacturer:</b> ${sensorCert.payload.manufacturer}</div>
         <div><b class="text-white">signedBy:</b> ${sensorCert.payload.signedBy}</div>
         <div><b class="text-white">issuedAt:</b> ${sensorCert.payload.issuedAt}</div>
         <div class="mt-1"><b class="text-white">signature:</b> ${sensorCert.signature.substring(0,60)}...</div>
       </div>`
    : `<p class="text-muted fst-italic mb-0">Sin sensor certificate todavía.</p>`;

  const tokenHTML = token
    ? `<div class="font-monospace small text-warning bg-dark p-3 rounded" style="word-break:break-all;max-height:100px;overflow-y:auto">
         <div><b class="text-white">access_token:</b> ${token.access_token.substring(0,80)}...</div>
         <div><b class="text-white">obtainedAt:</b> ${token.obtainedAt}</div>
         <div><b class="text-white">expires_in:</b> ${token.expires_in}s (1h)</div>
       </div>`
    : `<p class="text-muted fst-italic mb-0">Sin token JWT todavía.</p>`;

  const logsHTML = logs.slice(0, 20).map(l => {
    const c = l.type === 'error' ? 'text-danger' : l.type === 'success' ? 'text-success' : l.type === 'warn' ? 'text-warning' : 'text-info';
    return `<div class="${c} small"><span class="text-secondary">[${l.ts.substring(11,19)}]</span> ${l.msg}</div>`;
  }).join('') || '<span class="text-secondary small">Sin logs aún...</span>';

   const steps = [
    { label: '1. Registro',    done: isReg || hasToken || isSending || isBlind },
    { label: '2. Sensor Cert', done: isReg },
    { label: '3. JWT',         done: hasToken },
    { label: '4. Métricas',    done: isSending || isBlind },  // ← verde si cualquiera de los dos corre
    { label: '5. Firma Ciega', done: isBlind }                // ← solo verde cuando blind está activo
  ];
  const stepsHTML = steps.map(s =>
    `<div class="col text-center">
       <div class="p-2 rounded small fw-semibold ${s.done ? 'bg-success bg-opacity-25 text-success' : 'bg-secondary bg-opacity-15 text-secondary'}">
         ${s.done ? '✅' : '○'} ${s.label}
       </div>
     </div>`
  ).join(`<div class="col-auto align-self-center text-secondary small">→</div>`);

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IoT Sensor — Panel de Control</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body        { background: #0d1117; color: #c9d1d9; }
    .card       { background: #161b22; border: 1px solid #30363d; border-radius: 12px; }
    .card-header{ background: #21262d; border-bottom: 1px solid #30363d; border-radius: 12px 12px 0 0 !important; }
    .log-box    { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 12px; height: 220px; overflow-y: auto; }
    h1 span     { background: linear-gradient(135deg, #58a6ff, #bc8cff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .border-accent { border-left: 4px solid #58a6ff !important; }
    footer      { border-top: 1px solid #30363d; }
  </style>
  <meta http-equiv="refresh" content="15">
</head>
<body>
<div class="container-fluid py-4 px-4">

  <!-- Header -->
  <div class="row mb-4 align-items-center">
    <div class="col">
      <h1 class="display-6 fw-bold"><span>📡 IoT Device Panel</span></h1>
      <p class="text-secondary mb-0">
        Device: <code class="text-info">${DEVICE_ID}</code> &nbsp;|&nbsp;
        Fab: <code class="text-info">${MANUFACTURER}</code> &nbsp;|&nbsp;
        Zona: <code class="text-info">${ZONE}</code> &nbsp;|&nbsp;
        RSA: <code class="text-success">sciots-rsa</code>
      </p>
    </div>
  </div>

  <!-- Estado + Acciones -->
  <div class="row g-4 mb-4">
    <div class="col-lg-6">
      <div class="card p-3 h-100 border-accent">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h6 class="text-secondary mb-0 text-uppercase small">Estado del dispositivo</h6>
          ${metricsBadge}
        </div>
        <div class="mb-3">${statusBadge}</div>
        <div class="d-flex flex-wrap gap-2 align-items-center">
          ${btnRegister}
          ${btnToken}
          ${btnStop}
          ${btnBlindSign}
          <form method="POST" action="/reset" class="ms-auto">
            <button class="btn btn-outline-danger btn-sm" onclick="return confirm('¿Resetear todos los datos del dispositivo?')">
              🗑 Reset
            </button>
          </form>
        </div>
      </div>
    </div>
    <div class="col-lg-6">
      <div class="card p-3 h-100">
        <h6 class="text-secondary text-uppercase small mb-2">Sensor Certificate</h6>
        ${certHTML}
      </div>
    </div>
  </div>

  <!-- Token + Logs -->
  <div class="row g-4 mb-4">
    <div class="col-lg-6">
      <div class="card p-3 h-100">
        <h6 class="text-secondary text-uppercase small mb-2">Access Token (JWT)</h6>
        ${tokenHTML}
      </div>
    </div>
    <div class="col-lg-6">
      <div class="card p-3 h-100">
        <h6 class="text-secondary text-uppercase small mb-2">Logs del sistema</h6>
        <div class="log-box">${logsHTML}</div>
      </div>
    </div>
  </div>

  <!-- Progreso del flujo -->
  <div class="row mb-4">
    <div class="col">
      <div class="card p-3">
        <h6 class="text-secondary text-uppercase small mb-3">Progreso del flujo OAuth2 IoT + RSA</h6>
        <div class="row align-items-center g-1">${stepsHTML}</div>
      </div>
    </div>
  </div>

  <footer class="py-3 text-center text-secondary small">
    IoT OAuth2 Device Flow + RSA (sciots-rsa) &nbsp;|&nbsp;
    Auth Server: <a href="${AUTH_SERVER_URL}" class="text-info" target="_blank">${AUTH_SERVER_URL}</a>
    &nbsp;|&nbsp; Panel se refresca cada 15s
  </footer>

</div>
</body>
</html>`;
}