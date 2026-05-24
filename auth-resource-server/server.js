/**
 * server.js — Auth + Resource Server
 *
 * Arranque:
 *  1. Crea dirs y archivos JSON
 *  2. Genera claves RSA con generateKeyPair() del helper (→ utils/rsa.js)
 *  3. Crea vistas HTML Bootstrap
 *  4. Monta Express con rutas /authserver/* y /resourceserver/*
 */

import 'dotenv/config';
import express       from 'express';
import session       from 'express-session';
import bodyParser    from 'body-parser';
import cookieParser  from 'cookie-parser';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname }     from 'path';
import { fileURLToPath }     from 'url';
import * as rsa from 'sciots-rsa'
import { generateKeyPair, exportPublicKey, exportPrivateKey } from './helpers/rsaHelpers.js';
import authRoutes     from './routes/authRoutes.js';
import resourceRoutes from './routes/resourceRoutes.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app  = express();
const PORT = process.env.PORT || 3000;

// ── Directorios ────────────────────────────────────────────────────
const KEYS_DIR  = join(__dirname, 'keys');
const DATA_DIR  = join(__dirname, 'data');
const VIEWS_DIR = join(__dirname, 'views');
[KEYS_DIR, DATA_DIR, VIEWS_DIR].forEach(d => { if (!existsSync(d)) mkdirSync(d, { recursive: true }); });

// ── Archivos de datos iniciales ────────────────────────────────────
const dataDefaults = {
  [join(DATA_DIR, 'users.json')]:
    JSON.stringify([{ username: 'admin', password: 'admin123', role: 'admin' }], null, 2),
  [join(DATA_DIR, 'authorizationCodes.json')]: '[]',
  [join(DATA_DIR, 'registeredDevices.json')]:  '[]',
  [join(DATA_DIR, 'metrics.json')]:             '[]'
};
Object.entries(dataDefaults).forEach(([fp, def]) => {
  if (!existsSync(fp)) { writeFileSync(fp, def, 'utf8'); console.log(`[Init] Creado: ${fp.split('/').pop()}`); }
});

// ── Generar claves RSA del Auth Server si no existen ──────────────
// generateKeyPair() → utils/rsa.js → bigint-crypto-utils (primeSync + modInv)
// Claves guardadas como JSON { n: string, e/d: string }
const PUB_KEY_FILE  = join(KEYS_DIR, 'auth-public.json');
const PRIV_KEY_FILE = join(KEYS_DIR, 'auth-private.json');

if (!existsSync(PUB_KEY_FILE) || !existsSync(PRIV_KEY_FILE)) {
  console.log('[Init] Generando par de claves RSA 2048 bits (bigint-crypto-utils)...');
  console.log('[Init] Esto puede tardar unos segundos...');
  const { publicKey, privateKey } = rsa.generateKeyPair(2048);
  writeFileSync(PUB_KEY_FILE,  JSON.stringify(exportPublicKey(publicKey),  null, 2), 'utf8');
  writeFileSync(PRIV_KEY_FILE, JSON.stringify(exportPrivateKey(privateKey), null, 2), 'utf8');
  console.log('[Init] ✅ Claves RSA generadas → keys/auth-public.json + auth-private.json');
} else {
  console.log('[Init] Claves RSA del Auth Server ya existen.');
}

// ── Crear vistas HTML Bootstrap ────────────────────────────────────
initViews();

// ── Middlewares ────────────────────────────────────────────────────
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret:            process.env.SESSION_SECRET || 'fallback_secret',
  resave:            false,
  saveUninitialized: false,
  cookie:            { secure: false, maxAge: 15 * 60 * 1000 }
}));

// ── Rutas ──────────────────────────────────────────────────────────
app.use('/authserver',     authRoutes);
app.use('/resourceserver', resourceRoutes);

app.get('/', (req, res) => {
  res.json({
    service: 'IoT Auth + Resource Server',
    version: '1.0.0',
    rsaModule: 'utils/rsa.js (bigint-crypto-utils)',
    routes:  { auth: '/authserver/*', resource: '/resourceserver/*' }
  });
});

app.use((err, req, res, next) => {
  console.error('[Error Global]', err.message);
  res.status(500).json({ error: 'internal_server_error', message: err.message });
});

app.listen(PORT, () => {
  console.log(`\n🔐 Auth + Resource Server → http://localhost:${PORT}`);
  console.log(`   Auth:     http://localhost:${PORT}/authserver`);
  console.log(`   Resource: http://localhost:${PORT}/resourceserver\n`);
});

// ══════════════════════════════════════════════════════════════════
// Vistas HTML Bootstrap (se crean al arrancar si no existen)
// ══════════════════════════════════════════════════════════════════
function initViews() {

  const loginHTML = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IoT Auth — Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; display: flex; align-items: center; }
    .card { border: none; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }
    .card-header { background: linear-gradient(135deg, #e94560, #0f3460); border-radius: 16px 16px 0 0 !important; }
    .btn-login { background: linear-gradient(135deg, #e94560, #c23152); border: none; }
    .form-control:focus { border-color: #e94560; box-shadow: 0 0 0 .25rem rgba(233,69,96,.25); }
    .badge-rsa { background: #0f3460; color: #58a6ff; font-size: .7rem; font-family: monospace; }
  </style>
</head>
<body>
<div class="container">
  <div class="row justify-content-center">
    <div class="col-md-5">
      <div class="card">
        <div class="card-header text-white text-center py-4">
          <h4 class="mb-1">🔐 IoT Authorization Server</h4>
          <small class="opacity-75">OAuth2 Device Flow + RSA Certificates</small><br>
          <span class="badge badge-rsa mt-1">bigint-crypto-utils RSA</span>
        </div>
        <div class="card-body p-4">
          {{ERROR}}
          <p class="text-muted small mb-4">Un dispositivo IoT solicita autorización. Inicia sesión para revisar la solicitud.</p>
          <form method="POST" action="/authserver/login">
            <input type="hidden" name="requestId" value="{{REQUEST_ID}}">
            <div class="mb-3">
              <label class="form-label fw-semibold">Usuario</label>
              <input type="text" name="username" class="form-control form-control-lg" placeholder="admin" required autofocus>
            </div>
            <div class="mb-4">
              <label class="form-label fw-semibold">Contraseña</label>
              <input type="password" name="password" class="form-control form-control-lg" placeholder="••••••••" required>
            </div>
            <button type="submit" class="btn btn-login btn-lg text-white w-100 fw-bold">Iniciar Sesión →</button>
          </form>
        </div>
        <div class="card-footer text-center py-2">
          <small class="text-muted">Usuario: <code>admin</code> / Contraseña: <code>admin123</code></small>
        </div>
      </div>
    </div>
  </div>
</div>
</body>
</html>`;

  const consentHTML = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IoT Auth — Consentimiento</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; display: flex; align-items: center; }
    .card { border: none; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }
    .card-header { background: linear-gradient(135deg, #2d6a4f, #1b4332); border-radius: 16px 16px 0 0 !important; }
    .device-box { background: #f8f9fa; border-left: 4px solid #2d6a4f; border-radius: 6px; }
    .key-preview { font-family: monospace; font-size: .78rem; word-break: break-all; background: #1a1a2e; color: #00ff88; padding: 10px; border-radius: 6px; }
    .btn-approve { background: linear-gradient(135deg, #2d6a4f, #1b4332); border: none; }
    .btn-reject  { background: linear-gradient(135deg, #e94560, #c23152); border: none; }
    .blind-section { background: #0f1b2d; border: 1px solid #1e3a5f; border-radius: 10px; }
    .blind-section .section-title { font-size: .7rem; letter-spacing: .12em; text-transform: uppercase; color: #58a6ff; font-weight: 700; }
    .blind-token-box { font-family: monospace; font-size: .72rem; word-break: break-all; background: #070d1a; color: #f0c040; padding: 10px; border-radius: 6px; border: 1px solid #2a3f60; max-height: 80px; overflow-y: auto; }
    .badge-blind { background: #1e3a5f; color: #58a6ff; font-size: .65rem; font-family: monospace; vertical-align: middle; }
  </style>
</head>
<body>
<div class="container">
  <div class="row justify-content-center">
    <div class="col-lg-7 col-md-9">
      <div class="card">
        <div class="card-header text-white text-center py-4">
          <h4 class="mb-1">🛡️ Solicitud de Registro de Dispositivo</h4>
          <small class="opacity-75">Sesión activa: <strong>{{USER}}</strong></small>
        </div>
        <div class="card-body p-4">
          <p class="text-muted mb-3">Revisa los detalles del dispositivo IoT que solicita acceso al sistema:</p>
          <div class="device-box p-3 mb-4">
            <div class="row align-items-center mb-2">
              <div class="col-4"><span class="text-muted small fw-semibold">DEVICE ID</span></div>
              <div class="col-8"><strong>{{DEVICE_ID}}</strong></div>
            </div>
            <div class="row align-items-center mb-2">
              <div class="col-4"><span class="text-muted small fw-semibold">FABRICANTE</span></div>
              <div class="col-8">{{MANUFACTURER}}</div>
            </div>
            <div class="row align-items-start">
              <div class="col-4"><span class="text-muted small fw-semibold">CLAVE PÚBLICA</span></div>
              <div class="col-8"><div class="key-preview">{{PUBLIC_KEY}}</div></div>
            </div>
          </div>
          <div class="alert alert-warning mb-4">
            <strong>⚠️ ¿Autorizar este dispositivo?</strong><br>
            <small>Al aprobar, el dispositivo recibirá credenciales RSA para enviar métricas protegidas al servidor.</small>
          </div>

          <!-- ── FIRMA CIEGA RSA-Chaum ── -->
          <div class="blind-section p-3 mb-4">
            <div class="d-flex align-items-center justify-content-between mb-2">
              <span class="section-title">🔏 Firma Ciega (RSA-Chaum)</span>
              <span class="badge badge-blind">POST /authserver/blind-sign</span>
            </div>
            <p class="text-secondary mb-2" style="font-size:.8rem;">
              Introduce el token cegado <code>m' = m·r<sup>e</sup> mod n</code> generado por el dispositivo.
              El servidor calculará <code>s' = (m')ᵈ mod n</code> sin conocer el mensaje original <code>m</code>.
            </p>
            <form method="POST" action="/authserver/blind-sign">
              <input type="hidden" name="requestId" value="{{REQUEST_ID}}">
              <div class="mb-2">
                <label class="text-muted" style="font-size:.72rem; font-weight:600;">TOKEN CEGADO (m')</label>
                <input type="text" name="blindedToken" class="form-control form-control-sm mt-1"
                       style="font-family:monospace;font-size:.75rem;background:#070d1a;color:#f0c040;border:1px solid #2a3f60;"
                       placeholder="Número decimal del token cegado por el dispositivo" required>
              </div>
              <div class="d-flex justify-content-end mt-2">
                <button type="submit" class="btn btn-sm text-white fw-bold"
                        style="background:linear-gradient(135deg,#1e3a5f,#0f3460);border:1px solid #2a5298;">
                  🔏 Firmar a ciegas
                </button>
              </div>
            </form>
          </div>
          <!-- ── /FIRMA CIEGA ── -->

          <div class="row g-3">
            <div class="col-6">
              <form method="POST" action="/authserver/approve">
                <input type="hidden" name="requestId" value="{{REQUEST_ID}}">
                <button type="submit" class="btn btn-approve btn-lg text-white w-100 fw-bold">✅ Aprobar</button>
              </form>
            </div>
            <div class="col-6">
              <form method="POST" action="/authserver/reject">
                <input type="hidden" name="requestId" value="{{REQUEST_ID}}">
                <button type="submit" class="btn btn-reject btn-lg text-white w-100 fw-bold">❌ Rechazar</button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
</body>
</html>`;

  const errorHTML = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Error — IoT Auth Server</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: #1a1a2e; min-height: 100vh; display: flex; align-items: center; }
  </style>
</head>
<body>
<div class="container text-center text-white">
  <div class="display-1 mb-3">❌</div>
  <h3 class="mb-2">Solicitud inválida o expirada</h3>
  <p class="text-secondary">Reinicia el proceso desde el panel del dispositivo IoT.</p>
  <a href="http://localhost:4000" class="btn btn-outline-light mt-3">← Volver al panel del dispositivo</a>
</div>
</body>
</html>`;

  const blindSignResultHTML = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IoT Auth — Firma Ciega</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; display: flex; align-items: center; }
    .card { border: none; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }
    .card-header { background: linear-gradient(135deg, #1e3a5f, #0f3460); border-radius: 16px 16px 0 0 !important; }
    .key-preview  { font-family: monospace; font-size: .78rem; word-break: break-all; background: #1a1a2e; color: #00ff88; padding: 10px; border-radius: 6px; }
    .token-box    { font-family: monospace; font-size: .72rem; word-break: break-all; background: #070d1a; color: #f0c040; padding: 10px; border-radius: 6px; border: 1px solid #2a3f60; max-height: 100px; overflow-y: auto; }
    .step-label   { font-size: .68rem; letter-spacing: .1em; text-transform: uppercase; color: #58a6ff; font-weight: 700; }
    .step-row     { background: #0f1b2d; border: 1px solid #1e3a5f; border-radius: 8px; }
    .badge-blind  { background: #1e3a5f; color: #58a6ff; font-size: .65rem; font-family: monospace; }
    .btn-back     { background: linear-gradient(135deg, #2d6a4f, #1b4332); border: none; }
    .formula      { font-family: monospace; font-size: .82rem; background: #070d1a; color: #c9d1d9; padding: 8px 12px; border-radius: 6px; border-left: 3px solid #58a6ff; }
  </style>
</head>
<body>
<div class="container">
  <div class="row justify-content-center">
    <div class="col-lg-8 col-md-10">
      <div class="card">
        <div class="card-header text-white text-center py-4">
          <h4 class="mb-1">🔏 Resultado de Firma Ciega</h4>
          <small class="opacity-75">RSA-Chaum Blind Signature &nbsp;·&nbsp; Sesión: <strong>{{USER}}</strong></small><br>
          <span class="badge badge-blind mt-1">POST /authserver/blind-sign</span>
        </div>
        <div class="card-body p-4">
          <div class="alert alert-info mb-4" style="background:#0f1b2d;border:1px solid #1e3a5f;color:#c9d1d9;">
            <strong style="color:#58a6ff;">¿Qué acaba de ocurrir?</strong><br>
            <small>El servidor calculó <code>s' = (m')ᵈ mod n</code> sobre el token cegado.
            El dispositivo puede descegar con <code>s = s' · r⁻¹ mod n</code> y obtiene una firma RSA válida
            de <code>m</code> que el servidor <strong>nunca vio</strong>.</small>
          </div>
          <div class="step-row p-3 mb-3">
            <div class="step-label mb-1">① Token cegado recibido &nbsp;<code style="font-size:.65rem;color:#f0c040;">m'</code></div>
            <div class="token-box">{{BLINDED_TOKEN}}</div>
          </div>
          <div class="step-row p-3 mb-3">
            <div class="step-label mb-2">② Operación ejecutada en el servidor</div>
            <div class="formula">s' = pow(m', d, n)</div>
          </div>
          <div class="step-row p-3 mb-4">
            <div class="step-label mb-1">③ Firma ciega resultante &nbsp;<code style="font-size:.65rem;color:#00ff88;">s' = (m')ᵈ mod n</code></div>
            <div class="key-preview">{{BLIND_SIGNATURE}}</div>
          </div>
          <div class="alert mb-4" style="background:#1b2f1b;border:1px solid #2d6a4f;color:#c9d1d9;">
            <strong style="color:#00ff88;">➜ Siguiente paso (en el dispositivo)</strong><br>
            <small>Calcular: <code>s = s' · r⁻¹ mod n</code> &nbsp;→&nbsp; Verificar: <code>sᵉ mod n == m</code></small>
          </div>
          <div class="row g-3">
            <div class="col-6">
              <a href="/authserver/consent?requestId={{REQUEST_ID}}" class="btn btn-back btn-lg text-white w-100 fw-bold">← Volver</a>
            </div>
            <div class="col-6">
              <form method="POST" action="/authserver/approve">
                <input type="hidden" name="requestId" value="{{REQUEST_ID}}">
                <button type="submit" class="btn btn-lg text-white w-100 fw-bold"
                        style="background:linear-gradient(135deg,#2d6a4f,#1b4332);border:none;">✅ Aprobar dispositivo</button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
</body>
</html>`;

  const views = {
    'login.html':             loginHTML,
    'consent.html':           consentHTML,
    'error.html':             errorHTML,
    'blind-sign-result.html': blindSignResultHTML
  };

  Object.entries(views).forEach(([name, html]) => {
    const fp = join(VIEWS_DIR, name);
    if (!existsSync(fp)) { writeFileSync(fp, html, 'utf8'); }
  });
}