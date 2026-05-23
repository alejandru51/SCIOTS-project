'use strict';

import crypto    from 'crypto';
import readline  from 'readline';
import { modPow, modInv } from 'bigint-crypto-utils';
import { RsaPublicKey }   from 'sciots-rsa';
import coap from 'coap';

const SERVER_HOST = 'localhost';
const SERVER_PORT = 5683;

// Estado en memoria entre opciones del menú
let publicKey  = null;
let signature  = null;
let currentId  = null;

// ─── Helper CoAP (promisificado) ──────────────────────────────────────────
function coapRequest({ method, path, payload, headers = {} }) {
  return new Promise((resolve, reject) => {
    const req = coap.request({
      host:   SERVER_HOST,
      port:   SERVER_PORT,
      method,
      pathname: path,
    });

    // Cabeceras personalizadas como opciones CoAP (usando opción 2048+ o string options)
    for (const [key, value] of Object.entries(headers)) {
      req.setOption(key, Buffer.from(value));
    }

    if (payload) {
      req.write(JSON.stringify(payload));
    }

    req.on('response', (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk.toString(); });
      res.on('end', () => {
        const code = res.code; // e.g. '2.05', '4.01', '4.09'
        const [major] = code.split('.').map(Number);
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = { raw: data }; }
        resolve({ ok: major === 2, code, body: parsed });
      });
    });

    req.on('error', reject);
    req.end();
  });
}

// ─── Helpers de terminal ──────────────────────────────────────────────────
function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, ans => { rl.close(); resolve(ans.trim()); }));
}

function promptHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input:  process.stdin,
      output: process.stdout,
    });

    if (process.stdin.isTTY) {
      process.stdout.write(question);
      process.stdin.setRawMode(true);
      let pass = '';
      const handler = (ch) => {
        const c = ch.toString();
        if (c === '\n' || c === '\r' || c === '\u0004') {
          process.stdin.setRawMode(false);
          process.stdin.removeListener('data', handler);
          rl.close();
          process.stdout.write('\n');
          resolve(pass);
        } else if (c === '\u0003') {
          process.exit();
        } else if (c === '\u007f') {
          if (pass.length > 0) { pass = pass.slice(0, -1); process.stdout.write('\b \b'); }
        } else {
          pass += c;
          process.stdout.write('*');
        }
      };
      process.stdin.resume();
      process.stdin.on('data', handler);
    } else {
      rl.question(question, (ans) => {
        rl.close();
        resolve(ans.trim());
      });
    }
  });
}

function randomBlindingFactor(n) {
  let r;
  do {
    const bytes = crypto.randomBytes(Math.floor(n.toString(2).length / 8));
    r = BigInt('0x' + bytes.toString('hex')) % n;
  } while (r < 2n);
  return r;
}

// ─── Opción 1: login + obtener firma ciega ────────────────────────────────
async function opcionConectar() {
  console.log('\n── Conexión al servidor y obtención de firma ciega ──');
  const username = await prompt('Usuario   : ');
  const password = await promptHidden('Contraseña: ');
  const id       = await prompt('ID a firmar: ');

  // 1. Pide clave pública — el servidor valida credenciales aquí
  console.log('\nConectando con el servidor...');
  const pkRes = await coapRequest({
  method:  'POST',
  path:    '/rsa-public-key',
  payload: { username, password },
});

  if (!pkRes.ok) {
    console.error(`\nAcceso denegado: ${pkRes.body.error}\n`);
    return;
  }

  const { n, e } = pkRes.body;
  publicKey  = new RsaPublicKey(BigInt(n), BigInt(e));
  currentId  = id;

  console.log('Autenticado. Clave pública recibida.');

  const hashHex    = crypto.createHash('sha256').update(id).digest('hex');
  const hashBigInt = BigInt('0x' + hashHex) % publicKey.n;

  const r   = randomBlindingFactor(publicKey.n);
  const rE  = modPow(r, publicKey.e, publicKey.n);
  const blindedMessage = (hashBigInt * rE) % publicKey.n;

  console.log(`\nHash(ID)  : ${hashHex}`);
  console.log(`Cegado    : ${blindedMessage.toString().slice(0, 30)}...`);

  const signRes = await coapRequest({
    method:  'POST',
    path:    '/blind-sign',
    payload: { blindedMessage: blindedMessage.toString() },
  });

  if (!signRes.ok) {
    console.error(`\nError en firma ciega: ${signRes.body.error}\n`);
    return;
  }

  const { blindSignature } = signRes.body;

  // Descega la firma: S = S' * r⁻¹ mod n = hash^d
  const rInv = modInv(r, publicKey.n);
  signature  = (BigInt(blindSignature) * rInv) % publicKey.n;

  console.log(`Firma desencegada: ${signature.toString().slice(0, 30)}...`);
  console.log('\nFirma ciega obtenida. Ahora puedes usar la opción 2 para enviarla.\n');
}

// ─── Opción 2: enviar firma al servidor para verificar y registrar ─────────
async function opcionEnviarFirma() {
  if (!signature || !currentId) {
    console.log('\nPrimero debes conectarte y obtener la firma (opción 1).\n');
    return;
  }

  console.log(`\n── Enviando firma para ID: ${currentId} ──`);

  const res = await coapRequest({
    method:  'POST',
    path:    '/verify-signature',
    payload: {
      id:        currentId,
      signature: signature.toString(),
    },
  });

  const result = res.body;

  if (res.ok) {
    console.log(`\nID registrado correctamente: ${result.registered}\n`);
    signature = null;
    currentId = null;
  } else if (res.code === '4.09') {
    console.error(`\nID ya registrado — no válido: ${result.error}\n`);
  } else if (res.code === '4.01') {
    console.error(`\nFirma inválida: ${result.error}\n`);
  } else {
    console.error(`\nError: ${result.error}\n`);
  }
}

// ─── Menú principal ───────────────────────────────────────────────────────
async function menu() {
  while (true) {
    console.log('╔══════════════════════════════════════╗');
    console.log('║       CLIENTE FIRMA CIEGA RSA        ║');
    console.log('╠══════════════════════════════════════╣');
    console.log('║  1 · Conectar al servidor y obtener  ║');
    console.log('║      firma ciega (login + ID)        ║');
    console.log('║  2 · Enviar firma al servidor        ║');
    console.log('║  0 · Salir                           ║');
    console.log('╚══════════════════════════════════════╝');

    const opcion = await prompt('Elige opción: ');

    switch (opcion) {
      case '1': await opcionConectar();    break;
      case '2': await opcionEnviarFirma(); break;
      case '0': console.log('Saliendo...'); process.exit(0);
      default:  console.log('\nOpción no válida.\n');
    }
  }
}

menu().catch(err => { console.error('Error fatal:', err); process.exit(1); });