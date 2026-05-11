'use strict';

import crypto    from 'crypto';
import readline  from 'readline';
import { modPow, modInv } from 'bigint-crypto-utils';
import { RsaPublicKey }   from 'sciots-rsa';

const SERVER = 'http://localhost:3000';

// Estado en memoria entre opciones del menú
let publicKey  = null;
let signature  = null;
let currentId  = null;

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

    // Si stdin es TTY usamos modo raw para mostrar asteriscos
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
      // Fallback: stdin no es TTY (nodemon, pipe...) — lee sin ocultar
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
  const pkRes = await fetch(`${SERVER}/rsa-public-key`, {
    headers: {
      'X-Username': username,
      'X-Password': password,
    },
  });

  if (!pkRes.ok) {
    const err = await pkRes.json();
    console.error(`\nAcceso denegado: ${err.error}\n`);
    return;
  }

  const { n, e } = await pkRes.json();
  publicKey  = new RsaPublicKey(BigInt(n), BigInt(e));
  currentId  = id;

  console.log('Autenticado. Clave pública recibida.');

  // 2. Hash del ID
  const hashHex    = crypto.createHash('sha256').update(id).digest('hex');
  const hashBigInt = BigInt('0x' + hashHex) % publicKey.n;

  // 3. Factor de cegamiento
  const r   = randomBlindingFactor(publicKey.n);
  const rE  = modPow(r, publicKey.e, publicKey.n);
  const blindedMessage = (hashBigInt * rE) % publicKey.n;

  console.log(`\nHash(ID)  : ${hashHex}`);
  console.log(`Cegado    : ${blindedMessage.toString().slice(0, 30)}...`);

  // 4. Envía mensaje cegado al servidor
  const signRes = await fetch(`${SERVER}/blind-sign`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ blindedMessage: blindedMessage.toString() }),
  });

  if (!signRes.ok) {
    const err = await signRes.json();
    console.error(`\nError en firma ciega: ${err.error}\n`);
    return;
  }

  const { blindSignature } = await signRes.json();

  // 5. Descega la firma: S = S' * r⁻¹ mod n = hash^d
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

  const res = await fetch(`${SERVER}/verify-signature`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({
      id:        currentId,
      signature: signature.toString()
    }),
  });

  const result = await res.json();

  if (res.ok) {
    console.log(`\nID registrado correctamente: ${result.registered}\n`);
    // Limpiamos estado para no reutilizar la misma firma
    signature = null;
    currentId = null;
  } else if (res.status === 409) {
    console.error(`\nID ya registrado — no válido: ${result.error}\n`);
  } else if (res.status === 401) {
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