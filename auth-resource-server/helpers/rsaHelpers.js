/**
 *
 * SERIALIZACIÓN DE CLAVES:
 *  exportPublicKey  → { n: string, e: string }
 *  exportPrivateKey → { n: string, d: string }
 *  importPublicKey  → reconstruye RsaPublicKey   con new rsa.RsaPublicKey(BigInt, BigInt)
 *  importPrivateKey → reconstruye RsaPrivateKey  con new rsa.RsaPrivateKey(BigInt, BigInt)
 * ─────────────────────────────────────────────────────────────────
 */

import { createHash } from 'crypto';       
import * as rsa from 'sciots-rsa';      

// ═════════════════════════════════════════════════════════════════
// SECCIÓN 1 — SERIALIZACIÓN / DESERIALIZACIÓN DE CLAVES
// BigInt no es serializable en JSON → convertir a string y viceversa
// ═════════════════════════════════════════════════════════════════

/**
 * exportPublicKey(key)
 * Convierte una RsaPublicKey a plain object JSON-safe.
 * Los campos n y e son BigInt → se convierten a string decimal.
 *
 * @param {rsa.RsaPublicKey} key
 * @returns {{ n: string, e: string }}
 */
export function exportPublicKey(key) {
  return {
    n: key.n.toString(),
    e: key.e.toString()
  };
}

/**
 * exportPrivateKey(key)
 * Convierte una RsaPrivateKey a plain object JSON-safe.
 * Los campos n y d son BigInt → se convierten a string decimal.
 *
 * @param {rsa.RsaPrivateKey} key
 * @returns {{ n: string, d: string }}
 */
export function exportPrivateKey(key) {
  return {
    n: key.n.toString(),
    d: key.d.toString()
  };
}

/**
 * importPublicKey(obj)
 * Reconstruye una RsaPublicKey desde un plain object JSON.
 * Convierte los strings decimales a BigInt y usa new rsa.RsaPublicKey().
 *
 * @param {{ n: string, e: string }} obj
 * @returns {rsa.RsaPublicKey}
 */
export function importPublicKey(obj) {
  return new rsa.RsaPublicKey(
    BigInt(obj.n),
    BigInt(obj.e)
  );
}

/**
 * importPrivateKey(obj)
 * Reconstruye una RsaPrivateKey desde un plain object JSON.
 * Convierte los strings decimales a BigInt y usa new rsa.RsaPrivateKey().
 *
 * @param {{ n: string, d: string }} obj
 * @returns {rsa.RsaPrivateKey}
 */
export function importPrivateKey(obj) {
  return new rsa.RsaPrivateKey(
    BigInt(obj.n),
    BigInt(obj.d)
  );
}

// ═════════════════════════════════════════════════════════════════
// SECCIÓN 2 — NORMALIZACIÓN INTERNA DE CLAVES
// Acepta tanto instancias de clase como plain objects (desde JSON)
// ═════════════════════════════════════════════════════════════════

/**
 * Acepta RsaPublicKey o plain object { n, e } y devuelve siempre RsaPublicKey.
 * @param {rsa.RsaPublicKey|{n:string,e:string}} key
 * @returns {rsa.RsaPublicKey}
 */
function toPublicKey(key) {
  return key instanceof rsa.RsaPublicKey
    ? key
    : importPublicKey(key);
}

/**
 * Acepta RsaPrivateKey o plain object { n, d } y devuelve siempre RsaPrivateKey.
 * @param {rsa.RsaPrivateKey|{n:string,d:string}} key
 * @returns {rsa.RsaPrivateKey}
 */
function toPrivateKey(key) {
  return key instanceof rsa.RsaPrivateKey
    ? key
    : importPrivateKey(key);
}

// ═════════════════════════════════════════════════════════════════
// SECCIÓN 3 — HELPER INTERNO: dato → SHA-256 → BigInt
// crypto se usa aquí, solo para calcular el hash.
// ═════════════════════════════════════════════════════════════════

/**
 * hashToBigInt(data)
 * Serializa el dato a string, calcula su SHA-256 con crypto,
 * y convierte el digest hexadecimal a BigInt.
 * Este BigInt es el que se firma/verifica con RSA.
 *
 * crypto → SOLO para el hash SHA-256, nada más.
 *
 * @param {string|object} data
 * @returns {BigInt}
 */
function hashToBigInt(data) {
  const str = typeof data === 'string'
    ? data
    : JSON.stringify(data);

  // ── crypto usado SOLO para SHA-256 hash ───────────────────────
  const hexDigest = createHash('sha256')
    .update(str, 'utf8')
    .digest('hex');
  // ──────────────────────────────────────────────────────────────

  return BigInt('0x' + hexDigest);
}

// ═════════════════════════════════════════════════════════════════
// SECCIÓN 4 — HELPERS INTERNOS: string ↔ BigInt (para cifrado)
// Convierte texto a número big-endian y viceversa.
// No se usa crypto aquí en ningún momento.
// ═════════════════════════════════════════════════════════════════

/**
 * Convierte un string UTF-8 a BigInt interpretando los bytes como
 * un número entero big-endian.
 * @param {string} str
 * @returns {BigInt}
 */
function stringToBigInt(str) {
  const hex = Buffer.from(str, 'utf8').toString('hex');
  return BigInt('0x' + hex);
}

/**
 * Convierte un BigInt de vuelta a string UTF-8.
 * @param {BigInt} big
 * @returns {string}
 */
function bigIntToString(big) {
  let hex = big.toString(16);
  // Asegurar longitud par para que Buffer.from lo interprete correctamente
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return Buffer.from(hex, 'hex').toString('utf8');
}

// ═════════════════════════════════════════════════════════════════
// SECCIÓN 5 — GENERACIÓN DE CLAVES
// ═════════════════════════════════════════════════════════════════

/**
 * generateKeyPair(bits)
 * Genera un par de claves RSA delegando completamente en sciots-rsa.
 * rsa.generateKeyPair usa internamente bigint-crypto-utils (primeSync + modInv).
 *
 * @param {number} [bits=2048]
 * @returns {{ publicKey: rsa.RsaPublicKey, privateKey: rsa.RsaPrivateKey }}
 */
export function generateKeyPair(bits = 2048) {
  // Delegación total en sciots-rsa — aquí no se toca crypto ni BigInt directamente
  return rsa.generateKeyPair(bits);
}

// ═════════════════════════════════════════════════════════════════
// SECCIÓN 6 — FIRMA
// ═════════════════════════════════════════════════════════════════

/**
 * signData(data, privateKey)
 *
 * Proceso:
 *  1. Serializa data → string
 *  2. SHA-256(string) → hexDigest  [crypto, SOLO para hash]
 *  3. hexDigest → BigInt
 *  4. s = privateKey.sign(hash)    [RsaPrivateKey.sign() de sciots-rsa → modPow]
 *  5. return s.toString()          [string decimal, serializable en JSON]
 *
 * @param {string|object} data         Dato a firmar
 * @param {rsa.RsaPrivateKey|{n:string,d:string}} privateKey
 * @returns {string}  Firma como string decimal
 */
export function signData(data, privateKey) {
  const key  = toPrivateKey(privateKey);
  const hash = hashToBigInt(data);           // SHA-256 → BigInt (crypto solo para hash)
  const sig  = key.sign(hash);               // RsaPrivateKey.sign() de sciots-rsa
  return sig.toString();                     // BigInt → string decimal para JSON
}

// ═════════════════════════════════════════════════════════════════
// SECCIÓN 7 — VERIFICACIÓN DE FIRMA
// ═════════════════════════════════════════════════════════════════

/**
 * verifySignature(data, signature, publicKey)
 *
 * Proceso:
 *  1. recovered = publicKey.verify(BigInt(signature))  [RsaPublicKey.verify() de sciots-rsa]
 *  2. expected  = SHA-256(data) → BigInt               [crypto, SOLO para hash]
 *  3. return recovered === expected
 *
 * @param {string|object} data
 * @param {string} signature          String decimal (BigInt.toString)
 * @param {rsa.RsaPublicKey|{n:string,e:string}} publicKey
 * @returns {boolean}
 */
export function verifySignature(data, signature, publicKey) {
  try {
    const key       = toPublicKey(publicKey);
    const sigBigInt = BigInt(signature);
    const recovered = key.verify(sigBigInt);   // RsaPublicKey.verify() de sciots-rsa
    const expected  = hashToBigInt(data);      // SHA-256 → BigInt (crypto solo para hash)
    return recovered === expected;
  } catch (err) {
    console.error('[rsaHelpers] verifySignature error:', err.message);
    return false;
  }
}

// ═════════════════════════════════════════════════════════════════
// SECCIÓN 8 — CIFRADO
// ═════════════════════════════════════════════════════════════════

/**
 * encryptData(data, publicKey)
 *
 * Proceso:
 *  1. string → BigInt (bytes big-endian)
 *  2. c = publicKey.encrypt(m)    [RsaPublicKey.encrypt() de sciots-rsa → modPow]
 *  3. return c.toString()
 *
 * NOTA: solo apto para strings cortos (tamaño en bytes < tamaño del módulo n).
 * En este proyecto se usa de forma demostrativa.
 *
 * @param {string} data
 * @param {rsa.RsaPublicKey|{n:string,e:string}} publicKey
 * @returns {string}  Cifrado como string decimal
 */
export function encryptData(data, publicKey) {
  const key = toPublicKey(publicKey);
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  const m   = stringToBigInt(str);

  if (m >= key.n) {
    throw new Error('[rsaHelpers] encryptData: mensaje demasiado largo para el módulo RSA');
  }

  const c = key.encrypt(m);    // RsaPublicKey.encrypt() de sciots-rsa
  return c.toString();
}

// ═════════════════════════════════════════════════════════════════
// SECCIÓN 9 — DESCIFRADO
// ═════════════════════════════════════════════════════════════════

/**
 * decryptData(ciphertext, privateKey)
 *
 * Proceso:
 *  1. BigInt(ciphertext)
 *  2. m = privateKey.decrypt(c)   [RsaPrivateKey.decrypt() de sciots-rsa → modPow]
 *  3. BigInt → string UTF-8
 *
 * @param {string} ciphertext    String decimal (BigInt.toString)
 * @param {rsa.RsaPrivateKey|{n:string,d:string}} privateKey
 * @returns {string}  Texto plano
 */
export function decryptData(ciphertext, privateKey) {
  const key = toPrivateKey(privateKey);
  const c   = BigInt(ciphertext);
  const m   = key.decrypt(c);     // RsaPrivateKey.decrypt() de sciots-rsa
  return bigIntToString(m);
}