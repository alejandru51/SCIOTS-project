// Exactamente igual al del auth-resource-server.
// Copia completa para que device-server sea completamente independiente.

import { createHash } from 'crypto';
import * as rsa from 'sciots-rsa'; 

export function exportPublicKey(key) {
  return { n: key.n.toString(), e: key.e.toString() };
}

export function exportPrivateKey(key) {
  return { n: key.n.toString(), d: key.d.toString() };
}

export function importPublicKey(obj) {
  return new rsa.RsaPublicKey(BigInt(obj.n), BigInt(obj.e));
}

export function importPrivateKey(obj) {
  return new rsa.RsaPrivateKey(BigInt(obj.n), BigInt(obj.d));
}

export function generateKeyPair(bits = 2048) {
  return rsa.generateKeyPair(bits);
}

function hashToBigInt(data) {
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  // crypto → SOLO para SHA-256 hash ──────────────────────────────
  const hex = createHash('sha256').update(str, 'utf8').digest('hex');
  // ────────────────────────────────────────────────────────────────
  return BigInt('0x' + hex);
}

function stringToBigInt(str) {
  const hex = Buffer.from(str, 'utf8').toString('hex');
  return BigInt('0x' + hex);
}

function bigIntToString(big) {
  let hex = big.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return Buffer.from(hex, 'hex').toString('utf8');
}

function toPublicKey(key) {
  return key instanceof rsa.RsaPublicKey ? key : importPublicKey(key);
}

function toPrivateKey(key) {
  return key instanceof rsa.RsaPrivateKey ? key : importPrivateKey(key);
}

export function signData(data, privateKey) {
  const key  = toPrivateKey(privateKey);
  const hash = hashToBigInt(data);
  const sig  = key.sign(hash);        // RsaPrivateKey.sign() del módulo dado
  return sig.toString();
}

export function verifySignature(data, signature, publicKey) {
  try {
    const key       = toPublicKey(publicKey);
    const sigBigInt = BigInt(signature);
    const recovered = key.verify(sigBigInt);   // RsaPublicKey.verify() del módulo dado
    const expected  = hashToBigInt(data);
    return recovered === expected;
  } catch (err) {
    console.error('[rsaHelpers] verifySignature error:', err.message);
    return false;
  }
}

export function encryptData(data, publicKey) {
  const key = toPublicKey(publicKey);
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  const m   = stringToBigInt(str);
  if (m >= key.n) throw new Error('[rsaHelpers] Mensaje demasiado largo para el módulo RSA');
  const c = key.encrypt(m);           // RsaPublicKey.encrypt() del módulo dado
  return c.toString();
}

export function decryptData(ciphertext, privateKey) {
  const key = toPrivateKey(privateKey);
  const c   = BigInt(ciphertext);
  const m   = key.decrypt(c);         // RsaPrivateKey.decrypt() del módulo dado
  return bigIntToString(m);
}