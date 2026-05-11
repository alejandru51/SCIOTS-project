import { modInv, modPow } from 'bigint-crypto-utils';
import * as bcu from 'bigint-crypto-utils';

export class RsaPublicKey {
  constructor(n, e) {
    this.n = n;
    this.e = e;
  }
  encrypt(m) { return modPow(m, this.e, this.n); }
  verify(s)  { return modPow(s, this.e, this.n); }
}

export class RsaPrivateKey {
  constructor(n, d) {
    this.n = n;
    this.d = d;
  }
  decrypt(c) { return modPow(c, this.d, this.n); }
  sign(m)    { return modPow(m, this.d, this.n); }
}

export function generateKeyPair(bitLength) {
  const p    = bcu.primeSync(bitLength / 2);
  const q    = bcu.primeSync(bitLength / 2);
  const n    = p * q;
  const phiN = (p - 1n) * (q - 1n);
  const e    = 65537n;
  const d    = modInv(e, phiN);
  return {
    publicKey:  new RsaPublicKey(n, e),
    privateKey: new RsaPrivateKey(n, d),
  };
}