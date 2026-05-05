import { modInv, modPow, phi, prime, primeSync } from 'bigint-crypto-utils';
import e from 'express';
export class RsaPublicKey{
    constructor(n,e){
        this.n = n;
        this.e = e;
    }
    encrypt(m){
        return modPow(m, this.e,this.n);
    }
    verify(s){
        return modPow(s, this.e,this.n);
    }
}
export class RsaPrivateKey{
    constructor(n,e){
        this.n = n;
        this.e = e;
    }
    decrypt(c){
        return modPow(c, this.e,this.n);
    }
    sign(m){
        return modPow(m, this.e,this.n);
    }
}
export function generateKeyPair(bitlenght){
    p= primeSync(bitlenght/2);
    q = primeSync(bitlenght/2);
    n= p*q;
    phi = (p-1n)*(q-1n);
    e=65537n;
    d= modInv(e,phi);
    return{
        publicKey: new RsaPublicKey(n,e),
        privateKey: new RsaPrivateKey(n,d)
    }
}