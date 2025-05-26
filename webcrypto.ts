import { createStore, get, set, keys, UseStore } from 'idb-keyval';
import { KeyPair, Signer, Verifier } from './keypair';
import { fromBase64, toBase64 } from './utils';

export async function createKeyPair(userId: string): Promise<KeyPair> {
    const cryptoKeyPair = await crypto.subtle.generateKey({
        name: 'ECDSA', namedCurve: 'P-256'
    }, false, ['sign', 'verify']);
    
    const spkiPublicKey = await toSpki(cryptoKeyPair.publicKey);
    return new WebCryptoKeyPair(userId, cryptoKeyPair, spkiPublicKey);
}

export async function loadKeyPairs(): Promise<KeyPair[]> {
    const userIds = await keys(getStorage());
    return Promise.all(userIds.map(async userId => await loadKeyPair(userId as string) as KeyPair));
}

export async function loadKeyPair(userId: string): Promise<KeyPair|null> {
    const storage = getStorage();
    const cryptoKeyPair = await get(userId, storage) as CryptoKeyPair;

    const spkiPublicKey = await toSpki(cryptoKeyPair.publicKey);
    return new WebCryptoKeyPair(userId, cryptoKeyPair, spkiPublicKey);
}

export async function createVerifier(publicKeyBuffer: ArrayBuffer): Promise<Verifier> {
    const cryptoKey = await crypto.subtle.importKey('spki', publicKeyBuffer, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
    if (cryptoKey.type !== 'public') {
        throw new Error('Given key is not public!');
    }
    return new WebCryptoVerifier(cryptoKey);
}

class WebCryptoKeyPair implements KeyPair {
    private signer: Signer;
    private verifier: Verifier;

    constructor(private userId: string, private cryptoKeyPair: CryptoKeyPair, private spkiPublicKey: ArrayBuffer) {
        this.signer = new WebCryptoSigner(cryptoKeyPair.privateKey);
        this.verifier = new WebCryptoVerifier(cryptoKeyPair.publicKey);
    }

    getUserId(): string {
        return this.userId;
    }

    getPublicKey(): ArrayBuffer {
        return this.spkiPublicKey;
    }

    async save(): Promise<void> {
        const storage = getStorage();
        await set(this.userId, this.cryptoKeyPair, storage);
    }

    sign(message: ArrayBuffer): Promise<string> {
        return this.signer.sign(message);
    }

    verify(message: ArrayBuffer, signature: string): Promise<boolean> {
        return this.verifier.verify(message, signature);
    }    
}

class WebCryptoSigner implements Signer {
    constructor(private privateKey: CryptoKey) {}

    async sign(message: ArrayBuffer): Promise<string> {
        const signature = await crypto.subtle.sign({
            name: 'ECDSA',
            hash: 'SHA-256'
        }, this.privateKey, message);
        return toBase64(signature);
    }
}

class WebCryptoVerifier implements Verifier {
    constructor(private publicKey: CryptoKey) {}

    async verify(message: ArrayBuffer, signature: string): Promise<boolean> {
        return await crypto.subtle.verify({
            name: 'ECDSA',
            hash: 'SHA-256'
        }, this.publicKey, fromBase64(signature), message);
    }
}

function getStorage(): UseStore {
    return createStore('WEB_CRYPTO_KEYS', 'KEY_PAIRS');
}

async function toSpki(publicKey: CryptoKey): Promise<ArrayBuffer> {
    if (publicKey.type !== 'public') {
        throw new Error('Given key is not public!');
    }
    return await crypto.subtle.exportKey('spki', publicKey);
}
