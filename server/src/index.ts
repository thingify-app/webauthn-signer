export * from './storage';

import { Account, Storage } from './storage';
import { arrayBuffersEqual, arrayBufferToString, fromBase64, mergeBuffer } from './utils';

export class Server {
    constructor(private storage: Storage) {}

    async createAccountInitial(): Promise<ArrayBuffer> {
        const nonce = createNonce();
        await this.storage.storeNonce(nonce, Date.now() + 5 * 60 * 1000);
        return nonce;
    }

    async createAccount(nonce: ArrayBuffer, username: string, keyId: ArrayBuffer, publicKey: ArrayBuffer): Promise<void> {
        // Lookup the nonce and verify it's valid and unexpired.
        const nonceValid = await this.storage.verifyAndDeleteNonce(nonce);
        if (!nonceValid) {
            throw new Error('Invalid or expired nonce');
        }

        // Validate the public key format by attempting to import it.
        await importPublicKey(publicKey);

        // Store the account.
        const account: Account = { username, keyId, publicKey };
        await this.storage.storeAccount(account);
    }

    async loginInitial(username: string) {
        // Lookup the account by username.
        const account = await this.storage.getAccount(username);
        if (!account) {
            throw new Error('Account not found');
        }

        // Generate a nonce and store it.
        const nonce = createNonce();
        await this.storage.storeNonce(nonce, Date.now() + 5 * 60 * 1000);

        return { nonce, keyId: account.keyId };
    }

    async login(nonce: ArrayBuffer, username: string, authenticatorData: ArrayBuffer, clientDataJSON: ArrayBuffer, signature: ArrayBuffer) {
        // Lookup the account by username.
        const account = await this.storage.getAccount(username);
        if (!account) {
            throw new Error('Account not found');
        }

        // Lookup the nonce and verify it's valid and unexpired.
        const nonceValid = await this.storage.verifyAndDeleteNonce(nonce);
        if (!nonceValid) {
            throw new Error('Invalid or expired nonce');
        }

        // Verify the signature of the nonce using the stored publicKey.
        const signatureValid = await verifyWebauthnSignature(await importPublicKey(account.publicKey), nonce, authenticatorData, clientDataJSON, signature);

        if (!signatureValid) {
            throw new Error('Invalid signature');
        }
    }
}

function createNonce(): ArrayBuffer {
    const nonce = new Uint8Array(64);
    crypto.getRandomValues(nonce);
    return nonce.buffer;
}

async function importPublicKey(spkiKey: ArrayBuffer): Promise<CryptoKey> {
    return await crypto.subtle.importKey('spki', spkiKey, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
}

async function verifyWebauthnSignature(publicKey: CryptoKey, challenge: ArrayBuffer, authenticatorData: ArrayBuffer, clientDataJSON: ArrayBuffer, signature: ArrayBuffer): Promise<boolean> {
    // First, validate that the client data JSON contains the given message.
    const clientDataParsed = JSON.parse(arrayBufferToString(clientDataJSON));

    const messageMatches = arrayBuffersEqual(fromBase64(clientDataParsed.challenge), challenge);
    if (!messageMatches) {
        console.error('Message does not match challenge.');
        return false;
    }

    const hashedClientData = await crypto.subtle.digest({name: 'SHA-256'}, clientDataJSON);
    const data = mergeBuffer(authenticatorData, hashedClientData);

    return await crypto.subtle.verify({
        name: 'ECDSA',
        hash: 'SHA-256'
    }, publicKey, signature, data);
}
