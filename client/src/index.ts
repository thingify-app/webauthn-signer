export * from './keypair';
export * from './webcrypto';
export * from './nodekeys';
export * from './rootkeys';
export * from './storage';
export * from './utils';

import { KeyPair } from './keypair';
import { arrayBufferToString, fromBase64, stringToArrayBuffer, toBase64 } from './utils';
import { createKeyPairNoStorage, createVerifier as createVerifierWebAuthn, loadKeyPairNoStorage, loadLocalKeyId, LoginChallengeResult, performLoginChallenge, WebAuthnKeyPair } from './webauthn';
import { createKeyPair as createKeyPairWebCrypto, createVerifier as createVerifierWebCrypto } from './webcrypto';

export async function createStateInitial(username: string, nonce: ArrayBuffer): Promise<WebAuthnKeyPair> {
    // Create root key.
    return await createKeyPairNoStorage(username, nonce);
}

export async function login(keyId: ArrayBuffer, nonce: ArrayBuffer): Promise<LoginChallengeResult> {
    return await performLoginChallenge(keyId, nonce);
}

export async function importState(state: string): Promise<[RootKeyState, InMemoryKeyPair]> {
    const parsedState: ExportedState = JSON.parse(state);
    const keyId = parsedState.rootKeyId;

    const inMemoryKeyPair = await createKeyPairWebCrypto('in-memory-temp-key');
    const inMemoryPublicKey = inMemoryKeyPair.getPublicKey();
    console.log('In-memory public key:');
    console.log(toBase64(inMemoryPublicKey));

    // Pass the in-memory public key as a challenge, so that we can use this signed key.
    const [keyPair, signature] = await loadKeyPairNoStorage(keyId, parsedState.publicRootKey, inMemoryPublicKey);
    return [
        new RootKeyState(keyPair),
        new InMemoryKeyPair(inMemoryKeyPair, signature)
    ];
}

export async function loadLocalKey(nonce: ArrayBuffer): Promise<string> {
    return loadLocalKeyId(nonce);
}

export class RootKeyState {
    constructor(private rootKey: KeyPair) {}

    exportState(): ExportedState {
        return {
            publicRootKey: toBase64(this.rootKey.getPublicKey()),
            rootKeyId: toBase64(this.rootKey.getKeyId()),
            adminKeys: [],
        };
    }

    getRootPublicKey(): ArrayBuffer {
        return this.rootKey.getPublicKey();
    }

    signPayload(message: ArrayBuffer): Promise<string> {
        return this.rootKey.sign(message);
    }

    verifyPayload(message: ArrayBuffer, signature: string): Promise<boolean> {
        return this.rootKey.verify(message, signature);
    }
}

export class InMemoryKeyPair implements KeyPair {
    private signaturePrefix: string;
    constructor(private inMemoryKeyPair: KeyPair, private inMemoryKeyPairSignature: string) {
        this.signaturePrefix = `${toBase64(this.inMemoryKeyPair.getPublicKey())}.${toBase64(stringToArrayBuffer(this.inMemoryKeyPairSignature))}`;
    }

    getKeyId(): ArrayBuffer {
        return this.inMemoryKeyPair.getKeyId();
    }

    getUserId(): string {
        return this.inMemoryKeyPair.getUserId();
    }

    getPublicKey(): ArrayBuffer {
        return this.inMemoryKeyPair.getPublicKey();
    }

    async save(): Promise<void> {
        // No-op for in-memory key.
    }

    async sign(message: ArrayBuffer): Promise<string> {
        const messageSignature = await this.inMemoryKeyPair.sign(message);
        return `${this.signaturePrefix}.${messageSignature}`;
    }

    async verify(message: ArrayBuffer, signature: string): Promise<boolean> {
        throw new Error('In-memory key cannot verify signatures!');
    }
}

export async function verifySignature(message: ArrayBuffer, signature: string, rootPublicKey: ArrayBuffer): Promise<boolean> {
    // Signature consists of 3 dot-separated components:
    // - public key of the temporary key used to sign the message
    // - signature of the temporary key's public key by the root key
    // - signature of the message by the temporary key
    const parts = signature.split('.', 3);
    const tempPublicKey = fromBase64(parts[0]);
    const tempKeySignature = arrayBufferToString(fromBase64(parts[1]));
    const messageSignature = parts[2];

    const rootKeyVerifier = await createVerifierWebAuthn(rootPublicKey);
    const isTempKeySignatureValid = await rootKeyVerifier.verify(tempPublicKey, tempKeySignature);

    if (!isTempKeySignatureValid) {
        return false;
    }

    const tempKeyVerifier = await createVerifierWebCrypto(tempPublicKey);
    return await tempKeyVerifier.verify(message, messageSignature);
}

export interface ExportedState {
    publicRootKey: string;
    rootKeyId: string;
    adminKeys: ExportedAdminKey[];
}

export interface ExportedAdminKey {
    nickname: string;
    publicKey: string;
    keyId: string;
    timestamp: string;
    rootKeySignature: string;
}
