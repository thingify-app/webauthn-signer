export * from './keypair';
export * from './webcrypto';
export * from './nodekeys';
export * from './rootkeys';
export * from './storage';
export * from './utils';

import { KeyPair } from './keypair';
import { toBase64 } from './utils';
import { createKeyPairNoStorage, loadKeyPairNoStorage } from './webauthn';

export async function createState(): Promise<RootKeyState> {
    // Create root key.
    const rootKeyPair = await createKeyPairNoStorage('root-key');
    return new RootKeyState(rootKeyPair);
}

export async function importState(state: string): Promise<RootKeyState> {
    const parsedState: ExportedState = JSON.parse(state);
    const keyId = parsedState.rootKeyId;

    const keyPair = await loadKeyPairNoStorage(keyId, parsedState.publicRootKey);
    return new RootKeyState(keyPair);
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

    listRootKeys(): KeyPair[] {
        return [];
    }

    signPayload(message: ArrayBuffer): Promise<string> {
        return this.rootKey.sign(message);
    }

    verifyPayload(message: ArrayBuffer, signature: string): Promise<boolean> {
        return this.rootKey.verify(message, signature);
    }
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
