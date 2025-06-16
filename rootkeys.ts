import { KeyPair } from './keypair';
import { LocalStorage } from './storage';
import { createKeyPair, loadKeyPairs } from './webauthn';

const localUserStorage = new LocalStorage('LOCAL_USER');

export async function loadRootKeyPairs(): Promise<KeyPair[]> {
    const keyPairs = await loadKeyPairs(localUserStorage);
    if (keyPairs.length === 0) {
        throw new Error('No WebAuthn keypairs found!');
    } else {
        return keyPairs;
    }
}

export async function createRootKey(username: string): Promise<KeyPair> {
    return await createKeyPair(localUserStorage, username);
}
