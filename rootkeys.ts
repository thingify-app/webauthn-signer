import { KeyPair } from './keypair';
import { LocalStorage } from './storage';
import { stringToArrayBuffer, toBase64 } from './utils';
import { createKeyPair, loadKeyPairs } from './webauthn';

const webAuthnStorage = new LocalStorage('WEB_AUTHN_KEYS');
const rootKeyStorage = new LocalStorage('ROOT_KEYS');

export async function loadRootKeyPairs(): Promise<KeyPair[]> {
    const rootKeyString = await rootKeyStorage.load('ROOT_KEYS');
    if (rootKeyString) {
        const rootKeyPayload: RootKeyPayload = JSON.parse(rootKeyString);
        const keys: RootKey[] = JSON.parse(rootKeyPayload.payload);

        const webAuthnKeys = await loadKeyPairs(webAuthnStorage);
        const keyPairs: KeyPair[] = [];

        if (keys.length !== rootKeyPayload.signatures.length) {
            throw new Error('Number of signatures does not match number of keys in payload!');
        }

        for (const [index, key] of keys.entries()) {
            const keyPair = webAuthnKeys.find(webAuthnKey => webAuthnKey.getUserId() === key.keyId);
            if (!keyPair) {
                throw new Error(`WebAuthn key not found for key ID: ${key.keyId}`);
            }
            if (key.spkiPublicKey !== toBase64(keyPair.getPublicKey())) {
                throw new Error(`Stored WebAuthn public key does not match signed public key for key ID ${key.keyId}!`);
            }

            const verified = await keyPair.verify(stringToArrayBuffer(rootKeyPayload.payload), rootKeyPayload.signatures[index]);
            if (!verified) {
                throw new Error(`Could not verify signature for key ID ${key.keyId}!`);
            }

            keyPairs.push(keyPair);
        }

        return keyPairs;
    } else {
        return [];
    }
}

export async function createRootKey(username: string): Promise<KeyPair> {
    return await createKeyPair(webAuthnStorage, username);
}

export async function addRootKey(newKey: KeyPair): Promise<void> {
    const allKeys = await loadRootKeyPairs();
    allKeys.push(newKey);

    // To add a new root key, every existing root key plus the new key must
    // sign the new payload.
    await saveKeys(allKeys);
}

export async function deleteRootKey(keyId: string): Promise<void> {
    const existingKeys = await loadRootKeyPairs();

    if (!existingKeys.find(key => key.getUserId() === keyId)) {
        throw new Error(`Key with ID ${keyId} does not exist!`);
    }
    
    // To remove a root key, all other existing root keys must sign the new
    // payload.
    const newKeys = existingKeys.filter(key => key.getUserId() !== keyId);
    await saveKeys(newKeys);
}

async function saveKeys(keys: KeyPair[]): Promise<void> {
    const payload = await generateRootKeyPayload(keys);
    await rootKeyStorage.store('ROOT_KEYS', JSON.stringify(payload));
}

async function generateRootKeyPayload(keys: KeyPair[]): Promise<RootKeyPayload> {
    const rootKeys: RootKey[] = keys.map(key => ({
        keyId: key.getUserId(),
        spkiPublicKey: toBase64(key.getPublicKey()),
    }));

    const payload = JSON.stringify(rootKeys);

    const signatures = [];
    for (const key of keys) {
        signatures.push(await key.sign(stringToArrayBuffer(payload)));
    }

    return {
        payload,
        signatures,
    };
}

interface RootKeyPayload {
    payload: string;
    signatures: string[];
}

interface RootKey {
    keyId: string;
    spkiPublicKey: string;
}
