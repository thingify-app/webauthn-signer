import { KeyPair } from './keypair';
import { LocalStorage } from './storage';
import { stringToArrayBuffer, toBase64 } from './utils';
import { createKeyPair, loadKeyPairs } from './webcrypto';

const nodeKeyStorage = new LocalStorage('NODE_KEYS');

export async function createLocalNodeKey(rootKeyPairs: KeyPair[], signingRootKey: KeyPair): Promise<NodeKey> {
    const userId = crypto.randomUUID();
    const keyPair = await createKeyPair(userId);
    keyPair.save();

    const nodeKey: NodeKey = {
        nickname: userId,
        publicKey: toBase64(keyPair.getPublicKey()),
    };

    // Add local key to list of trusted node keys:
    await addNodeKey(rootKeyPairs, signingRootKey, nodeKey);

    return nodeKey;
}

export async function loadLocalNodeKeys(): Promise<KeyPair[]> {
    return await loadKeyPairs();
}

export async function loadNodeKeys(rootKeyPairs: KeyPair[]): Promise<NodeKey[]> {
    const nodeKeyString = await nodeKeyStorage.load('NODE_KEYS');
    if (nodeKeyString) {
        const nodeKeyPayload: NodeKeyPayload = JSON.parse(nodeKeyString);
        
        const signer = nodeKeyPayload.signedById;
        const signingKey = rootKeyPairs.find(keyPair => keyPair.getUserId() === signer);
        if (!signingKey) {
            throw new Error('Payload was not signed by known root key!');
        }
        
        const verified = await signingKey.verify(stringToArrayBuffer(nodeKeyPayload.payload), nodeKeyPayload.signature);
        if (!verified) {
            throw new Error('Could not verify signature on saved node key payload!');
        }

        const nodeKeys = JSON.parse(nodeKeyPayload.payload);
        return nodeKeys;
    } else {
        return [];
    }
}

export async function saveNodeKeys(signer: KeyPair, nodeKeys: NodeKey[]): Promise<void> {
    const signedPayload = await generateNodeKeyPayload(signer, nodeKeys);
    await nodeKeyStorage.store('NODE_KEYS', JSON.stringify(signedPayload));
}

export async function addNodeKey(rootKeyPairs: KeyPair[], signer: KeyPair, nodeKey: NodeKey): Promise<void> {
    const nodeKeys = await loadNodeKeys(rootKeyPairs);
    nodeKeys.push(nodeKey);

    await saveNodeKeys(signer, nodeKeys);
}

async function generateNodeKeyPayload(signer: KeyPair, keys: NodeKey[]): Promise<NodeKeyPayload> {
    const payload = JSON.stringify(keys);
    const signature = await signer.sign(stringToArrayBuffer(payload));
    return {
        payload,
        signature,
        signedById: signer.getUserId(),
    };
}

interface NodeKeyPayload {
    payload: string;
    signature: string;
    signedById: string;
}

export interface NodeKey {
    nickname: string;
    publicKey: string;
}