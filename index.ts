import { KeyPair, Signer, Verifier } from './keypair';
import { LocalStorage } from './storage';
import { fromBase64, stringToArrayBuffer, toBase64 } from './utils';
import { createKeyPair as createWebAuthnKeyPair, createVerifier as createWebAuthnVerifier, loadKeyPairs as loadWebAuthnKeyPairs } from './webauthn';
import { createKeyPair as createWebCryptoKeyPair, createVerifier as createWebCryptoVerifier, loadKeyPairs as loadWebCryptoKeyPairs } from './webcrypto';

const usernameBox = document.getElementById('username') as HTMLInputElement;
const signUpButton = document.getElementById('signUp') as HTMLButtonElement;
const yourRootKeysBox = document.getElementById('yourRootKeys') as HTMLDivElement;
const addRootKeyButton = document.getElementById('addRootKey') as HTMLButtonElement;
const trustedNodeKeysBox = document.getElementById('trustedNodeKeys') as HTMLDivElement;
const nodeKeyNicknameBox = document.getElementById('nodeKeyNickname') as HTMLInputElement;
const nodeKeyBox = document.getElementById('nodeKey') as HTMLInputElement;
const addNodeKeyButton = document.getElementById('addNodeKey') as HTMLButtonElement;
const localNodeKeysBox = document.getElementById('localNodeKeys') as HTMLDivElement;
const generateLocalNodeKeyButton = document.getElementById('generateLocalNodeKey') as HTMLButtonElement;
const signingKeySelect = document.getElementById('signingKey') as HTMLSelectElement;
const messageToSign = document.getElementById('messageToSign') as HTMLTextAreaElement;
const signButton = document.getElementById('signDocument') as HTMLButtonElement;
const signatureBox = document.getElementById('signature') as HTMLDivElement;
const publicKeyBox = document.getElementById('publicKey') as HTMLInputElement;
const messageToVerify = document.getElementById('messageToVerify') as HTMLTextAreaElement;
const signatureToVerify = document.getElementById('signatureToVerify') as HTMLTextAreaElement;
const verifyButton = document.getElementById('verifyDocument') as HTMLButtonElement;
const verifyStatus = document.getElementById('verifyStatus') as HTMLDivElement;

const localUserStorage = new LocalStorage('LOCAL_USER');
const nodeKeyStorage = new LocalStorage('NODE_KEYS');

populateYourAccount();
populateTrustedNodeKeys();
populateLocalNodeKeys();

signUpButton.addEventListener('click', async () => {
    const username = usernameBox.value;
    if (username.length === 0) {
        alert('Please enter a username.');
        return;
    }

    const creds = await createKeyPair(username);
    await creds.save();
    populateYourAccount();
});

addRootKeyButton.addEventListener('click', async () => {});

addNodeKeyButton.addEventListener('click', async () => {
    const nickname = nodeKeyNicknameBox.value;
    const publicKey = nodeKeyBox.value;

    if (nickname.length === 0) {
        return alert('Nickname required!');
    }

    if (publicKey.length === 0) {
        return alert('Public key required!');
    }

    try {
        const spkiKey = fromBase64(nodeKeyBox.value);
        await createWebCryptoVerifier(spkiKey);
    } catch (err) {
        return alert('Could not parse public key!');
    }

    await addNodeKey({
        nickname,
        publicKey
    });

    populateTrustedNodeKeys();

    nodeKeyNicknameBox.value = '';
    nodeKeyBox.value = '';
});

generateLocalNodeKeyButton.addEventListener('click', async () => {
    const userId = crypto.randomUUID();
    const keyPair = await createWebCryptoKeyPair(userId);
    keyPair.save();
    
    // Add local key to list of trusted node keys:
    await addNodeKey({
        nickname: userId,
        publicKey: toBase64(keyPair.getPublicKey()),
    });

    // Re-populate both lists.
    populateTrustedNodeKeys();
    populateLocalNodeKeys();
});

signButton.addEventListener('click', async () => {
    const selectedKeyId = signingKeySelect.value;

    if (!selectedKeyId) {
        alert('Please select a signing key.');
        return;
    }

    const keyPairs = await loadWebCryptoKeyPairs();
    const signer = keyPairs.find(keyPair => keyPair.getUserId() === selectedKeyId);
    if (!signer) {
        alert('No local key found!');
        return;
    }

    const message = messageToSign.value;
    const challenge = stringToArrayBuffer(message);

    const signature = await signer.sign(challenge);
    signatureBox.replaceChildren(createInputBoxElement('', signature));
});

verifyButton.addEventListener('click', async () => {
    try {
        const spkiKey = fromBase64(publicKeyBox.value);
        
        const message = messageToVerify.value;
        const signature = signatureToVerify.value;
        const verifier = await createWebCryptoVerifier(spkiKey);

        const verified = await verifier.verify(stringToArrayBuffer(message), signature);
        console.log(`Verified: ${verified}`);
        verifyStatus.innerText = `Verified: ${verified}`;
    } catch (e) {
        verifyStatus.innerText = `Error: ${e}`;
    }
});

async function populateYourAccount() {
    // Reset UI state first.
    signButton.disabled = true;
    yourRootKeysBox.innerHTML = '';

    const signer = await loadRootKeyPair();
    if (signer) {
        const spki = signer.getPublicKey();
        yourRootKeysBox.appendChild(createInputBoxElement(`${signer.getUserId()}: `, toBase64(spki)));
        signButton.disabled = false;
    } else {
        yourRootKeysBox.innerText = 'Signed out.';
        signButton.disabled = true;
    }
}

function createInputBoxElement(label: string, value: string): HTMLDivElement {
    const container = document.createElement('div');
    const input = document.createElement('input');
    input.value = value;
    input.readOnly = true;
    container.appendChild(document.createTextNode(label));
    container.appendChild(input);
    return container;
}

async function createKeyPair(username: string): Promise<KeyPair> {
    return await createWebAuthnKeyPair(localUserStorage, username);
}

async function loadRootKeyPair(): Promise<KeyPair> {
    const keyPairs = await loadWebAuthnKeyPairs(localUserStorage);
    if (keyPairs.length === 0) {
        throw new Error('No WebAuthn keypairs found!');
    } else {
        return keyPairs[0];
    }
}

async function populateTrustedNodeKeys() {
    // Reset UI state first
    trustedNodeKeysBox.innerHTML = '';

    const rootKeyPair = await loadRootKeyPair();
    const nodeKeys = await loadNodeKeys(rootKeyPair);

    for (let key of nodeKeys) {
        trustedNodeKeysBox.appendChild(createInputBoxElement(`${key.nickname}: `, key.publicKey));
    }
}

async function populateLocalNodeKeys() {
    // Reset UI state first
    localNodeKeysBox.innerHTML = '';
    signingKeySelect.innerHTML = '';
    signingKeySelect.appendChild(createOptionElement('Choose a signing key...', ''));

    const keyPairs = await loadWebCryptoKeyPairs();
    for (let key of keyPairs) {
        const userId = key.getUserId();
        localNodeKeysBox.appendChild(createInputBoxElement(`${userId}: `, toBase64(key.getPublicKey())));
        signingKeySelect.appendChild(createOptionElement(userId, userId));
    }
}

function createOptionElement(label: string, value: string): HTMLOptionElement {
    const element = document.createElement('option');
    element.text = label;
    element.value = value;
    return element;
}

async function addNodeKey(nodeKey: NodeKey): Promise<void> {
    const rootKey = await loadRootKeyPair();

    const nodeKeys = await loadNodeKeys(rootKey);
    nodeKeys.push(nodeKey);

    await saveNodeKeys(rootKey, nodeKeys);
}

async function loadNodeKeys(verifier: Verifier): Promise<NodeKey[]> {
    let nodeKeys: NodeKey[] = [];
    
    const nodeKeyString = await nodeKeyStorage.load('NODE_KEYS');
    if (nodeKeyString) {
        const nodeKeyPayload: NodeKeyPayload = JSON.parse(nodeKeyString);
        const verified = await verifier.verify(stringToArrayBuffer(nodeKeyPayload.payload), nodeKeyPayload.signature);
        if (!verified) {
            throw new Error('Could not verify signature on saved node key payload!');
        }
        nodeKeys = JSON.parse(nodeKeyPayload.payload);
    }

    return nodeKeys;
}

async function saveNodeKeys(signer: Signer, nodeKeys: NodeKey[]): Promise<void> {
    const signedPayload = await generateNodeKeyPayload(signer, nodeKeys);
    await nodeKeyStorage.store('NODE_KEYS', JSON.stringify(signedPayload));
}

async function generateNodeKeyPayload(signer: Signer, keys: NodeKey[]): Promise<NodeKeyPayload> {
    const payload = JSON.stringify(keys);
    const signature = await signer.sign(stringToArrayBuffer(payload));
    return {
        payload,
        signature
    };
}

interface NodeKeyPayload {
    payload: string;
    signature: string;
}

interface NodeKey {
    nickname: string;
    publicKey: string;
}
