import { KeyPair, Signer, Verifier } from './keypair';
import { LocalStorage } from './storage';
import { fromBase64, stringToArrayBuffer, toBase64 } from './utils';
import { createKeyPair as createWebAuthnKeyPair, createVerifier as createWebAuthnVerifier, loadKeyPairs as loadWebAuthnKeyPairs } from './webauthn';
import { createKeyPair as createWebCryptoKeyPair, createVerifier as createWebCryptoVerifier, loadKeyPairs as loadWebCryptoKeyPairs } from './webcrypto';

const usernameBox = document.getElementById('username') as HTMLInputElement;
const signUpButton = document.getElementById('signUp') as HTMLButtonElement;
const rootKeyNicknameBox = document.getElementById('rootKeyNickname') as HTMLInputElement;
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

let selectedRootKey: KeyPair|null = null;

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

addRootKeyButton.addEventListener('click', async () => {
    const nickname = rootKeyNicknameBox.value;

    if (nickname.length === 0) {
        return alert('Nickname required!');
    }

    const creds = await createKeyPair(nickname);
    await creds.save();
    populateYourAccount();

    rootKeyNicknameBox.value = '';
});

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

    if (!selectedRootKey) {
        return alert('No root key selected for signing!');
    }

    await addNodeKey(selectedRootKey, {
        nickname,
        publicKey
    });

    populateTrustedNodeKeys();

    nodeKeyNicknameBox.value = '';
    nodeKeyBox.value = '';
});

generateLocalNodeKeyButton.addEventListener('click', async () => {
    if (!selectedRootKey) {
        return alert('No root key selected for signing!');
    }

    const userId = crypto.randomUUID();
    const keyPair = await createWebCryptoKeyPair(userId);
    keyPair.save();
    
    // Add local key to list of trusted node keys:
    await addNodeKey(selectedRootKey, {
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
    yourRootKeysBox.innerHTML = '';

    const keyPairs = await loadWebAuthnKeyPairs(localUserStorage);
    if (keyPairs.length > 0) {
        for (const [index, key] of keyPairs.entries()) {
            const spki = key.getPublicKey();

            const selectHandler = async () => {
                selectedRootKey = key;
                console.log(`Selected root key: ${key.getUserId()}`);
            };

            yourRootKeysBox.appendChild(
                createRootKeyElement(
                    key.getUserId(),
                    spki,
                    index === 0,
                    selectHandler
                )
            );
        }
    } else {
        yourRootKeysBox.innerText = 'Signed out.';
    }
}

function createRootKeyElement(label: string, spki: ArrayBuffer, first: boolean, selectHandler: () => void): HTMLDivElement {
    const container = createInputBoxElement(`${label}: `, toBase64(spki));
    
    const radio = document.createElement('input');
    radio.type = 'radio';
    radio.name = 'selectedRootKey';
    radio.value = label;

    if (first) {
        radio.checked = true;
        selectHandler();
    }

    radio.addEventListener('click', () => {
        if (radio.checked) {
            selectHandler();
        }
    });

    container.prepend(radio);
    return container;
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

async function loadRootKeyPairs(): Promise<KeyPair[]> {
    const keyPairs = await loadWebAuthnKeyPairs(localUserStorage);
    if (keyPairs.length === 0) {
        throw new Error('No WebAuthn keypairs found!');
    } else {
        return keyPairs;
    }
}

async function populateTrustedNodeKeys() {
    // Reset UI state first
    trustedNodeKeysBox.innerHTML = '';

    const nodeKeys = await loadNodeKeys();
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

async function addNodeKey(signer: KeyPair, nodeKey: NodeKey): Promise<void> {
    const nodeKeys = await loadNodeKeys();
    nodeKeys.push(nodeKey);

    await saveNodeKeys(signer, nodeKeys);
}

async function loadNodeKeys(): Promise<NodeKey[]> {
    const rootKeyPairs = await loadRootKeyPairs();
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

async function saveNodeKeys(signer: KeyPair, nodeKeys: NodeKey[]): Promise<void> {
    const signedPayload = await generateNodeKeyPayload(signer, nodeKeys);
    await nodeKeyStorage.store('NODE_KEYS', JSON.stringify(signedPayload));
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

interface NodeKey {
    nickname: string;
    publicKey: string;
}
