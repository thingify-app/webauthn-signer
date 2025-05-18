import { KeyPair, Verifier } from './keypair';
import { LocalStorage } from './storage';
import { fromBase64, stringToArrayBuffer, toBase64 } from './utils';
import { createKeyPair, createVerifier, loadKeyPair } from './webauthn';

const usernameBox = document.getElementById('username') as HTMLInputElement;
const generateButton = document.getElementById('generateKey') as HTMLButtonElement;
const yourAccountsBox = document.getElementById('yourAccounts') as HTMLDivElement;
const signOutButton = document.getElementById('signOut') as HTMLButtonElement;
const messageToSign = document.getElementById('messageToSign') as HTMLTextAreaElement;
const signButton = document.getElementById('signDocument') as HTMLButtonElement;
const signatureBox = document.getElementById('signature') as HTMLDivElement;
const publicKeyBox = document.getElementById('publicKey') as HTMLInputElement;
const messageToVerify = document.getElementById('messageToVerify') as HTMLTextAreaElement;
const signatureToVerify = document.getElementById('signatureToVerify') as HTMLTextAreaElement;
const verifyButton = document.getElementById('verifyDocument') as HTMLButtonElement;
const verifyStatus = document.getElementById('verifyStatus') as HTMLDivElement;

const localUserStorage = new LocalStorage();
populateYourAccount();

generateButton?.addEventListener('click', async () => {
    const username = usernameBox.value;
    if (username.length === 0) {
        alert('Please enter a username.');
        return;
    }

    console.log(localUserStorage);
    const creds = await createKeyPair(localUserStorage, username);
    await creds.save();
    populateYourAccount();
});

signOutButton?.addEventListener('click', async () => {
    localUserStorage.clear();
    populateYourAccount();
});

signButton?.addEventListener('click', async () => {
    const signer = await loadSigner();
    if (signer === null) {
        alert('No local key found!');
        return;
    }

    const message = messageToSign.value;
    const challenge = stringToArrayBuffer(message);

    const signature = await signer.sign(challenge);
    signatureBox.replaceChildren(createInputBoxElement(signature));
});

verifyButton?.addEventListener('click', async () => {
    try {
        const spkiKey = fromBase64(publicKeyBox.value);
        
        const message = messageToVerify.value;
        const signature = signatureToVerify.value;
        const verifier = await loadVerifier(spkiKey);

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
    signOutButton.style.display = 'none';
    yourAccountsBox.innerHTML = '';

    const signer = await loadSigner();
    if (signer) {
        const spki = signer.getPublicKey();
        yourAccountsBox.innerText = `${signer.getUserId()}: `;
        const keyInput = createInputBoxElement(toBase64(spki));
        yourAccountsBox.appendChild(keyInput);
        signButton.disabled = false;
        signOutButton.style.display = 'block';
    } else {
        yourAccountsBox.innerText = 'Signed out.';
        signButton.disabled = true;
        signOutButton.style.display = 'none';
    }
}

function createInputBoxElement(value: string): HTMLInputElement {
    const input = document.createElement('input');
    input.value = value;
    input.readOnly = true;
    return input;
}

async function loadSigner(): Promise<KeyPair|null> {
    return await loadKeyPair(localUserStorage);
}

async function loadVerifier(publicKey: ArrayBuffer): Promise<Verifier> {
    return await createVerifier(publicKey);
}
