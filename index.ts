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

populateYourAccount();

generateButton?.addEventListener('click', async () => {
    const username = usernameBox.value;
    if (username.length === 0) {
        alert('Please enter a username.');
        return;
    }

    const creds = await createPublicKeyCredentials(stringToArrayBuffer('foobar'), username);
    const publicKey = await importPublicKey(creds.publicKey);
    console.log(creds);
    console.log(toBase64(creds.publicKey));
    await savePublicKey(username, creds.rawId, publicKey);
    populateYourAccount();
});

signOutButton?.addEventListener('click', async () => {
    localStorage.clear();
    populateYourAccount();
});

signButton?.addEventListener('click', async () => {
    const localKey = await loadPublicKey();
    const userId = localKey ? localKey.rawId : null;
    const message = messageToSign.value;
    const challenge = stringToArrayBuffer(message);
    const signedData = await signChallenge(challenge, userId);

    signatureBox.replaceChildren(createInputBoxElement(signedDataToCompact(signedData)));
});

verifyButton?.addEventListener('click', async () => {
    try {
        const spkiKey = fromBase64(publicKeyBox.value);
        const publicKey = await importPublicKey(spkiKey);
        
        const message = messageToVerify.value;
        const signedData = compactToSignedData(signatureToVerify.value);
        console.log(signedData);

        const verified = await verifySignature(publicKey, message, signedData);
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

    const localPublicKey = await loadPublicKey();
    if (localPublicKey) {
        const spki = await crypto.subtle.exportKey('spki', localPublicKey.publicKey);
        yourAccountsBox.innerText = `${localPublicKey.userId}: `;
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

async function createPublicKeyCredentials(challenge: ArrayBuffer, userId: string): Promise<GeneratedCredentials> {
    const options: PublicKeyCredentialCreationOptions = {
        challenge,
        pubKeyCredParams: [{
            type: "public-key",
            alg: -7
        }],
        rp: {
            name: 'WebAuthn Signer Demo'
        },
        user: {
            id: stringToArrayBuffer(userId),
            name: userId,
            displayName: userId
        },
        // For some reason, this is required to use e.g. Google Password Manager passkey.
        authenticatorSelection: {
            residentKey: 'required'
        }
    };
    const creds = await navigator.credentials.create({
        publicKey: options
    }) as PublicKeyCredential;

    const response = creds.response as AuthenticatorAttestationResponse;
    console.log(response);
    return {
        rawId: creds.rawId,
        publicKey: response.getPublicKey()!,
        algorithm: response.getPublicKeyAlgorithm(),
    };
}

async function importPublicKey(spkiKey: ArrayBuffer): Promise<CryptoKey> {
    return await crypto.subtle.importKey('spki', spkiKey, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
}

async function savePublicKey(userId: string, rawId: ArrayBuffer, key: CryptoKey): Promise<void> {
    const spki = await crypto.subtle.exportKey('spki', key);
    localStorage.setItem('LOCAL_KEY', JSON.stringify({
        userId: userId,
        rawId: toBase64(rawId),
        spki: toBase64(spki),
    }));
}

async function loadPublicKey(): Promise<SavedKey|null> {
    const localKey = localStorage.getItem('LOCAL_KEY');
    if (localKey) {
        const parsed = JSON.parse(localKey);
        const publicKey = await crypto.subtle.importKey('spki', fromBase64(parsed.spki), {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
        return {
            userId: parsed.userId,
            rawId: fromBase64(parsed.rawId),
            publicKey,
        };
    } else {
        return null;
    }
}

async function signChallenge(challenge: ArrayBuffer, rawId: ArrayBuffer|null): Promise<SignedData> {
    const getOptions: PublicKeyCredentialRequestOptions = {
        challenge,
        allowCredentials: rawId ? [
            {
                type: 'public-key',
                id: rawId
            }
        ] : [],
        userVerification: 'required',
    };

    const assertion = await navigator.credentials.get({
        publicKey: getOptions,
    }) as PublicKeyCredential;
    console.log(assertion);
    const response = assertion.response as AuthenticatorAssertionResponse;
    const signature = convertEcdsaAsn1Signature(new Uint8Array(response.signature));

    return {
        authenticatorData: response.authenticatorData,
        clientData: response.clientDataJSON,
        signature: signature
    };
}

async function verifySignature(publicKey: CryptoKey, message: string, signedData: SignedData): Promise<boolean> {
    // First, validate that the client data JSON contains the given message.
    const clientDataParsed = JSON.parse(arrayBufferToString(signedData.clientData));
    console.log(clientDataParsed);
    console.log(fromBase64(clientDataParsed.challenge));
    const messageMatches = arrayBufferToString(fromBase64(clientDataParsed.challenge)) === message;
    if (!messageMatches) {
        throw new Error('Message does not match challenge.');
    }

    const hashedClientData = await crypto.subtle.digest({name: 'SHA-256'}, signedData.clientData);
    const data = mergeBuffer(signedData.authenticatorData, hashedClientData);

    return await crypto.subtle.verify({
        name: 'ECDSA',
        hash: 'SHA-256'
    }, publicKey, signedData.signature, data);
}

function stringToArrayBuffer(str: string): ArrayBuffer {
    const textEncoder = new TextEncoder();
    return textEncoder.encode(str);
}

function arrayBufferToString(arr: ArrayBuffer): string {
    const textDecoder = new TextDecoder();
    return textDecoder.decode(arr);
}

function mergeBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer): ArrayBuffer {
    const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
}

function readAsn1IntegerSequence(input: Uint8Array): Uint8Array<ArrayBuffer>[] {
    if (input[0] !== 0x30) throw new Error('Input is not an ASN.1 sequence');
    const seqLength = input[1];
    const elements : Uint8Array[] = [];
  
  
    let current = input.slice(2, 2 + seqLength);
    while (current.length > 0) {
      const tag = current[0];
      if (tag !== 0x02) throw new Error('Expected ASN.1 sequence element to be an INTEGER');
  
  
      const elLength = current[1];
      elements.push(current.slice(2, 2 + elLength));
  
  
      current = current.slice(2 + elLength);
    }
    return elements;
}

function convertEcdsaAsn1Signature(input: Uint8Array): ArrayBuffer {
    const elements = readAsn1IntegerSequence(input);
    if (elements.length !== 2) throw new Error('Expected 2 ASN.1 sequence elements');
    let [r, s] = elements;

    // R and S length is assumed multiple of 128bit.
    // If leading is 0 and modulo of length is 1 byte then
    // leading 0 is for two's complement and will be removed.
    if (r[0] === 0 && r.byteLength % 16 == 1) {
      r = r.slice(1);
    }
    if (s[0] === 0 && s.byteLength % 16 == 1) {
      s = s.slice(1);
    }

    // R and S length is assumed multiple of 128bit.
    // If missing a byte then it will be padded by 0.
    if ((r.byteLength % 16) == 15) {
      r = new Uint8Array(mergeBuffer(new Uint8Array([0]), r));
    }
    if ((s.byteLength % 16) == 15) {
      s = new Uint8Array(mergeBuffer(new Uint8Array([0]), s));
    }

    // If R and S length is not still multiple of 128bit,
    // then error
    if (r.byteLength % 16 != 0) throw Error("unknown ECDSA sig r length error");
    if (s.byteLength % 16 != 0) throw Error("unknown ECDSA sig s length error");

    return mergeBuffer(r, s);
}

function toBase64(input: ArrayBuffer): string {
    return btoa(String.fromCodePoint(...new Uint8Array(input)));
}

function fromBase64(input: string): Uint8Array {
    return Uint8Array.from(atob(input), m => m.codePointAt(0)!);
}

function signedDataToCompact(signedData: SignedData): string {
    return `${toBase64(signedData.authenticatorData)}.${toBase64(signedData.clientData)}.${toBase64(signedData.signature)}`;
}

function compactToSignedData(compact: string): SignedData {
    const parts = compact.split('.', 3);
    const authenticatorData = fromBase64(parts[0]);
    const clientData = fromBase64(parts[1]);
    const signature = fromBase64(parts[2]);
    return {
        authenticatorData,
        clientData,
        signature
    };
}

interface GeneratedCredentials {
    rawId: ArrayBuffer;
    publicKey: ArrayBuffer;
    algorithm: COSEAlgorithmIdentifier;
}

interface SignedData {
    authenticatorData: ArrayBuffer;
    clientData: ArrayBuffer;
    signature: ArrayBuffer;
}

interface SavedKey {
    userId: string;
    rawId: ArrayBuffer;
    publicKey: CryptoKey;
}
