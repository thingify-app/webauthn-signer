const usernameBox = document.getElementById('username') as HTMLInputElement;
const generateButton = document.getElementById('generateKey') as HTMLButtonElement;
const yourAccountsBox = document.getElementById('yourAccounts') as HTMLDivElement;
const messageToSign = document.getElementById('messageToSign') as HTMLTextAreaElement;
const signButton = document.getElementById('signDocument') as HTMLButtonElement;
const signatureBox = document.getElementById('signature') as HTMLDivElement;
const publicKeyBox = document.getElementById('publicKey') as HTMLInputElement;
const messageToVerify = document.getElementById('messageToVerify') as HTMLTextAreaElement;
const signatureToVerify = document.getElementById('signatureToVerify') as HTMLTextAreaElement;
const verifyButton = document.getElementById('verifyDocument') as HTMLButtonElement;

populateYourAccounts();

generateButton?.addEventListener('click', async () => {
    const username = usernameBox.value;
    if (username.length === 0) {
        alert('Please enter a username.');
        return;
    }

    const creds = await createPublicKeyCredentials(stringToArrayBuffer('foobar'), username);
    const publicKey = await importPublicKey(creds.publicKey);
    console.log(creds.publicKey);
    console.log(toBase64(creds.publicKey));
    await savePublicKey(publicKey);
    populateYourAccounts();
});

signButton?.addEventListener('click', async () => {
    const message = messageToSign.value;
    const challenge = stringToArrayBuffer(messageToSign.value);
    const signedData = await signChallenge(challenge);

    signatureBox.innerText = JSON.stringify(signedDataToJson(signedData));
});

verifyButton?.addEventListener('click', async () => {
    const spkiKey = fromBase64(publicKeyBox.value);
    const publicKey = await importPublicKey(spkiKey);
    
    const message = messageToVerify.value;
    const signedData = jsonToSignedData(JSON.parse(signatureToVerify.value));
    
    const verified = await verifySignature(publicKey, message, signedData);
    console.log(`Verified: ${verified}`);
});

function populateYourAccounts() {
    yourAccountsBox.innerHTML = '';
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i)!;
        const value = localStorage.getItem(key);
        const element = document.createElement('div');
        element.textContent = value;
        yourAccountsBox.appendChild(element);
    }
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
            id: Uint8Array.from(userId, c => c.charCodeAt(0)),
            name: userId,
            displayName: userId
        }
    };
    const creds = await navigator.credentials.create({
        publicKey: options
    }) as PublicKeyCredential;

    const response = creds.response as AuthenticatorAttestationResponse;
    return {
        rawId: creds.rawId,
        publicKey: response.getPublicKey()!,
        algorithm: response.getPublicKeyAlgorithm(),
    };
}

async function importPublicKey(spkiKey: ArrayBuffer): Promise<CryptoKey> {
    return await crypto.subtle.importKey('spki', spkiKey, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
}

async function savePublicKey(key: CryptoKey): Promise<void> {
    const spki = await crypto.subtle.exportKey('spki', key);
    localStorage.setItem('LOCAL_KEY', toBase64(spki));
}

async function loadPublicKey(): Promise<CryptoKey> {
    const spki = localStorage.getItem('LOCAL_KEY')!;
    return await crypto.subtle.importKey('spki', fromBase64(spki), {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
}

async function signChallenge(challenge: ArrayBuffer): Promise<SignedData> {
    const getOptions: PublicKeyCredentialRequestOptions = {
        challenge,
        allowCredentials: [],
        userVerification: 'required',
        timeout: 60000
    };

    const assertion = await navigator.credentials.get({
        publicKey: getOptions
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

function signedDataToJson(signedData: SignedData): SignedDataJson {
    return {
        authenticatorData: toBase64(signedData.authenticatorData),
        clientData: toBase64(signedData.clientData),
        signature: toBase64(signedData.signature),
    };
}

function jsonToSignedData(json: SignedDataJson): SignedData {
    return {
        authenticatorData: fromBase64(json.authenticatorData),
        clientData: fromBase64(json.clientData),
        signature: fromBase64(json.signature),
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

interface SignedDataJson {
    authenticatorData: string;
    clientData: string;
    signature: string;
}
