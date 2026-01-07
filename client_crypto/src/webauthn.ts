import { KeyPair, Signer, Verifier } from './keypair';
import { Storage } from './storage';
import { arrayBufferToString, fromBase64, stringToArrayBuffer, toBase64 } from './utils';

export async function createKeyPair(storage: Storage, userId: string): Promise<KeyPair> {
    const challenge = new Uint8Array(64);
    crypto.getRandomValues(challenge);

    const options: PublicKeyCredentialCreationOptions = {
        challenge,
        pubKeyCredParams: [{
            type: 'public-key',
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
    console.log(JSON.parse(arrayBufferToString(response.clientDataJSON)));
    // TODO: verify challenge and signature in here.

    const publicKey = response.getPublicKey();
    if (publicKey === null) {
        throw new Error('No public key returned!');
    }

    const signer = new WebAuthnSigner(creds.rawId);
    const verifier = new WebAuthnVerifier(await importPublicKey(publicKey));
    const storer = new WebAuthnStorer(storage, userId, creds.rawId, publicKey);

    return {
        getKeyId: () => creds.rawId,
        sign: (message) => signer.sign(message),
        verify: (message, signature) => verifier.verify(message, signature),
        save: () => storer.save(),
        getUserId: () => userId,
        getPublicKey: () => publicKey
    };
}

export async function createKeyPairNoStorage(userId: string, nonce: ArrayBuffer): Promise<WebAuthnKeyPair> {
    const options: PublicKeyCredentialCreationOptions = {
        challenge: nonce,
        pubKeyCredParams: [{
            type: 'public-key',
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
    console.log(JSON.parse(arrayBufferToString(response.clientDataJSON)));
    // TODO: verify challenge and signature in here.

    const publicKey = response.getPublicKey();
    if (publicKey === null) {
        throw new Error('No public key returned!');
    }

    const signer = new WebAuthnSigner(creds.rawId);
    const verifier = new WebAuthnVerifier(await importPublicKey(publicKey));

    return {
        getKeyId: () => creds.rawId,
        sign: (message) => signer.sign(message),
        verify: (message, signature) => verifier.verify(message, signature),
        save: () => {
            throw new Error('Saving not supported for no-storage KeyPair');
        },
        getUserId: () => userId,
        getPublicKey: () => publicKey,
        authenticatorData: response.getAuthenticatorData(),
        clientDataJSON: response.clientDataJSON
    };
}

export interface WebAuthnKeyPair extends KeyPair {
    authenticatorData: ArrayBuffer;
    clientDataJSON: ArrayBuffer;
}

export async function importKeyPairs(storage: Storage, keyPairs: {userId: string, rawId: ArrayBuffer, spkiPublicKey: ArrayBuffer}[]): Promise<void> {
    storage.clear();
    for (const keyPair of keyPairs) {
        const storer = new WebAuthnStorer(storage, keyPair.userId, keyPair.rawId, keyPair.spkiPublicKey);
        await storer.save();
    }
}

export async function loadKeyPairs(storage: Storage): Promise<KeyPair[]> {
    const keys = await storage.keys();
    return Promise.all(keys.map(async userId => await loadKeyPair(storage, userId) as KeyPair));
}

export async function loadKeyPair(storage: Storage, userId: string): Promise<KeyPair|null> {
    const data = await storage.load(userId);
    if (data) {
        const parsed = JSON.parse(data);
        const userId = parsed.userId;
        const rawId = fromBase64(parsed.rawId);
        const spki = fromBase64(parsed.spki);

        const publicKey = await importPublicKey(spki);

        const signer = new WebAuthnSigner(rawId);
        const verifier = new WebAuthnVerifier(publicKey);
        const storer = new WebAuthnStorer(storage, userId, rawId, spki);

        return {
            getKeyId: () => rawId,
            sign: (message) => signer.sign(message),
            verify: (message, signature) => verifier.verify(message, signature),
            save: () => storer.save(),
            getUserId: () => userId,
            getPublicKey: () => spki
        };
    } else {
        return null;
    }
}

export async function performLoginChallenge(keyId: ArrayBuffer, challenge: ArrayBuffer): Promise<LoginChallengeResult> {
    const getOptions: PublicKeyCredentialRequestOptions = {
        challenge,
        allowCredentials: [
            {
                type: 'public-key',
                id: keyId
            }
        ],
        userVerification: 'required',
    };
    
    const assertion = await navigator.credentials.get({
        publicKey: getOptions,
    }) as PublicKeyCredential;

    const response = assertion.response as AuthenticatorAssertionResponse;
    const signature = convertEcdsaAsn1Signature(response.signature);

    return {
        authenticatorData: response.authenticatorData,
        clientDataJSON: response.clientDataJSON,
        signature: signature
    };
}

export interface LoginChallengeResult {
    authenticatorData: ArrayBuffer;
    clientDataJSON: ArrayBuffer;
    signature: ArrayBuffer;
}

export async function loadKeyPairNoStorage(keyId: string, publicKeySpki: string, challenge: ArrayBuffer): Promise<[KeyPair, string]> {
    const rawKeyId = fromBase64(keyId);
    const rawSpki = fromBase64(publicKeySpki);
    
    const publicKey = await importPublicKey(rawSpki);
    const verifier = new WebAuthnVerifier(publicKey);
    const signer = new WebAuthnSigner(rawKeyId);

    // Try signing a payload with the actual key, then verify it with the given
    // public key.
    const signature = await signer.sign(challenge);
    const verified = await verifier.verify(challenge, signature);
    if (!verified) {
        throw new Error('Could not verify signature with given public key!');
    }

    return [{
        getKeyId: () => rawKeyId,
        sign: async (message) => signer.sign(message),
        verify: (message, signature) => verifier.verify(message, signature),
        save: async () => {
            throw new Error('Saving not supported for no-storage KeyPair');
        },
        getUserId: () => keyId,
        getPublicKey: () => rawSpki
    }, signature];
}

export async function loadLocalKeyId(challenge: ArrayBuffer): Promise<string> {
    const getOptions: PublicKeyCredentialRequestOptions = {
        challenge,
        userVerification: 'required',
    };

    const assertion = await navigator.credentials.get({
        publicKey: getOptions,
    }) as PublicKeyCredential;

    return toBase64(assertion.rawId);
}

export class WebAuthnStorer {
    constructor(private storage: Storage, private userId: string, private rawId: ArrayBuffer, private spki: ArrayBuffer) {}

    async save(): Promise<void> {
        await this.storage.store(this.userId, JSON.stringify({
            userId: this.userId,
            rawId: toBase64(this.rawId),
            spki: toBase64(this.spki),
        }));
    }
}

export class WebAuthnSigner implements Signer {
    constructor(private rawId: ArrayBuffer) {}

    async sign(message: ArrayBuffer): Promise<string> {
        const getOptions: PublicKeyCredentialRequestOptions = {
            challenge: message,
            allowCredentials: [
                {
                    type: 'public-key',
                    id: this.rawId
                }
            ],
            userVerification: 'required',
        };
    
        const assertion = await navigator.credentials.get({
            publicKey: getOptions,
        }) as PublicKeyCredential;

        const response = assertion.response as AuthenticatorAssertionResponse;
        const signature = convertEcdsaAsn1Signature(response.signature);

        // TODO: verify that the signature is correct, and as expected for the
        // stored public key.
    
        return signedDataToCompact({
            authenticatorData: response.authenticatorData,
            clientData: response.clientDataJSON,
            signature: signature
        });
    }
}

export async function createVerifier(publicKeyBuffer: ArrayBuffer): Promise<Verifier> {
    const publicKey = await importPublicKey(publicKeyBuffer);
    return new WebAuthnVerifier(publicKey);
}

export class WebAuthnVerifier implements Verifier {
    constructor(private publicKey: CryptoKey) {}

    async verify(message: ArrayBuffer, signature: string): Promise<boolean> {
        const signedData = compactToSignedData(signature);

        // First, validate that the client data JSON contains the given message.
        const clientDataParsed = JSON.parse(arrayBufferToString(signedData.clientData));
        console.log(clientDataParsed);
        console.log(fromBase64(clientDataParsed.challenge));

        const messageMatches = arrayBuffersEqual(fromBase64(clientDataParsed.challenge), message);
        if (!messageMatches) {
            console.error('Message does not match challenge.');
            return false;
        }

        const hashedClientData = await crypto.subtle.digest({name: 'SHA-256'}, signedData.clientData);
        const data = mergeBuffer(signedData.authenticatorData, hashedClientData);

        return await crypto.subtle.verify({
            name: 'ECDSA',
            hash: 'SHA-256'
        }, this.publicKey, signedData.signature, data);
    }
}

async function importPublicKey(spkiKey: ArrayBuffer): Promise<CryptoKey> {
    return await crypto.subtle.importKey('spki', spkiKey, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
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

function mergeBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer): ArrayBuffer {
    const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
}

function mergeBufferUint8(buffer1: Uint8Array, buffer2: Uint8Array): Uint8Array {
    const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(buffer1, 0);
    tmp.set(buffer2, buffer1.byteLength);
    return tmp;
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

function convertEcdsaAsn1Signature(input: ArrayBuffer): ArrayBuffer {
    const elements = readAsn1IntegerSequence(new Uint8Array(input));
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
      r = mergeBufferUint8(new Uint8Array([0]), r);
    }
    if ((s.byteLength % 16) == 15) {
      s = mergeBufferUint8(new Uint8Array([0]), s);
    }

    // If R and S length is not still multiple of 128bit,
    // then error
    if (r.byteLength % 16 != 0) throw Error('unknown ECDSA sig r length error');
    if (s.byteLength % 16 != 0) throw Error('unknown ECDSA sig s length error');

    return mergeBufferUint8(r, s).buffer;
}

function arrayBuffersEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
    const aBytes = new Uint8Array(a);
    const bBytes = new Uint8Array(b);

    if (aBytes.length !== bBytes.length) {
        return false;
    }

    for (let i = 0; i < a.byteLength; i++) {
        if (aBytes[i] !== bBytes[i]) {
            return false;
        }
    }

    return true;
}

interface SignedData {
    authenticatorData: ArrayBuffer;
    clientData: ArrayBuffer;
    signature: ArrayBuffer;
}
