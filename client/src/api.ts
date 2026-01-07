import { fromBase64, toBase64 } from 'webauthn-signer';

export class Api {
    constructor(private baseUrl: string) {}

    async createAccountInitial(): Promise<ArrayBuffer> {
        const response = await fetch(`${this.baseUrl}/createAccountInitial`, {
            method: 'POST',
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const json = await response.json();
        const nonce = fromBase64(json.nonce);
        return nonce;
    }

    async createAccount(nonce: ArrayBuffer, username: string, keyId: ArrayBuffer, publicKey: ArrayBuffer): Promise<void> {
        const response = await fetch(`${this.baseUrl}/createAccount`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                nonce: toBase64(nonce),
                username,
                keyId: toBase64(keyId),
                publicKey: toBase64(publicKey),
            }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server returned ${response.status}: ${errorText}`);
        }
    }

    async loginInitial(username: string) {
        const response = await fetch(`${this.baseUrl}/loginInitial`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server returned ${response.status}: ${errorText}`);
        }

        const responseData = await response.json();
        return {
            nonce: fromBase64(responseData.nonce),
            keyId: fromBase64(responseData.keyId),
        };
    }

    async login(nonce: ArrayBuffer, username: string, authenticatorData: ArrayBuffer, clientDataJSON: ArrayBuffer, signature: ArrayBuffer) {
        const response = await fetch(`${this.baseUrl}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                nonce: toBase64(nonce),
                username,
                authenticatorData: toBase64(authenticatorData),
                clientDataJSON: toBase64(clientDataJSON),
                signature: toBase64(signature),
            }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server returned ${response.status}: ${errorText}`);
        }
    }
}
