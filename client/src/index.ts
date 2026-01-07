import { createStateInitial, login as loginCrypto, toBase64 } from 'webauthn-signer';
import { Api } from './api';

export class Client {
    private api: Api;
    
    constructor(baseUrl: string) {
        this.api = new Api(baseUrl);
    }

    async createAccount(username: string) {
        const nonce = await this.api.createAccountInitial();
        console.log(`Received nonce for signup: ${toBase64(nonce)}`);

        const initialState = await createStateInitial(username, nonce);

        await this.api.createAccount(nonce, username, initialState.getKeyId(), initialState.getPublicKey());
        console.log('Account created successfully!');
    }

    async login(username: string) {
        const { nonce, keyId } = await this.api.loginInitial(username);
        console.log(`Received nonce for login: ${toBase64(nonce)}, keyId: ${toBase64(keyId)}`);

        const result = await loginCrypto(keyId, nonce);

        await this.api.login(nonce, username, result.authenticatorData, result.clientDataJSON, result.signature);
        console.log('Login successful!');
    }
}
