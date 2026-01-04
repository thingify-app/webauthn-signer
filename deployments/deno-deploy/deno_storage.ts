import { Account, Storage } from 'webauthn-signer-server';
import { toBase64 } from './utils.ts';

export class DenoStorage implements Storage {
    private kv: Deno.Kv;

    constructor(kv: Deno.Kv) {
        this.kv = kv;
    }
  
    async storeAccount(account: Account): Promise<void> {
        const storedAccount: StoredAccount = {
            username: account.username,
            keyId: account.keyId,
            publicKey: account.publicKey,
        };
        await this.kv.set(['account', account.username], storedAccount);
    }

    async getAccount(username: string): Promise<Account | null> {
        const res = await this.kv.get<StoredAccount>(['account', username]);
        return res.value;
    }

    async storeNonce(nonce: ArrayBuffer, expiresAt: number): Promise<void> {
        const storedNonce: StoredNonce = {
            value: nonce,
            expiresAt,
        };
        await this.kv.set(['nonce', toBase64(nonce)], storedNonce, { expireIn: expiresAt - Date.now() });
    }

    async verifyAndDeleteNonce(nonce: ArrayBuffer): Promise<boolean> {
        const b64Nonce = toBase64(nonce);
        const res = await this.kv.get<StoredNonce>(['nonce', b64Nonce]);
        if (res.value && res.value.expiresAt > Date.now()) {
            await this.kv.delete(['nonce', b64Nonce]);
            return true;
        }
        return false;
    }
}

interface StoredAccount { 
    username: string;  
    keyId: ArrayBuffer;
    publicKey: ArrayBuffer;
}

interface StoredNonce {
    value: ArrayBuffer;
    expiresAt: number;
}
