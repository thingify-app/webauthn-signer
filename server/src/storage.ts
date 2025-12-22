import { toBase64 } from "./utils";

export interface Storage {
    storeAccount(account: Account): Promise<void>;
    getAccount(username: string): Promise<Account | null>;
    storeNonce(nonce: ArrayBuffer, expiresAt: number): Promise<void>;
    verifyAndDeleteNonce(nonce: ArrayBuffer): Promise<boolean>;
}

export class InMemoryStorage implements Storage {
    private accounts: Map<string, Account> = new Map();
    private nonces: Map<string, number> = new Map();

    async storeAccount(account: Account): Promise<void> {
        this.accounts.set(account.username, account);
    }

    async getAccount(username: string): Promise<Account | null> {
        return this.accounts.get(username) || null;
    }

    async storeNonce(nonce: ArrayBuffer, expiresAt: number): Promise<void> {
        this.nonces.set(toBase64(nonce), expiresAt);
    }
    
    async verifyAndDeleteNonce(nonce: ArrayBuffer): Promise<boolean> {
        const key = toBase64(nonce);
        const expiresAt = this.nonces.get(key);
        if (expiresAt && expiresAt > Date.now()) {
            this.nonces.delete(key);
            return true;
        }
        return false;
    }
}

export interface Account {
    username: string;
    keyId: ArrayBuffer;
    publicKey: ArrayBuffer;
}
