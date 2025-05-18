export interface KeyPair extends Signer, Verifier {
    getUserId(): string;
    getPublicKey(): ArrayBuffer;
    save(): Promise<void>;
}

export interface Signer {
    sign(message: ArrayBuffer): Promise<string>;
}

export interface Verifier {
    verify(message: ArrayBuffer, signature: string): Promise<boolean>;
}
