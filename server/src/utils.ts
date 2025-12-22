export function toBase64(input: ArrayBuffer): string {
    return btoa(String.fromCodePoint(...new Uint8Array(input)));
}

export function fromBase64(input: string): ArrayBuffer {
    // Replace urlsafe base64 characters if needed:
    input = input.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(input), m => m.codePointAt(0)!).buffer;
}

export function stringToArrayBuffer(str: string): ArrayBuffer {
    const textEncoder = new TextEncoder();
    return textEncoder.encode(str).buffer;
}

export function arrayBufferToString(arr: ArrayBuffer): string {
    const textDecoder = new TextDecoder();
    return textDecoder.decode(arr);
}

export function arrayBuffersEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
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

export function mergeBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer): ArrayBuffer {
    const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
}
