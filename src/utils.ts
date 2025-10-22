export function toBase64(input: ArrayBuffer): string {
    return btoa(String.fromCodePoint(...new Uint8Array(input)));
}

export function fromBase64(input: string): Uint8Array {
    return Uint8Array.from(atob(input), m => m.codePointAt(0)!);
}

export function stringToArrayBuffer(str: string): ArrayBuffer {
    const textEncoder = new TextEncoder();
    return textEncoder.encode(str);
}

export function arrayBufferToString(arr: ArrayBuffer): string {
    const textDecoder = new TextDecoder();
    return textDecoder.decode(arr);
}
