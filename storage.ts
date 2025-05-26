export interface Storage {
    store(key: string, value: string): Promise<void>;
    load(key: string): Promise<string|null>;
    keys(): Promise<string[]>;
    clear(): Promise<void>;
}

export class LocalStorage implements Storage {
    async store(key: string, value: string): Promise<void> {
        localStorage.setItem(key, value);
    }

    async keys(): Promise<string[]> {
        const length = localStorage.length;
        const keys = [];
        for (let i = 0; i < length; i++) {
            keys.push(localStorage.key(i) as string);
        }
        return keys;
    }

    async load(key: string): Promise<string|null> {
        return localStorage.getItem(key);
    }

    async clear(): Promise<void> {
        localStorage.clear();
    }
}
