export interface Storage {
    store(key: string, value: string): Promise<void>;
    load(key: string): Promise<string|null>;
    keys(): Promise<string[]>;
    clear(): Promise<void>;
}

export class LocalStorage implements Storage {
    constructor(private namespace: string) {
        if (namespace.includes('-')) {
            throw new Error('Namespace must not contain "-" characters');
        }
    }

    async store(key: string, value: string): Promise<void> {
        localStorage.setItem(`${this.namespace}-${key}`, value);
    }

    async loadAll(): Promise<{key: string, value: string}[]> {
        const keys = await this.keys();
        const results = [];
        for (let key of keys) {
            results.push({key, value: await this.load(key) as string});
        }

        return results;
    }

    async keys(): Promise<string[]> {
        const length = localStorage.length;
        const keys = [];
        for (let i = 0; i < length; i++) {
            const key = localStorage.key(i);
            if (key?.startsWith(`${this.namespace}-`)) {
                keys.push(key.slice(this.namespace.length + 1));
            }
        }
        return keys;
    }

    async load(key: string): Promise<string|null> {
        return localStorage.getItem(`${this.namespace}-${key}`);
    }

    async clear(): Promise<void> {
        const keys = await this.keys();
        for (let key of keys) {
            localStorage.removeItem(key);
        }
    }
}
