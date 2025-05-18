export interface Storage {
    store(key: string, value: string): Promise<void>;
    load(key: string): Promise<string|null>;
    clear(): Promise<void>;
}

export class LocalStorage implements Storage {
    async store(key: string, value: string): Promise<void> {
        localStorage.setItem(key, value);
    }

    async load(key: string): Promise<string|null> {
        return localStorage.getItem(key);
    }

    async clear(): Promise<void> {
        localStorage.clear();
    }
}
