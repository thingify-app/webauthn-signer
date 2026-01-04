import { assertEquals } from 'jsr:@std/assert';
import { DenoStorage } from './deno_storage.ts';

let kv: Deno.Kv;

Deno.test.beforeEach(async () => {
    kv = await Deno.openKv();
});

Deno.test.afterEach(() => {
    kv.close();
});

Deno.test('DenoStorage login flow', async () => {
    const storage = new DenoStorage(kv);

    const nonce = new Uint8Array([1,2,3]).buffer;
    await storage.storeNonce(nonce, Date.now() + 1000);

    const nonceValid = await storage.verifyAndDeleteNonce(nonce);
    assertEquals(nonceValid, true);

    const nonceValidAgain = await storage.verifyAndDeleteNonce(nonce);
    assertEquals(nonceValidAgain, false);
});

Deno.test('DenoStorage expired nonce', async () => {
    const storage = new DenoStorage(kv);

    const nonce = new Uint8Array([4,5,6]).buffer;
    await storage.storeNonce(nonce, Date.now() - 1000);

    const nonceValid = await storage.verifyAndDeleteNonce(nonce);
    assertEquals(nonceValid, false);
});
