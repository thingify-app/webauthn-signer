import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { zValidator } from '@hono/zod-validator'
import * as z from 'zod';
import { ClientError, Server } from 'webauthn-signer-server';
import { DenoStorage } from './deno_storage.ts';
import { fromBase64, toBase64 } from './utils.ts';

const kv = await Deno.openKv();

const storage = new DenoStorage(kv);
const server = new Server(storage);

const app = new Hono();

app.use('*', cors());

app.post('/createAccountInitial', async (c) => {
    const nonce = await server.createAccountInitial();
    return c.json({ nonce: toBase64(nonce) });
});

const createAccountRequest = z.object({
    nonce: z.base64(),
    username: z.string(),
    keyId: z.base64(),
    publicKey: z.base64(),
});

app.post('/createAccount', zValidator('json', createAccountRequest), async (c) => {
    const { nonce, username, keyId, publicKey } = c.req.valid('json');
    await server.createAccount(
        fromBase64(nonce),
        username,
        fromBase64(keyId),
        fromBase64(publicKey),
    );
    return c.json({ success: true });
});

const loginInitialRequest = z.object({
    username: z.string(),
});

app.post('/loginInitial', zValidator('json', loginInitialRequest), async (c) => {
    const { username } = c.req.valid('json');
    const result = await server.loginInitial(username);
    return c.json({ 
        nonce: toBase64(result.nonce),
        keyId: toBase64(result.keyId),
    });
});

const loginRequest = z.object({
    nonce: z.base64(),
    username: z.string(),
    authenticatorData: z.base64(),
    clientDataJSON: z.base64(),
    signature: z.base64(),
});

app.post('/login', zValidator('json', loginRequest), async (c) => {
    const { nonce, username, authenticatorData, clientDataJSON, signature } = c.req.valid('json');
    await server.login(
        fromBase64(nonce),
        username,
        fromBase64(authenticatorData),
        fromBase64(clientDataJSON),
        fromBase64(signature),
    );
    return c.json({ success: true });
});

app.onError((err, c) => {
    if (err instanceof ClientError) {
        return c.json({ error: err.message }, 400);
    }
    console.error(err);
    return c.json({ error: 'Internal Server Error' }, 500);
});

Deno.serve(app.fetch);
