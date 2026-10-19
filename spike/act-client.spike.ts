// Spike: ACT in the client, both ways, against Bee at BEE_API_URL (with a
// usable postage batch). Reading: Bee grants a key that only this test
// holds, and the test opens the encrypted reference itself with
// openActReference. Writing: the test publishes an ACT under its own key,
// granting the node's key, and Bee opens it with its ACT headers. Run:
//   pnpm vitest run --config spike/vitest.config.ts spike/act-client.spike.ts
import { expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  ActAccessDeniedError,
  beeByteLoader,
  beeByteUploader,
  encryptActReference,
  grantActAccess,
  openActReference,
} from '../src/swarm-act';
import { bytesToHex } from '../src/swarm-common';

const BEE = process.env.BEE_API_URL || 'http://localhost:1633';
const log = (...a: unknown[]) => console.log('[act-client]', ...a);
const json = async <T>(r: Response) => {
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return (await r.json()) as T;
};

it('a client opens what Bee granted to its key, and nothing else', async () => {
  const batch = (
    await json<{ stamps: { batchID: string; usable: boolean }[] }>(
      await fetch(`${BEE}/stamps`),
    )
  ).stamps.find((x) => x.usable)!.batchID;
  const publisher = (
    await json<{ publicKey: string }>(await fetch(`${BEE}/addresses`))
  ).publicKey;

  // The reader's key lives only in this process; never printed.
  const readerKey = secp256k1.utils.randomSecretKey();
  const readerPublic = bytesToHex(secp256k1.getPublicKey(readerKey, true));
  const strangerKey = secp256k1.utils.randomSecretKey();

  const post = (path: string, body: string, headers: Record<string, string>) =>
    fetch(`${BEE}${path}`, {
      method: 'POST',
      body,
      headers: {
        'swarm-postage-batch-id': batch,
        'swarm-deferred-upload': 'false',
        ...headers,
      },
    });

  const granted = await json<{ ref: string; historyref: string }>(
    await post('/grantee', JSON.stringify({ grantees: [readerPublic] }), {
      'content-type': 'application/json',
    }),
  );
  log('granted; history', granted.historyref.slice(0, 12));

  const text = `client-side ACT ${new Date().toISOString()}`;
  const uploaded = await post('/bzz?name=note.txt', text, {
    'content-type': 'text/plain',
    'swarm-collection': 'false',
    'swarm-act': 'true',
    'swarm-act-history-address': granted.historyref,
  });
  const encryptedReference = (await json<{ reference: string }>(uploaded))
    .reference;
  const historyAddress =
    uploaded.headers.get('swarm-act-history-address') ?? granted.historyref;
  log('uploaded; encrypted ref', encryptedReference.slice(0, 12));

  // Without ACT, the encrypted reference leads nowhere.
  const blind = await fetch(`${BEE}/bzz/${encryptedReference}/`);
  log('plain read of the encrypted ref:', blind.status);
  expect(blind.ok).toBe(false);

  const load = beeByteLoader({ beeUrl: BEE });
  const started = Date.now();
  const plain = await openActReference({
    load,
    historyAddress,
    publisherPublicKey: publisher,
    privateKey: readerKey,
    encryptedReference,
  });
  log('opened client-side in', Date.now() - started, 'ms');

  const read = await fetch(`${BEE}/bzz/${plain}/`);
  expect(read.status).toBe(200);
  expect(await read.text()).toBe(text);
  log('read the plain reference with no ACT headers: ok');

  // Bee's own ACT download (as the publisher) agrees.
  const viaNode = await fetch(`${BEE}/bzz/${encryptedReference}/`, {
    headers: {
      'swarm-act': 'true',
      'swarm-act-publisher': publisher,
      'swarm-act-history-address': historyAddress,
    },
  });
  expect(await viaNode.text()).toBe(text);

  await expect(
    openActReference({
      load,
      historyAddress,
      publisherPublicKey: publisher,
      privateKey: strangerKey,
      encryptedReference,
    }),
  ).rejects.toBeInstanceOf(ActAccessDeniedError);
  log('a key that was not granted: refused');

  // Revoke the reader: a later upload under the new history is closed to
  // it, while what it could read before stays open at the earlier time.
  const beforeRevocation = Math.floor(Date.now() / 1000);
  await new Promise((r) => setTimeout(r, 1100));
  const revoked = await fetch(`${BEE}/grantee/${granted.ref}`, {
    method: 'PATCH',
    body: JSON.stringify({ revoke: [readerPublic] }),
    headers: {
      'content-type': 'application/json',
      'swarm-postage-batch-id': batch,
      'swarm-act-history-address': historyAddress,
      'swarm-deferred-upload': 'false',
    },
  });
  const after = await json<{ ref: string; historyref: string }>(revoked);
  const second = await post('/bzz?name=note.txt', `${text} (after)`, {
    'content-type': 'text/plain',
    'swarm-collection': 'false',
    'swarm-act': 'true',
    'swarm-act-history-address': after.historyref,
  });
  const secondReference = (await json<{ reference: string }>(second)).reference;
  const secondHistory =
    second.headers.get('swarm-act-history-address') ?? after.historyref;
  await expect(
    openActReference({
      load,
      historyAddress: secondHistory,
      publisherPublicKey: publisher,
      privateKey: readerKey,
      encryptedReference: secondReference,
    }),
  ).rejects.toBeInstanceOf(ActAccessDeniedError);
  log('after revocation: the new upload is refused');
  expect(
    await openActReference({
      load,
      historyAddress: secondHistory,
      publisherPublicKey: publisher,
      privateKey: readerKey,
      encryptedReference,
      timestamp: beforeRevocation,
    }),
  ).toBe(plain);
  log('after revocation: the first upload still opens at its time');
});

it('Bee opens what the client granted to the node, under the client key', async () => {
  const batch = (
    await json<{ stamps: { batchID: string; usable: boolean }[] }>(
      await fetch(`${BEE}/stamps`),
    )
  ).stamps.find((x) => x.usable)!.batchID;
  const node = (
    await json<{ publicKey: string }>(await fetch(`${BEE}/addresses`))
  ).publicKey;

  // The publisher is a key only this test holds; never printed.
  const publisherPrivateKey = secp256k1.utils.randomSecretKey();
  const publisher = bytesToHex(
    secp256k1.getPublicKey(publisherPrivateKey, true),
  );
  const load = beeByteLoader({ beeUrl: BEE });
  const upload = beeByteUploader({
    beeUrl: BEE,
    postageBatchId: batch,
    deferredUpload: false,
  });
  const uploadPlain = async (text: string) =>
    (
      await json<{ reference: string }>(
        await fetch(`${BEE}/bzz?name=note.txt`, {
          method: 'POST',
          body: text,
          headers: {
            'content-type': 'text/plain',
            'swarm-collection': 'false',
            'swarm-postage-batch-id': batch,
            'swarm-deferred-upload': 'false',
          },
        }),
      )
    ).reference;
  const readAsNode = (
    encryptedReference: string,
    historyAddress: string,
    timestamp?: number,
  ) =>
    fetch(`${BEE}/bzz/${encryptedReference}/`, {
      headers: {
        'swarm-act': 'true',
        'swarm-act-publisher': publisher,
        'swarm-act-history-address': historyAddress,
        ...(timestamp ? { 'swarm-act-timestamp': String(timestamp) } : {}),
      },
    });

  const text = `granted client-side ${new Date().toISOString()}`;
  const plain = await uploadPlain(text);
  const granted = await grantActAccess({
    load,
    upload,
    publisherPrivateKey,
    grantees: [node],
  });
  const grantedAt = Math.floor(Date.now() / 1000);
  const encrypted = await encryptActReference({
    load,
    historyAddress: granted.historyAddress,
    publisherPrivateKey,
    reference: plain,
  });
  log('client granted the node; history', granted.historyAddress.slice(0, 12));

  const read = await readAsNode(encrypted, granted.historyAddress);
  log('Bee read with its ACT headers:', read.status);
  expect(read.status).toBe(200);
  expect(await read.text()).toBe(text);

  // Revoke the node by re-keying for nobody; Bee is refused the next
  // version but still opens the first at its time.
  await new Promise((r) => setTimeout(r, 1100));
  const revoked = await grantActAccess({
    load,
    upload,
    publisherPrivateKey,
    grantees: [],
    historyAddress: granted.historyAddress,
    rekey: true,
  });
  const second = await encryptActReference({
    load,
    historyAddress: revoked.historyAddress,
    publisherPrivateKey,
    reference: await uploadPlain(`${text} (after)`),
  });
  const refused = await readAsNode(second, revoked.historyAddress);
  log('Bee after revocation, new version:', refused.status);
  expect(refused.ok).toBe(false);
  const old = await readAsNode(encrypted, revoked.historyAddress, grantedAt);
  log('Bee after revocation, first version at its time:', old.status);
  expect(await old.text()).toBe(text);
});
