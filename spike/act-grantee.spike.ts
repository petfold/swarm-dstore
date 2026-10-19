// Throwaway spike: a second node, as a real ACT grantee, reads a snapshot
// behind a feed. Needs the publishing node at BEE_API_URL (with a usable
// postage batch) and a second node at BEE_READER_URL (an ultra-light node is
// enough). Follows S15 in swarmtyp's docs/spikes.md. Run:
//   BEE_READER_URL=http://127.0.0.1:1733 pnpm vitest run --config spike/vitest.config.ts spike/act-grantee.spike.ts
import { expect, it } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createBeeHttpTransport } from '../src/swarm-transport';
import { makeFeedTopic } from '../src/swarm-feeds';
import { bytesToHex, hexToBytes, concatBytes } from '../src/swarm-common';

const PUB = process.env.BEE_API_URL || 'http://localhost:1633';
const READER = process.env.BEE_READER_URL!;
const log = (...a: unknown[]) => console.log('[grantee]', ...a);
const t0 = Date.now();
const s = () => `${((Date.now() - t0) / 1000).toFixed(0)}s`;

const compressed = (uncompressed: `0x${string}`): string => {
  const b = hexToBytes(uncompressed.slice(2));
  const x = b.slice(1, 33);
  const y = b.slice(33, 65);
  return bytesToHex(concatBytes(new Uint8Array([y[31]! % 2 === 0 ? 2 : 3]), x));
};
const u64 = (n: number) => {
  const a = new Uint8Array(8);
  new DataView(a.buffer).setBigUint64(0, BigInt(n));
  return a;
};
const json = async <T>(r: Response) => (await r.json()) as T;

it('a second node reads an ACT snapshot behind a feed', async () => {
  const batch = (
    await json<{ stamps: { batchID: string; usable: boolean }[] }>(
      await fetch(`${PUB}/stamps`),
    )
  ).stamps.find((x) => x.usable)!.batchID;
  const publisher = (
    await json<{ publicKey: string }>(await fetch(`${PUB}/addresses`))
  ).publicKey;
  const reader = (
    await json<{ publicKey: string }>(await fetch(`${READER}/addresses`))
  ).publicKey;
  log(
    'publisher',
    publisher.slice(0, 12),
    'reader (2nd node)',
    reader.slice(0, 12),
  );

  const post = (path: string, body: string, headers: Record<string, string>) =>
    fetch(`${PUB}${path}`, {
      method: 'POST',
      body,
      headers: {
        'swarm-postage-batch-id': batch,
        'swarm-deferred-upload': 'false',
        ...headers,
      },
    });
  const grant = async (keys: string[]) =>
    json<{ ref: string; historyref: string }>(
      await post('/grantee', JSON.stringify({ grantees: keys }), {
        'content-type': 'application/json',
      }),
    );
  const upload = async (text: string, history: string) => {
    const r = await post('/bzz?name=dsheet', text, {
      'content-type': 'application/octet-stream',
      'swarm-collection': 'false',
      'swarm-act': 'true',
      'swarm-act-history-address': history,
    });
    return (await json<{ reference: string }>(r)).reference;
  };
  // Read through the second node, retrying while the network catches up.
  const readAsReader = async (ref: string, history: string, tries = 1) => {
    let last = { status: 0, text: '' };
    for (let i = 0; i < tries; i++) {
      const r = await fetch(`${READER}/bzz/${ref}/`, {
        headers: {
          'swarm-act-publisher': publisher,
          'swarm-act-history-address': history,
        },
      });
      last = { status: r.status, text: (await r.text()).slice(0, 80) };
      if (r.ok) return last;
      if (i < tries - 1) await new Promise((res) => setTimeout(res, 10_000));
    }
    return last;
  };

  // Control: can the second node fetch a chunk at all (so a refusal is ACT,
  // not content that has not reached it yet)?
  const readerHasChunk = async (address: string, tries = 12) => {
    for (let i = 0; i < tries; i++) {
      const r = await fetch(`${READER}/chunks/${address}`);
      if (r.ok) return true;
      await new Promise((res) => setTimeout(res, 10_000));
    }
    return false;
  };

  // 1. Grant the second node, upload v1, point a feed entry at it.
  const g = await grant([reader]);
  const v1 = await upload('sheet v1 for the reader', g.historyref);
  const transport = createBeeHttpTransport({
    beeUrl: PUB,
    postageBatchId: batch,
    ownerPrivateKey: generatePrivateKey(),
    deferredUpload: false,
  });
  const topic = makeFeedTopic(`spike/act-grantee/${Date.now()}`);
  const entry = (ref: string, hist: string) =>
    concatBytes(
      u64(Math.floor(Date.now() / 1000)),
      hexToBytes(ref),
      hexToBytes(hist),
    );
  await transport.writeFeedUpdate(topic, 0, entry(v1, g.historyref));
  const owner = await transport.feedOwner();
  log(
    s(),
    'published v1',
    v1.slice(0, 12),
    'history',
    g.historyref.slice(0, 12),
  );

  // 2. The second node finds the feed entry on the network.
  const readerTransport = createBeeHttpTransport({ beeUrl: READER });
  let payload: Uint8Array | null = null;
  for (let i = 0; i < 18 && !payload; i++) {
    payload = await readerTransport
      .readFeedUpdate(owner, topic, 0)
      .catch(() => null);
    if (!payload) await new Promise((res) => setTimeout(res, 10_000));
  }
  expect(payload).not.toBeNull();
  const ref = bytesToHex(payload!.slice(8, 40));
  const hist = bytesToHex(payload!.slice(40, 72));
  log(s(), 'reader found the feed entry; ref matches:', ref === v1);

  // 3. ...and opens the snapshot with its own key.
  const ok = await readAsReader(ref, hist, 18);
  log(s(), 'reader opens v1:', JSON.stringify(ok));
  expect(ok.text).toBe('sheet v1 for the reader');

  // 4. Content granted to someone else does not open for it.
  const stranger = compressed(
    privateKeyToAccount(generatePrivateKey()).publicKey,
  );
  const other = await grant([stranger]);
  const secret = await upload('not for the reader', other.historyref);
  log(
    s(),
    'control: reader fetches that history chunk:',
    await readerHasChunk(other.historyref),
  );
  const denied = await readAsReader(secret, other.historyref, 3);
  log(
    s(),
    'reader opens content granted to someone else:',
    JSON.stringify(denied),
  );
  expect(denied.status).not.toBe(200);

  // 5. Revoke the reader: v1 stays readable for it, v2 does not.
  await new Promise((res) => setTimeout(res, 1100));
  const rv = await fetch(`${PUB}/grantee/${g.ref}`, {
    method: 'PATCH',
    headers: {
      'swarm-postage-batch-id': batch,
      'swarm-deferred-upload': 'false',
      'content-type': 'application/json',
      'swarm-act-history-address': g.historyref,
    },
    body: JSON.stringify({ revoke: [reader] }),
  });
  const revoked = await json<{ historyref: string }>(rv);
  await new Promise((res) => setTimeout(res, 1100));
  const v2 = await upload('sheet v2 after revocation', revoked.historyref);
  await transport.writeFeedUpdate(topic, 1, entry(v2, revoked.historyref));
  log(
    s(),
    'control: reader fetches the new history chunk:',
    await readerHasChunk(revoked.historyref),
  );
  const afterV2 = await readAsReader(v2, revoked.historyref, 3);
  const stillV1 = await readAsReader(v1, g.historyref, 3);
  log(s(), 'after revocation, reader opens v2:', JSON.stringify(afterV2));
  log(s(), 'after revocation, reader opens v1:', JSON.stringify(stillV1));
  expect(afterV2.status).not.toBe(200);
  expect(stillV1.text).toBe('sheet v1 for the reader');
});
