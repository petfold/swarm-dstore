// Throwaway spike: can ACT-protected snapshots sit behind a public feed?
// Needs a Bee node at BEE_API_URL with a usable postage batch. Recorded as
// S15 in swarmtyp's docs/spikes.md. Run:
//   pnpm vitest run --config spike/vitest.config.ts spike/act-feeds.spike.ts
import { expect, it } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createBeeHttpTransport } from '../src/swarm-transport';
import { makeFeedTopic } from '../src/swarm-feeds';
import { bytesToHex, hexToBytes, concatBytes } from '../src/swarm-common';

const BEE = process.env.BEE_API_URL || 'http://localhost:1633';
const log = (...a: unknown[]) => console.log('[spike]', ...a);

const compressed = (uncompressed: `0x${string}`): string => {
  const b = hexToBytes(uncompressed.slice(2)); // 04 || X || Y
  const x = b.slice(1, 33),
    y = b.slice(33, 65);
  return bytesToHex(concatBytes(new Uint8Array([y[31]! % 2 === 0 ? 2 : 3]), x));
};
const u64 = (n: number) => {
  const a = new Uint8Array(8);
  new DataView(a.buffer).setBigUint64(0, BigInt(n));
  return a;
};

it('ACT snapshots behind a public feed', async () => {
  const stamps = (await (await fetch(`${BEE}/stamps`)).json()) as {
    stamps: { batchID: string; usable: boolean }[];
  };
  const batch = stamps.stamps.find((s) => s.usable)!.batchID;
  const addresses = (await (await fetch(`${BEE}/addresses`)).json()) as {
    publicKey: string;
  };
  const publisher = addresses.publicKey;
  log(
    'batch',
    batch.slice(0, 8),
    'publisher (node) key',
    publisher.slice(0, 12),
  );

  // 1. Access list with one reader (a key that is not this node's).
  const reader = compressed(
    privateKeyToAccount(generatePrivateKey()).publicKey,
  );
  const g = await fetch(`${BEE}/grantee`, {
    method: 'POST',
    headers: {
      'swarm-postage-batch-id': batch,
      'content-type': 'application/json',
      'swarm-deferred-upload': 'false',
    },
    body: JSON.stringify({ grantees: [reader] }),
  });
  const grantee = (await g.json()) as { ref: string; historyref: string };
  log('POST /grantee', g.status, JSON.stringify(grantee));
  expect(g.status).toBe(201);
  let history = grantee.historyref;

  // 2. Snapshot v1 uploaded with ACT, under that history.
  const upload = async (text: string, hist: string) => {
    const r = await fetch(`${BEE}/bzz?name=dsheet`, {
      method: 'POST',
      headers: {
        'swarm-postage-batch-id': batch,
        'content-type': 'application/octet-stream',
        'swarm-collection': 'false',
        'swarm-deferred-upload': 'false',
        'swarm-act': 'true',
        'swarm-act-history-address': hist,
      },
      body: new TextEncoder().encode(text),
    });
    const body = (await r.json()) as { reference: string };
    const h = r.headers.get('swarm-act-history-address')!;
    log(
      'upload',
      JSON.stringify(text),
      r.status,
      'encrypted ref',
      body.reference.slice(0, 12),
      'history',
      h.slice(0, 12),
      h === hist ? '(unchanged)' : '(NEW)',
    );
    return { ref: body.reference, history: h };
  };
  const v1 = await upload('sheet v1', history);

  // 3. Feed entry: timestamp || encrypted ref || history address (72 bytes).
  const ownerKey = generatePrivateKey();
  const transport = createBeeHttpTransport({
    beeUrl: BEE,
    postageBatchId: batch,
    ownerPrivateKey: ownerKey,
    deferredUpload: false,
  });
  const topic = makeFeedTopic(`spike/act/${Date.now()}`);
  const entry = (t: number, ref: string, hist: string) =>
    concatBytes(u64(t), hexToBytes(ref), hexToBytes(hist));
  const t1 = Math.floor(Date.now() / 1000);
  await transport.writeFeedUpdate(topic, 0, entry(t1, v1.ref, v1.history));
  const owner = await transport.feedOwner();

  // 4. Read back through the feed, decrypting with ACT headers.
  const read = async (index: number) => {
    const p = (await transport.readFeedUpdate(owner, topic, index))!;
    return {
      t: Number(new DataView(p.buffer, p.byteOffset, 8).getBigUint64(0)),
      ref: bytesToHex(p.slice(8, 40)),
      hist: bytesToHex(p.slice(40, 72)),
    };
  };
  const get = async (ref: string, hist?: string, ts?: number) => {
    const headers: Record<string, string> = {};
    if (hist)
      Object.assign(headers, {
        'swarm-act-publisher': publisher,
        'swarm-act-history-address': hist,
      });
    if (ts) headers['swarm-act-timestamp'] = String(ts);
    const r = await fetch(`${BEE}/bzz/${ref}/`, { headers });
    return {
      status: r.status,
      text: r.ok ? await r.text() : (await r.text()).slice(0, 80),
    };
  };
  const e0 = await read(0);
  const withAct = await get(e0.ref, e0.hist);
  log(
    'read v1 via feed + ACT headers:',
    withAct.status,
    JSON.stringify(withAct.text),
  );
  expect(withAct.text).toBe('sheet v1');

  // 5. Without ACT headers the encrypted reference opens nothing.
  const noAct = await get(e0.ref);
  log('read v1 without ACT headers:', noAct.status, JSON.stringify(noAct.text));
  expect(noAct.status).not.toBe(200);

  // 6. Revoke the reader: Bee re-keys and returns a new history.
  await new Promise((r) => setTimeout(r, 1100)); // history entries are keyed by second
  const rv = await fetch(`${BEE}/grantee/${grantee.ref}`, {
    method: 'PATCH',
    headers: {
      'swarm-postage-batch-id': batch,
      'content-type': 'application/json',
      'swarm-act-history-address': history,
      'swarm-deferred-upload': 'false',
    },
    body: JSON.stringify({ revoke: [reader] }),
  });
  const revoked = (await rv.json()) as { ref: string; historyref: string };
  log(
    'PATCH /grantee revoke',
    rv.status,
    'new history',
    revoked.historyref?.slice(0, 12),
    revoked.historyref === history ? '(same)' : '(NEW)',
  );
  expect(rv.status).toBe(200);
  history = revoked.historyref;
  await new Promise((r) => setTimeout(r, 1100));
  const v2 = await upload('sheet v2', history);
  await transport.writeFeedUpdate(
    topic,
    1,
    entry(Math.floor(Date.now() / 1000), v2.ref, v2.history),
  );

  // 7. Which history opens which version?
  const e1 = await read(1);
  log(
    'read v2 with its own history:',
    JSON.stringify(await get(e1.ref, e1.hist)),
  );
  log('read v2 with v1 history:', JSON.stringify(await get(e1.ref, e0.hist)));
  log(
    'read v1 with v2 history (now):',
    JSON.stringify(await get(e0.ref, e1.hist)),
  );
  log(
    'read v1 with v2 history at v1 time:',
    JSON.stringify(await get(e0.ref, e1.hist, e0.t)),
  );
  log(
    'read v1 with its own history:',
    JSON.stringify(await get(e0.ref, e0.hist)),
  );
  const latest = await transport.latestFeedIndex(owner, topic);
  log('feed latest index', JSON.stringify(latest));
});
