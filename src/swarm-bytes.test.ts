// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  encryptActReference,
  grantActAccess,
  openActReference,
} from './swarm-act';
import {
  providerByteLoader,
  providerByteUploader,
  readChunkTree,
  writeChunkTree,
  type StoredChunk,
} from './swarm-bytes';
import { bytesToHex, hexToBytes, toBase64 } from './swarm-common';
import { chunkAddress } from './swarm-feeds';
import type { SwarmProvider } from './swarm-transport';

const pattern = (n: number) =>
  new Uint8Array(n).map((_, i) => (i * 31 + 7) & 255);

/** Chunks by reference, addressed as Swarm addresses them. */
const memoryChunks = () => {
  const chunks = new Map<string, StoredChunk>();
  return {
    chunks,
    put: async (chunk: StoredChunk) => {
      const ref = bytesToHex(chunkAddress(chunk.payload, chunk.span));
      chunks.set(ref, chunk);
      return ref;
    },
    get: async (ref: string) => {
      const chunk = chunks.get(ref);
      if (!chunk) throw new Error(`missing ${ref}`);
      return chunk;
    },
  };
};

// Roots from cafe-utility's MerkleTree (what bee-js uses) for the same data.
const ROOTS: [number, string][] = [
  [1, 'b073f3782b5a9db35d5642aacb734064fc421fd277a882b6fd177c744d0ad10d'],
  [100, 'b1a8cbc4f0b2a6a4cbbf2ef757a5b554780b5f863d4566308e1bb33e5059d611'],
  [4096, 'ee1ccdcda5351ae064dcaf614b583e2e7a8a42ca4df5f5f5eb3b7559ac24b0ec'],
  [4097, 'bd3357b006abe623abfef563dd07f5cd9d496e301f404ad3d7767e20abc24ef6'],
  // 128 leaves: one full intermediate chunk.
  [524288, 'e3a273803ee6200d328d15f8a838eb5cc9124e4bb15114b517ae0a7b406cbcdf'],
  // 129 leaves: the last moves up a level unwrapped.
  [524289, 'd02da6e441f6fc652c6724357fe23faff6c454a6dae152f3c7c88d894be98fe1'],
  // 259 leaves: two full intermediates and a partial one.
  [1060864, 'e27f994a1f8c4605e71ca9fc22ae76cb26ad1c6696bdf63b8f3df2197bab7706'],
];

describe('chunk trees', () => {
  it.each(ROOTS)(
    'split %i bytes as Bee does',
    async (size, root) => {
      const store = memoryChunks();
      const data = pattern(size);
      expect(await writeChunkTree(data, store.put)).toBe(root);
      expect(await readChunkTree(root, store.get)).toEqual(data);
    },
    60_000,
  ); // hashing a megabyte in JS takes seconds

  it('refuses a chunk stored under another reference', async () => {
    await expect(
      writeChunkTree(pattern(10), async () => '00'.repeat(32)),
    ).rejects.toThrow(/unexpected reference/);
  });

  it('refuses a tree shorter than its span', async () => {
    const store = memoryChunks();
    const root = await writeChunkTree(pattern(9000), store.put);
    const { payload } = store.chunks.get(root)!;
    // The root with its last child dropped.
    const truncated = await store.put({
      payload: payload.slice(0, payload.length - 32),
      span: 9000,
    });
    await expect(readChunkTree(truncated, store.get)).rejects.toThrow(/span/);
  });
});

/** A window.swarm provider that offers only its chunk methods. */
const chunkOnlyProvider = () => {
  const store = memoryChunks();
  const calls: string[] = [];
  const provider: SwarmProvider = {
    async request({ method, params }) {
      calls.push(method);
      const p = params as {
        reference?: string;
        data?: Uint8Array;
        span?: number;
      };
      if (method === 'swarm_publishChunk') {
        if (!p.data?.length || p.data.length > 4096) throw new Error('size');
        return {
          reference: await store.put({ payload: p.data, span: p.span! }),
        };
      }
      if (method === 'swarm_readChunk') {
        const { payload, span } = await store.get(p.reference!);
        return { data: toBase64(payload), encoding: 'base64', span };
      }
      throw new Error(`unexpected ${method}`);
    },
  };
  return { provider, calls };
};

describe('over a window.swarm provider', () => {
  it('stores and reads bytes as chunks', async () => {
    const { provider, calls } = chunkOnlyProvider();
    const data = pattern(9000);
    const ref = await providerByteUploader(provider)(data);
    expect(ref).toBe(
      await writeChunkTree(data, memoryChunks().put), // same reference
    );
    expect(calls.filter((c) => c === 'swarm_publishChunk')).toHaveLength(4);
    expect(await providerByteLoader(provider)(ref)).toEqual(data);
  });

  it('carries ACT end to end, with a table larger than a chunk', async () => {
    const { provider } = chunkOnlyProvider();
    const load = providerByteLoader(provider);
    const upload = providerByteUploader(provider);
    const publisherPrivateKey = secp256k1.utils.randomSecretKey();
    const readers = Array.from({ length: 40 }, () =>
      secp256k1.utils.randomSecretKey(),
    );
    const { historyAddress, actReference } = await grantActAccess({
      load,
      upload,
      publisherPrivateKey,
      grantees: readers.map((k) => secp256k1.getPublicKey(k, true)),
    });
    expect((await load(actReference)).length).toBeGreaterThan(4096);
    const reference = bytesToHex(hexToBytes('ab'.repeat(32)));
    const encryptedReference = await encryptActReference({
      load,
      historyAddress,
      publisherPrivateKey,
      reference,
    });
    expect(
      await openActReference({
        load,
        historyAddress,
        publisherPublicKey: secp256k1.getPublicKey(publisherPrivateKey, true),
        privateKey: readers[39]!,
        encryptedReference,
      }),
    ).toBe(reference);
  });
});
