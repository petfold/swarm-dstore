import {
  type SwarmRequestConfig,
  bytesToHex,
  concatBytes,
  fromBase64,
  swarmFetch,
} from './swarm-common';
import { chunkAddress } from './swarm-feeds';
import type { SwarmProvider } from './swarm-transport';

/**
 * Bytes by reference, unwrapped, as Bee's `/bytes` stores them: a tree of
 * content-addressed chunks. Swarm structures that point at each other by
 * reference, such as manifests and ACT data, need this form; the
 * transport's `uploadData` wraps content in a manifest instead.
 *
 * Over a Bee node's API, the node splits and joins. Over a `window.swarm`
 * provider, which offers single chunks only, this splits and joins in the
 * page, exactly as Bee does, so the references are the same.
 */

/** Fetches the bytes stored under a reference (hex). */
export type ByteLoader = (reference: string) => Promise<Uint8Array>;

/** Stores bytes and returns their reference (hex), as `POST /bytes` does. */
export type ByteUploader = (data: Uint8Array<ArrayBuffer>) => Promise<string>;

/** A loader over a Bee node's `GET /bytes/{reference}`. */
export const beeByteLoader =
  (config: SwarmRequestConfig): ByteLoader =>
  async (reference) => {
    const response = await swarmFetch(config, `/bytes/${reference}`);
    if (!response.ok) throw new Error(`Not found on Swarm: ${reference}`);
    return new Uint8Array(await response.arrayBuffer());
  };

/** An uploader over a Bee node's `POST /bytes`. */
export const beeByteUploader =
  (
    config: SwarmRequestConfig & {
      postageBatchId: string;
      deferredUpload?: boolean;
    },
  ): ByteUploader =>
  async (data) => {
    const response = await swarmFetch(config, '/bytes', {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'swarm-postage-batch-id': config.postageBatchId,
        ...(config.deferredUpload === false
          ? { 'swarm-deferred-upload': 'false' }
          : {}),
      },
      body: data,
    });
    if (!response.ok) throw new Error('Swarm upload failed');
    return ((await response.json()) as { reference: string }).reference;
  };

// ─── Chunk trees ───

const CHUNK_SIZE = 4096;
const REFERENCE_SIZE = 32;
const BRANCHES = CHUNK_SIZE / REFERENCE_SIZE;

/** One chunk: its payload and the length of all the data under it. */
export interface StoredChunk {
  payload: Uint8Array;
  span: number;
}

/**
 * Split data into chunks as Bee's splitter does, hand each to `put`, and
 * return the root reference. Leaves hold 4096 bytes; an intermediate chunk
 * holds up to 128 references. When a level ends with a single reference,
 * it moves up a level unwrapped, as in Bee's hash trie.
 */
export const writeChunkTree = async (
  data: Uint8Array,
  put: (_chunk: StoredChunk) => Promise<string>,
): Promise<string> => {
  type Ref = { address: Uint8Array; span: number };
  const levels: Ref[][] = [[]];

  const store = async (payload: Uint8Array, span: number): Promise<Ref> => {
    const address = chunkAddress(payload, span);
    const reference = await put({ payload, span });
    if (reference !== bytesToHex(address)) {
      throw new Error('Chunk stored under an unexpected reference');
    }
    return { address, span };
  };
  const wrap = async (level: number) => {
    const refs = levels[level]!;
    levels[level] = [];
    const parent = await store(
      concatBytes(...refs.map((r) => r.address)),
      refs.reduce((n, r) => n + r.span, 0),
    );
    await push(level + 1, parent);
  };
  const push = async (level: number, ref: Ref) => {
    (levels[level] ??= []).push(ref);
    if (levels[level]!.length === BRANCHES) await wrap(level);
  };

  let offset = 0;
  do {
    const leaf = data.slice(offset, offset + CHUNK_SIZE);
    await push(0, await store(leaf, leaf.length));
    offset += CHUNK_SIZE;
  } while (offset < data.length);

  for (let level = 0; ; level++) {
    const refs = levels[level]!;
    const above = levels.slice(level + 1).some((l) => l.length > 0);
    if (refs.length === 0) continue;
    if (refs.length === 1 && !above) return bytesToHex(refs[0]!.address);
    if (refs.length === 1) {
      levels[level] = [];
      await push(level + 1, refs[0]!);
    } else {
      await wrap(level);
    }
  }
};

/** Read a chunk tree back into the data it holds. */
export const readChunkTree = async (
  reference: string,
  get: (_reference: string) => Promise<StoredChunk>,
): Promise<Uint8Array> => {
  const { payload, span } = await get(reference);
  if (span <= CHUNK_SIZE) {
    if (payload.length < span) throw new Error('Chunk shorter than its span');
    return payload.slice(0, span);
  }
  const children: string[] = [];
  for (let i = 0; i + REFERENCE_SIZE <= payload.length; i += REFERENCE_SIZE) {
    children.push(bytesToHex(payload.slice(i, i + REFERENCE_SIZE)));
  }
  const data = concatBytes(
    ...(await Promise.all(children.map((c) => readChunkTree(c, get)))),
  );
  if (data.length !== span) throw new Error('Chunk tree shorter than its span');
  return data;
};

// ─── Over a window.swarm provider ───

/** A loader over a provider's `swarm_readChunk`; needs no permission. */
export const providerByteLoader =
  (provider: SwarmProvider): ByteLoader =>
  (reference) =>
    readChunkTree(reference, async (ref) => {
      const chunk = (await provider.request({
        method: 'swarm_readChunk',
        params: { reference: ref },
      })) as { data: string; encoding?: string; span?: number | string };
      const payload =
        chunk.encoding === 'base64'
          ? fromBase64(chunk.data)
          : new TextEncoder().encode(chunk.data);
      return {
        payload,
        span: chunk.span === undefined ? payload.length : Number(chunk.span),
      };
    });

/**
 * An uploader over a provider's `swarm_publishChunk`, which needs the
 * page to be connected (`swarm_requestAccess`). The provider's postage
 * pays; each chunk is one call.
 */
export const providerByteUploader =
  (provider: SwarmProvider): ByteUploader =>
  (data) =>
    writeChunkTree(data, async ({ payload, span }) => {
      const { reference } = (await provider.request({
        method: 'swarm_publishChunk',
        params: { data: payload, span },
      })) as { reference: string };
      return reference.replace(/^0x/, '').toLowerCase();
    });
