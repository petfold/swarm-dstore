import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256 } from 'viem';
import {
  type SwarmRequestConfig,
  bytesToHex,
  concatBytes,
  hexToBytes,
  swarmFetch,
} from './swarm-common';

/**
 * Reading Swarm's access control (ACT) in the browser, with a key the app
 * holds. No node decrypts anything, so a reader needs no node of its own:
 * any client that can fetch bytes by reference can read what was shared
 * with its key.
 *
 * Bee-compatible bit for bit (Bee's pkg/accesscontrol, pkg/encryption and
 * pkg/manifest); the key derivation and the cipher are pinned against
 * vectors from Bee's own Go packages. A publisher (today, a Bee node)
 * grants a reader's public key; the reader then:
 * 1. finds the ACT in force at a given time in the publisher's history, a
 *    Mantaray manifest keyed by `MaxInt64 - unix time`;
 * 2. derives its lookup key and the key that unwraps the access key, by
 *    ECDH between its private key and the publisher's public key;
 * 3. looks up its entry in the ACT, a simple JSON manifest keyed by the
 *    lookup key in hex, and unwraps the access key;
 * 4. decrypts the encrypted reference with the access key.
 */

const keccak = (data: Uint8Array): Uint8Array => keccak256(data, 'bytes');

/**
 * Bee's `getKeys`: the lookup key and the access-key decryption key for a
 * pair of keys. ECDH is symmetric, so the publisher (granting) and the
 * reader (reading) derive the same two keys.
 */
export const actKeys = (
  privateKey: Uint8Array,
  otherPublicKey: Uint8Array,
): { lookupKey: Uint8Array; accessKeyDecryptionKey: Uint8Array } => {
  const shared = secp256k1.getSharedSecret(privateKey, otherPublicKey, true);
  // Bee hashes Go's big.Int.Bytes() of the shared x, which drops leading
  // zero bytes; about one key pair in 256 has one.
  let x = shared.slice(1);
  let start = 0;
  while (start < x.length - 1 && x[start] === 0) start++;
  x = x.slice(start);
  return {
    lookupKey: keccak(concatBytes(x, new Uint8Array([0]))),
    accessKeyDecryptionKey: keccak(concatBytes(x, new Uint8Array([1]))),
  };
};

/**
 * Bee's `encryption` transform with no padding and counter 0: each 32-byte
 * segment is XORed with Keccak(Keccak(key || LE32(segment))). Its own
 * inverse, so it both encrypts and decrypts.
 */
export const beeCipher = (key: Uint8Array, data: Uint8Array): Uint8Array => {
  const out = new Uint8Array(data.length);
  for (let segment = 0; segment * 32 < data.length; segment++) {
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, segment, true);
    const segmentKey = keccak(keccak(concatBytes(key, counter)));
    for (let j = 0; j < 32 && segment * 32 + j < data.length; j++) {
      out[segment * 32 + j] = data[segment * 32 + j]! ^ segmentKey[j]!;
    }
  }
  return out;
};

// ─── Mantaray, read only ───

/** Fetches the bytes stored under a reference (hex). */
export type ByteLoader = (reference: string) => Promise<Uint8Array>;

/** A loader over a Bee node's `GET /bytes/{reference}`. */
export const beeByteLoader =
  (config: SwarmRequestConfig): ByteLoader =>
  async (reference) => {
    const response = await swarmFetch(config, `/bytes/${reference}`);
    if (!response.ok) throw new Error(`Not found on Swarm: ${reference}`);
    return new Uint8Array(await response.arrayBuffer());
  };

export interface MantarayFork {
  type: number;
  prefix: Uint8Array;
  reference: Uint8Array;
  metadata?: Record<string, string>;
}

export interface MantarayNode {
  entry: Uint8Array;
  /** In ascending order of the fork's first byte. */
  forks: MantarayFork[];
}

const NODE_TYPE_VALUE = 2;
const NODE_TYPE_WITH_METADATA = 16;
const VERSION_01_HASH = hexToBytes(
  '025184789d63635766d78c41900196b57d7400875ebe4d9b5d1e76bd9652a9b7',
).slice(0, 31);
const VERSION_02_HASH = hexToBytes(
  '5768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f7b',
).slice(0, 31);

const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((v, i) => v === b[i]);

/** Decode one Mantaray node (versions 0.1 and 0.2), as Bee marshals it. */
export const decodeMantarayNode = (raw: Uint8Array): MantarayNode => {
  if (raw.length < 64) throw new Error('Mantaray node too short');
  // Everything after the 32-byte obfuscation key is XORed with it.
  const data = raw.slice();
  for (let i = 32; i < data.length; i++) {
    data[i] = data[i]! ^ raw[i % 32]!;
  }
  const version = data.slice(32, 63);
  const v02 = sameBytes(version, VERSION_02_HASH);
  if (!v02 && !sameBytes(version, VERSION_01_HASH)) {
    throw new Error('Not a Mantaray node (unknown version)');
  }
  const refSize = data[63]!;
  let offset = 64;
  if (data.length < offset + refSize + 32) {
    throw new Error('Mantaray node truncated');
  }
  const entry = data.slice(offset, offset + refSize);
  offset += refSize;
  const bitmap = data.slice(offset, offset + 32);
  offset += 32;
  const forks: MantarayFork[] = [];
  for (let b = 0; b < 256; b++) {
    if (((bitmap[b >> 3]! >> (b & 7)) & 1) === 0) continue;
    if (data.length < offset + 32 + refSize) {
      throw new Error('Mantaray fork truncated');
    }
    const type = data[offset]!;
    const prefixLength = data[offset + 1]!;
    if (prefixLength === 0 || prefixLength > 30) {
      throw new Error(`Invalid Mantaray prefix length ${prefixLength}`);
    }
    const fork: MantarayFork = {
      type,
      prefix: data.slice(offset + 2, offset + 2 + prefixLength),
      reference: data.slice(offset + 32, offset + 32 + refSize),
    };
    let size = 32 + refSize;
    if (v02 && (type & NODE_TYPE_WITH_METADATA) !== 0) {
      const lengthAt = offset + size;
      const metadataLength = (data[lengthAt]! << 8) | (data[lengthAt + 1] ?? 0);
      const metadataBytes = data.slice(
        lengthAt + 2,
        lengthAt + 2 + metadataLength,
      );
      if (metadataBytes.length !== metadataLength) {
        throw new Error('Mantaray fork metadata truncated');
      }
      fork.metadata = JSON.parse(new TextDecoder().decode(metadataBytes));
      size += 2 + metadataLength;
    }
    forks.push(fork);
    offset += size;
  }
  return { entry, forks };
};

export interface MantarayValue {
  path: Uint8Array;
  entry: Uint8Array;
  metadata?: Record<string, string>;
}

async function* walkNode(
  load: ByteLoader,
  node: MantarayNode,
  path: Uint8Array,
): AsyncGenerator<MantarayValue> {
  for (const fork of node.forks) {
    const forkPath = concatBytes(path, fork.prefix);
    const child = decodeMantarayNode(await load(bytesToHex(fork.reference)));
    if ((fork.type & NODE_TYPE_VALUE) !== 0 && child.entry.length > 0) {
      yield {
        path: forkPath,
        entry: child.entry,
        ...(fork.metadata ? { metadata: fork.metadata } : {}),
      };
    }
    yield* walkNode(load, child, forkPath);
  }
}

/**
 * Every value in a Mantaray manifest, in Bee's walk order: a node before
 * its descendants, forks in ascending order of their first byte.
 */
export const walkMantarayValues = async function* (
  load: ByteLoader,
  rootReference: string,
): AsyncGenerator<MantarayValue> {
  yield* walkNode(
    load,
    decodeMantarayNode(await load(rootReference)),
    new Uint8Array(0),
  );
};

// ─── ACT ───

const MAX_INT64 = 9223372036854775807n;

/**
 * The ACT in force at `timestamp` (unix seconds) in a publisher's history:
 * the newest entry not after it, or the oldest one when all are later, as
 * Bee's `History.Lookup` does.
 */
export const lookupActHistory = async (
  load: ByteLoader,
  historyAddress: string,
  timestamp: number,
): Promise<{
  actReference: string;
  metadata?: Record<string, string>;
} | null> => {
  const searched = MAX_INT64 - BigInt(timestamp);
  let last: { actReference: string; metadata?: Record<string, string> } | null =
    null;
  for await (const value of walkMantarayValues(load, historyAddress)) {
    const key = BigInt(new TextDecoder().decode(value.path));
    const found = {
      actReference: bytesToHex(value.entry),
      ...(value.metadata ? { metadata: value.metadata } : {}),
    };
    last = found;
    if (key !== 0n && searched <= key) return found;
  }
  return last;
};

/** Raised when the ACT has no entry for this reader's key. */
export class ActAccessDeniedError extends Error {
  constructor() {
    super('This content was not shared with this key');
    this.name = 'ActAccessDeniedError';
  }
}

const toKeyBytes = (key: string | Uint8Array): Uint8Array =>
  typeof key === 'string' ? hexToBytes(key.replace(/^0x/, '')) : key;

/**
 * Decrypt an ACT-encrypted reference with the reader's own key, without a
 * node: what Bee's `Swarm-Act-*` download headers do inside the node.
 * Returns the plain reference (hex), readable with any `bzz`/`bytes` read.
 */
export const openActReference = async (options: {
  load: ByteLoader;
  /** The publisher's history address (`Swarm-Act-History-Address`). */
  historyAddress: string;
  /** The publisher's public key, hex, compressed or not. */
  publisherPublicKey: string | Uint8Array;
  /** The reader's secp256k1 private key. */
  privateKey: string | Uint8Array;
  /** The encrypted reference the publisher handed out. */
  encryptedReference: string;
  /** Unix seconds; defaults to now. */
  timestamp?: number;
}): Promise<string> => {
  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
  const history = await lookupActHistory(
    options.load,
    options.historyAddress,
    timestamp,
  );
  if (!history) throw new Error('No ACT history entry found');
  const { lookupKey, accessKeyDecryptionKey } = actKeys(
    toKeyBytes(options.privateKey),
    toKeyBytes(options.publisherPublicKey),
  );
  const act = JSON.parse(
    new TextDecoder().decode(await options.load(history.actReference)),
  ) as { entries?: Record<string, { reference: string }> };
  const wrapped = act.entries?.[bytesToHex(lookupKey)]?.reference;
  if (!wrapped) throw new ActAccessDeniedError();
  const accessKey = beeCipher(accessKeyDecryptionKey, hexToBytes(wrapped));
  if (accessKey.length !== 32) throw new Error('Invalid ACT access key');
  return bytesToHex(
    beeCipher(accessKey, hexToBytes(options.encryptedReference)),
  );
};
