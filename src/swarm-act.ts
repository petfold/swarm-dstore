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
 * Swarm's access control (ACT) in the browser, with keys the app holds. No
 * node decrypts or grants anything: a reader needs only something that
 * serves bytes by reference, and a publisher only something that stores
 * them, so access is governed by the app's own keys, not a node's.
 *
 * Bee-compatible bit for bit (Bee's pkg/accesscontrol, pkg/encryption and
 * pkg/manifest); the key derivation and the cipher are pinned against
 * vectors from Bee's own Go packages, and Bee reads what this writes. A
 * publisher grants readers' public keys; a reader then:
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

// ─── Mantaray ───

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

/**
 * An uploader over a Bee node's `POST /bytes`. ACT data must be stored this
 * way, unwrapped: Bee loads it by its raw reference.
 */
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
const NODE_TYPE_EDGE = 4;
const NODE_TYPE_WITH_PATH_SEPARATOR = 8;
const NODE_TYPE_WITH_METADATA = 16;
const MAX_PREFIX_LENGTH = 30;
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
    if (prefixLength === 0 || prefixLength > MAX_PREFIX_LENGTH) {
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

/** Bee's fork metadata: 2-byte length, JSON, newline padding. */
const encodeForkMetadata = (metadata: Record<string, string>) => {
  const json = new TextEncoder().encode(JSON.stringify(metadata));
  // Bee pads the JSON so that it and its length fill whole 32-byte
  // segments; past one segment its arithmetic adds a whole segment when
  // they already do.
  const withLength = json.length + 2;
  const padding =
    withLength < 32
      ? 32 - withLength
      : withLength === 32
        ? 0
        : 32 - (withLength % 32);
  const length = json.length + padding;
  if (length > 0xffff) throw new Error('Mantaray fork metadata too large');
  const out = new Uint8Array(2 + length).fill(0x0a);
  out[0] = length >> 8;
  out[1] = length & 0xff;
  out.set(json, 2);
  return out;
};

const commonPrefixLength = (paths: Uint8Array[]) => {
  const first = paths[0]!;
  let n = 0;
  while (
    n < MAX_PREFIX_LENGTH &&
    n < first.length &&
    paths.every((p) => p.length > n && p[n] === first[n])
  ) {
    n++;
  }
  return n;
};

const writeNode = async (
  upload: ByteUploader,
  values: MantarayValue[],
  obfuscationKey: Uint8Array,
): Promise<{
  reference: Uint8Array;
  type: number;
  metadata?: Record<string, string>;
}> => {
  const own = values.find((v) => v.path.length === 0);
  const groups = new Map<number, MantarayValue[]>();
  for (const value of values) {
    if (value.path.length === 0) continue;
    const first = value.path[0]!;
    groups.set(first, [...(groups.get(first) ?? []), value]);
  }
  const bitmap = new Uint8Array(32);
  const forks: Uint8Array[] = [];
  for (const first of [...groups.keys()].sort((a, b) => a - b)) {
    const group = groups.get(first)!;
    const n = commonPrefixLength(group.map((v) => v.path));
    const prefix = group[0]!.path.slice(0, n);
    const child = await writeNode(
      upload,
      group.map((v) => ({ ...v, path: v.path.slice(n) })),
      obfuscationKey,
    );
    bitmap[first >> 3]! |= 1 << (first & 7);
    const head = new Uint8Array(32);
    head[0] =
      child.type |
      (prefix.indexOf(0x2f) > 0 ? NODE_TYPE_WITH_PATH_SEPARATOR : 0);
    head[1] = n;
    head.set(prefix, 2);
    forks.push(
      concatBytes(
        head,
        child.reference,
        child.metadata ? encodeForkMetadata(child.metadata) : new Uint8Array(0),
      ),
    );
  }
  const entry = own?.entry ?? new Uint8Array(32);
  if (entry.length !== 32) throw new Error('Mantaray entries are 32 bytes');
  const plain = concatBytes(
    obfuscationKey,
    VERSION_02_HASH,
    new Uint8Array([32]),
    entry,
    bitmap,
    ...forks,
  );
  const data = plain.map((v, i) => (i < 32 ? v : v ^ obfuscationKey[i % 32]!));
  const metadata =
    own?.metadata && Object.keys(own.metadata).length > 0
      ? own.metadata
      : undefined;
  return {
    reference: hexToBytes(await upload(data)),
    type:
      (own ? NODE_TYPE_VALUE : 0) |
      (groups.size > 0 ? NODE_TYPE_EDGE : 0) |
      (metadata ? NODE_TYPE_WITH_METADATA : 0),
    ...(metadata ? { metadata } : {}),
  };
};

/**
 * Store values as a Mantaray manifest, laid out as Bee writes version 0.2,
 * and return the root's reference. Paths must be distinct, and entries are
 * 32-byte references.
 */
export const writeMantaray = async (
  upload: ByteUploader,
  values: MantarayValue[],
  obfuscationKey: Uint8Array = new Uint8Array(32),
): Promise<string> =>
  bytesToHex((await writeNode(upload, values, obfuscationKey)).reference);

// ─── ACT ───

const MAX_INT64 = 9223372036854775807n;

const historyKey = (timestamp: number) =>
  new TextEncoder().encode((MAX_INT64 - BigInt(timestamp)).toString());

const now = () => Math.floor(Date.now() / 1000);

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

/** An ACT: Bee's simple manifest, wrapped access keys by lookup key. */
interface ActTable {
  entries: Record<
    string,
    { reference: string; metadata?: Record<string, string> }
  >;
}

/**
 * As Go's encoding/json writes it (keys sorted, empty metadata left out),
 * so the same table has the same reference as Bee's.
 */
const encodeAct = (act: ActTable) => {
  const entries: ActTable['entries'] = {};
  for (const key of Object.keys(act.entries).sort()) {
    entries[key] = act.entries[key]!;
  }
  return new TextEncoder().encode(JSON.stringify({ entries }));
};

const loadAct = async (
  load: ByteLoader,
  historyAddress: string,
  timestamp: number,
): Promise<ActTable> => {
  const history = await lookupActHistory(load, historyAddress, timestamp);
  if (!history) throw new Error('No ACT history entry found');
  const act = JSON.parse(
    new TextDecoder().decode(await load(history.actReference)),
  ) as Partial<ActTable>;
  return { entries: act.entries ?? {} };
};

const unwrapAccessKey = (
  act: ActTable,
  privateKey: Uint8Array,
  publisherPublicKey: Uint8Array,
): Uint8Array => {
  const { lookupKey, accessKeyDecryptionKey } = actKeys(
    privateKey,
    publisherPublicKey,
  );
  const wrapped = act.entries[bytesToHex(lookupKey)]?.reference;
  if (!wrapped) throw new ActAccessDeniedError();
  const accessKey = beeCipher(accessKeyDecryptionKey, hexToBytes(wrapped));
  if (accessKey.length !== 32) throw new Error('Invalid ACT access key');
  return accessKey;
};

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
  const act = await loadAct(
    options.load,
    options.historyAddress,
    options.timestamp ?? now(),
  );
  const accessKey = unwrapAccessKey(
    act,
    toKeyBytes(options.privateKey),
    toKeyBytes(options.publisherPublicKey),
  );
  return bytesToHex(
    beeCipher(accessKey, hexToBytes(options.encryptedReference)),
  );
};

/**
 * Publish an ACT under the publisher's own key and add it to the
 * publisher's history, in Bee's format: what `POST /grantee` and
 * `PATCH /grantee` do inside a node, with the app's key in place of the
 * node's. Returns the new history address, which readers need along with
 * the publisher's public key.
 *
 * Without `rekey`, the grantees join the ACT in force and share its access
 * key, so they can also open what was published under it before. With
 * `rekey`, the ACT starts over with a new access key for exactly
 * `grantees`: that is how a reader is revoked. Content published earlier
 * stays readable at its own time, as with any encryption.
 */
export const grantActAccess = async (options: {
  load: ByteLoader;
  upload: ByteUploader;
  publisherPrivateKey: string | Uint8Array;
  /** Readers' public keys, hex, compressed or not. */
  grantees: (string | Uint8Array)[];
  /** The history to extend; a new one when absent. */
  historyAddress?: string;
  rekey?: boolean;
  /**
   * Unix seconds; defaults to now. A history keeps one ACT per second, so
   * a second grant in the same second replaces the first.
   */
  timestamp?: number;
}): Promise<{ historyAddress: string; actReference: string }> => {
  const timestamp = options.timestamp ?? now();
  const privateKey = toKeyBytes(options.publisherPrivateKey);
  const publisher = secp256k1.getPublicKey(privateKey, true);

  let act: ActTable = { entries: {} };
  let accessKey: Uint8Array;
  if (options.historyAddress && !options.rekey) {
    act = await loadAct(options.load, options.historyAddress, timestamp);
    accessKey = unwrapAccessKey(act, privateKey, publisher);
  } else {
    accessKey = crypto.getRandomValues(new Uint8Array(32));
  }
  // The publisher is always a grantee: its entry is how it finds the
  // access key again.
  for (const grantee of [publisher, ...options.grantees.map(toKeyBytes)]) {
    const { lookupKey, accessKeyDecryptionKey } = actKeys(privateKey, grantee);
    act.entries[bytesToHex(lookupKey)] = {
      reference: bytesToHex(beeCipher(accessKeyDecryptionKey, accessKey)),
    };
  }
  const actReference = await options.upload(encodeAct(act));

  const key = historyKey(timestamp);
  const values: MantarayValue[] = [];
  if (options.historyAddress) {
    for await (const value of walkMantarayValues(
      options.load,
      options.historyAddress,
    )) {
      if (bytesToHex(value.path) !== bytesToHex(key)) values.push(value);
    }
  }
  values.push({ path: key, entry: hexToBytes(actReference) });
  return {
    historyAddress: await writeMantaray(options.upload, values),
    actReference,
  };
};

/**
 * Encrypt a reference for the ACT in force at `timestamp`: what an upload
 * with `Swarm-Act` does inside a node. Hand out the result with the
 * history address and the publisher's public key.
 */
export const encryptActReference = async (options: {
  load: ByteLoader;
  historyAddress: string;
  publisherPrivateKey: string | Uint8Array;
  /** The plain reference (hex). */
  reference: string;
  /** Unix seconds; defaults to now. */
  timestamp?: number;
}): Promise<string> => {
  const privateKey = toKeyBytes(options.publisherPrivateKey);
  const act = await loadAct(
    options.load,
    options.historyAddress,
    options.timestamp ?? now(),
  );
  const accessKey = unwrapAccessKey(
    act,
    privateKey,
    secp256k1.getPublicKey(privateKey, true),
  );
  return bytesToHex(beeCipher(accessKey, hexToBytes(options.reference)));
};
