// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256 } from 'viem';
import {
  ActAccessDeniedError,
  actKeys,
  beeCipher,
  decodeMantarayNode,
  lookupActHistory,
  openActReference,
  walkMantarayValues,
  type ByteLoader,
} from './swarm-act';
import { bytesToHex, concatBytes, hexToBytes } from './swarm-common';

/** A private key from a small number, as in the vectors. */
const priv = (seed: number) =>
  hexToBytes(BigInt(seed).toString(16).padStart(64, '0'));
const pub = (seed: number) => secp256k1.getPublicKey(priv(seed), true);
const hex = (b: Uint8Array) => bytesToHex(b);

// Computed with Bee's own Go packages (session.Key, encryption.New).
const ACCESS_KEY =
  '8abf1502f557f15026716030fb6384792583daf39608a3cd02ff2f47e9bc6e49';
const VECTORS = [
  {
    grantee: 42,
    publisher: 7,
    publisherPublicKey:
      '025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc',
    lookupKey:
      '90520a9c134c04fbe88dcc47d5809b8f2122f723b9680cfc05789a75f9ccfaf9',
    accessKeyDecryptionKey:
      '02a5e279ddd85943492047b8fd22077fb1c951e67f39f04d1913b73efcf3d83b',
    wrappedAccessKey:
      '86c90a1dd419789ae328bfda1fe9ccf58328396f4c7964d44b6ff7bde29e8b09',
  },
  {
    // The shared x starts with a zero byte, which Bee drops before hashing.
    grantee: 177,
    publisher: 100177,
    publisherPublicKey:
      '029acb593230e2a6ef975fff73554cce809a88ebd1d2a77d7f7fbf6eecba4943d2',
    lookupKey:
      '499869b38e436ca280bd7ddcb5ab2b6340c48bcf0b7c1c405a4363edefe45cb3',
    accessKeyDecryptionKey:
      '190a99ce393e6b01aea02efdf8e3897e523c74c7c9ad3504b8619fc012557eb0',
    wrappedAccessKey:
      'f248cba852b38e8f4cce943c651b59b99d412d424c6d023736465c63b69ed464',
  },
];

describe('actKeys', () => {
  it.each(VECTORS)(
    'matches Bee for grantee $grantee and publisher $publisher',
    (v) => {
      expect(hex(pub(v.publisher))).toBe(v.publisherPublicKey);
      const keys = actKeys(priv(v.grantee), pub(v.publisher));
      expect(hex(keys.lookupKey)).toBe(v.lookupKey);
      expect(hex(keys.accessKeyDecryptionKey)).toBe(v.accessKeyDecryptionKey);
    },
  );

  it('is symmetric, so publisher and grantee derive the same keys', () => {
    const a = actKeys(priv(42), pub(7));
    const b = actKeys(priv(7), pub(42));
    expect(hex(a.lookupKey)).toBe(hex(b.lookupKey));
    expect(hex(a.accessKeyDecryptionKey)).toBe(hex(b.accessKeyDecryptionKey));
  });

  it('accepts an uncompressed public key', () => {
    const uncompressed = secp256k1.getPublicKey(priv(7), false);
    expect(hex(actKeys(priv(42), uncompressed).lookupKey)).toBe(
      VECTORS[0]!.lookupKey,
    );
  });
});

describe('beeCipher', () => {
  it.each(VECTORS)('wraps the access key as Bee does ($grantee)', (v) => {
    const wrapped = beeCipher(
      hexToBytes(v.accessKeyDecryptionKey),
      hexToBytes(ACCESS_KEY),
    );
    expect(hex(wrapped)).toBe(v.wrappedAccessKey);
    expect(hex(beeCipher(hexToBytes(v.accessKeyDecryptionKey), wrapped))).toBe(
      ACCESS_KEY,
    );
  });

  it('matches Bee over many segments', () => {
    const out = beeCipher(hexToBytes(ACCESS_KEY), new Uint8Array(4096));
    expect(keccak256(out).slice(2)).toBe(
      'eab9772cbbd2b8dacaccb949a6539d856b707251894ce1642717b5912b7296fb',
    );
  });

  it('handles a length that is not a multiple of 32', () => {
    const data = new Uint8Array(45).map((_, i) => i);
    const key = hexToBytes(ACCESS_KEY);
    const once = beeCipher(key, data);
    expect(once.length).toBe(45);
    expect(beeCipher(key, once)).toEqual(data);
    // A prefix encrypts to a prefix: the cipher is a keystream.
    expect(beeCipher(key, data.slice(0, 40))).toEqual(once.slice(0, 40));
  });
});

// ─── An in-memory Mantaray writer, laid out as Bee marshals version 0.2 ───

const VERSION_02 = hexToBytes(
  '5768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f7b',
).slice(0, 31);

interface TestEntry {
  path: Uint8Array;
  reference: Uint8Array;
  metadata?: Record<string, string>;
}

class MemoryStore {
  readonly chunks = new Map<string, Uint8Array>();
  put(data: Uint8Array): string {
    const ref = keccak256(data).slice(2);
    this.chunks.set(ref, data);
    return ref;
  }
  load: ByteLoader = async (ref) => {
    const data = this.chunks.get(ref);
    if (!data) throw new Error(`missing ${ref}`);
    return data;
  };
}

const metadataBytes = (metadata: Record<string, string>) => {
  // Bee pads the JSON with newlines so that its 2-byte length and the JSON
  // fill whole 32-byte segments.
  const json = new TextEncoder().encode(JSON.stringify(metadata));
  const padded = Math.max(32, Math.ceil((json.length + 2) / 32) * 32) - 2;
  const out = new Uint8Array(2 + padded).fill(10);
  new DataView(out.buffer).setUint16(0, padded);
  out.set(json, 2);
  return out;
};

const commonPrefixLength = (paths: Uint8Array[]) => {
  let n = 0;
  while (n < 30 && paths.every((p) => p.length > n && p[n] === paths[0]![n])) {
    n++;
  }
  return n;
};

/** Store a node for `entries` (paths relative to it) and return its ref. */
const writeNode = (
  store: MemoryStore,
  entries: TestEntry[],
  obfuscationKey: Uint8Array,
): { ref: string; hasValue: boolean; metadata?: Record<string, string> } => {
  const own = entries.find((e) => e.path.length === 0);
  const groups = new Map<number, TestEntry[]>();
  for (const e of entries) {
    if (e.path.length === 0) continue;
    groups.set(e.path[0]!, [...(groups.get(e.path[0]!) ?? []), e]);
  }
  const bitmap = new Uint8Array(32);
  const forks: Uint8Array[] = [];
  for (const b of [...groups.keys()].sort((x, y) => x - y)) {
    const group = groups.get(b)!;
    const n = commonPrefixLength(group.map((e) => e.path));
    const child = writeNode(
      store,
      group.map((e) => ({ ...e, path: e.path.slice(n) })),
      obfuscationKey,
    );
    bitmap[b >> 3]! |= 1 << (b & 7);
    const head = new Uint8Array(32);
    head[0] = (child.hasValue ? 2 : 0) | (child.metadata ? 16 : 0);
    head[1] = n;
    head.set(group[0]!.path.slice(0, n), 2);
    forks.push(
      concatBytes(
        head,
        hexToBytes(child.ref),
        child.metadata ? metadataBytes(child.metadata) : new Uint8Array(0),
      ),
    );
  }
  const plain = concatBytes(
    obfuscationKey,
    VERSION_02,
    new Uint8Array([32]),
    own?.reference ?? new Uint8Array(32),
    bitmap,
    ...forks,
  );
  const data = plain.map((v, i) => (i < 32 ? v : v ^ obfuscationKey[i % 32]!));
  return {
    ref: store.put(data),
    hasValue: own !== undefined,
    ...(own?.metadata ? { metadata: own.metadata } : {}),
  };
};

const writeManifest = (
  store: MemoryStore,
  entries: {
    path: string;
    reference: Uint8Array;
    metadata?: Record<string, string>;
  }[],
  obfuscationKey = new Uint8Array(32),
) =>
  writeNode(
    store,
    entries.map((e) => ({ ...e, path: new TextEncoder().encode(e.path) })),
    obfuscationKey,
  ).ref;

const ref = (n: number) => keccak256(new Uint8Array([n]), 'bytes');
const historyKey = (unixSeconds: number) =>
  (9223372036854775807n - BigInt(unixSeconds)).toString();

describe('decodeMantarayNode', () => {
  it('reads a node with an obfuscation key and fork metadata', async () => {
    const store = new MemoryStore();
    const key = new Uint8Array(32).map((_, i) => 0xa0 + i);
    const root = writeManifest(
      store,
      [
        { path: 'b', reference: ref(2) },
        {
          path: 'a',
          reference: ref(1),
          metadata: { encryptedglref: 'x'.repeat(40) },
        },
      ],
      key,
    );
    const node = decodeMantarayNode(await store.load(root));
    expect(node.forks.map((f) => new TextDecoder().decode(f.prefix))).toEqual([
      'a',
      'b',
    ]);
    expect(node.forks[0]!.metadata).toEqual({ encryptedglref: 'x'.repeat(40) });
    expect(node.forks[1]!.metadata).toBeUndefined();
    const values = [];
    for await (const v of walkMantarayValues(store.load, root)) values.push(v);
    expect(values.map((v) => hex(v.entry))).toEqual([hex(ref(1)), hex(ref(2))]);
  });

  it('rejects data that is not a Mantaray node', () => {
    expect(() => decodeMantarayNode(new Uint8Array(200).fill(7))).toThrow(
      /unknown version/,
    );
    expect(() => decodeMantarayNode(new Uint8Array(10))).toThrow(/too short/);
  });
});

describe('lookupActHistory', () => {
  const store = new MemoryStore();
  const history = writeManifest(store, [
    { path: historyKey(1000), reference: ref(1) },
    { path: historyKey(2000), reference: ref(2) },
    {
      path: historyKey(3000),
      reference: ref(3),
      metadata: { encryptedglref: 'g3' },
    },
  ]);
  const at = async (t: number) =>
    (await lookupActHistory(store.load, history, t))?.actReference;

  it('takes the newest entry not after the time', async () => {
    expect(await at(1000)).toBe(hex(ref(1)));
    expect(await at(2500)).toBe(hex(ref(2)));
    expect(await at(3000)).toBe(hex(ref(3)));
    expect(await at(1_800_000_000)).toBe(hex(ref(3)));
  });

  it('falls back to the oldest entry when all are later', async () => {
    expect(await at(500)).toBe(hex(ref(1)));
  });

  it('returns the entry metadata', async () => {
    expect(
      (await lookupActHistory(store.load, history, 3500))?.metadata,
    ).toEqual({ encryptedglref: 'g3' });
  });
});

describe('openActReference', () => {
  // A publisher (7) grants a reader (42), as Bee's grantee upload does.
  const store = new MemoryStore();
  const plainReference = hex(ref(99));
  const reader = actKeys(priv(42), pub(7));
  const act = {
    entries: {
      [hex(reader.lookupKey)]: {
        reference: hex(
          beeCipher(reader.accessKeyDecryptionKey, hexToBytes(ACCESS_KEY)),
        ),
        metadata: {},
      },
    },
  };
  const actRef = store.put(new TextEncoder().encode(JSON.stringify(act)));
  const history = writeManifest(store, [
    { path: historyKey(1000), reference: hexToBytes(actRef) },
  ]);
  const encryptedReference = hex(
    beeCipher(hexToBytes(ACCESS_KEY), hexToBytes(plainReference)),
  );
  const open = (privateKey: string | Uint8Array) =>
    openActReference({
      load: store.load,
      historyAddress: history,
      publisherPublicKey: hex(pub(7)),
      privateKey,
      encryptedReference,
    });

  it('opens the reference with a granted key', async () => {
    expect(await open(priv(42))).toBe(plainReference);
    expect(await open(`0x${hex(priv(42))}`)).toBe(plainReference);
  });

  it('refuses a key that was not granted', async () => {
    await expect(open(priv(43))).rejects.toBeInstanceOf(ActAccessDeniedError);
  });
});
