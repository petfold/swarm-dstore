// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256 } from 'viem';
import {
  ActAccessDeniedError,
  actKeys,
  beeCipher,
  decodeMantarayNode,
  encryptActReference,
  grantActAccess,
  lookupActHistory,
  openActReference,
  walkMantarayValues,
  writeMantaray,
  type MantarayValue,
} from './swarm-act';
import type { ByteLoader, ByteUploader } from './swarm-bytes';
import { bytesToHex, hexToBytes } from './swarm-common';
import { chunkAddress } from './swarm-feeds';

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

/**
 * An ACT history as Bee 2.8.3 wrote it for `POST /grantee` with one
 * grantee, the public key of private key 42: its two Mantaray nodes and
 * the ACT they point to, by reference. The publisher is that node's key.
 */
const BEE_HISTORY = {
  publisher:
    '03d1ce6bb8e58358c1ce1df302c747cc91bafdc66eb8f5b21e31f6d228f5b5f01e',
  address: '554b4a2f6d934364c7499134d0520372ec68ef07a1b1eaf96e56b73673d3ec2a',
  chunks: {
    '554b4a2f6d934364c7499134d0520372ec68ef07a1b1eaf96e56b73673d3ec2a':
      '00000000000000000000000000000000000000000000000000000000000000005768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f200000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000012133932323333373230333530363233333038373000000000000000000000004de12847ccc03326d704691a638b3046d350eade9ba18a1ae20834dbf5af0968009e7b22656e63727970746564676c726566223a226133616432303161353463323666386562333763613363303836666438373262353363313662623137393337663361373831343135333263376536653933393464663666376464636635363462623133396231623637333332613262363131363663613634383834643035663166303366383665333262353435303931313263227d0a0a0a0a0a0a0a0a0a',
    '4de12847ccc03326d704691a638b3046d350eade9ba18a1ae20834dbf5af0968':
      '00000000000000000000000000000000000000000000000000000000000000005768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f2069d36a0d6bd057c87d47516029f6c264ca8374ad4d45fe23cc54c023c3e094a90000000000000000000000000000000000000000000000000000000000000000',
    '69d36a0d6bd057c87d47516029f6c264ca8374ad4d45fe23cc54c023c3e094a9':
      '7b22656e7472696573223a7b2239656162646535616539343033306633336366346562376232316563616261663235616164326231646337616166306565333166383730383138326136613566223a7b227265666572656e6365223a2235313361336234306263376130623363636265386238653066623763663932663038333136326433343834336366396230663263303934346134376336346338227d2c2264353037333539616463383330386664343863346432343337356137303136303964613931343536333836653866353831336236623830623137633766363066223a7b227265666572656e6365223a2263383065383966353561373265386630626337313833353435643964646663386631643734373439663235393733396130353666366262663462663261343734227d7d7d',
  } as Record<string, string>,
};

/** Content-addressed like Swarm, for single chunks. */
class MemoryStore {
  readonly chunks = new Map<string, Uint8Array>();
  constructor(initial: Record<string, string> = {}) {
    for (const [ref, data] of Object.entries(initial)) {
      this.chunks.set(ref, hexToBytes(data));
    }
  }
  upload: ByteUploader = async (data) => {
    const ref = hex(chunkAddress(data));
    this.chunks.set(ref, data);
    return ref;
  };
  load: ByteLoader = async (ref) => {
    const data = this.chunks.get(ref);
    if (!data) throw new Error(`missing ${ref}`);
    return data;
  };
}

const ref = (n: number) => keccak256(new Uint8Array([n]), 'bytes');
const historyKey = (unixSeconds: number) =>
  (9223372036854775807n - BigInt(unixSeconds)).toString();
const encode = (s: string) => new TextEncoder().encode(s);
const decode = (b: Uint8Array) => new TextDecoder().decode(b);

const collect = async (load: ByteLoader, root: string) => {
  const out: MantarayValue[] = [];
  for await (const value of walkMantarayValues(load, root)) out.push(value);
  return out;
};

describe('Mantaray as Bee writes it', () => {
  const bee = new MemoryStore(BEE_HISTORY.chunks);

  it('reads an ACT history Bee wrote', async () => {
    const [value, ...more] = await collect(bee.load, BEE_HISTORY.address);
    expect(more).toEqual([]);
    const granted = 9223372036854775807n - BigInt(decode(value!.path));
    expect(Number(granted)).toBeGreaterThan(1_790_000_000);
    expect(value!.metadata?.encryptedglref).toMatch(/^[0-9a-f]{128}$/);
    const act = JSON.parse(decode(await bee.load(hex(value!.entry))));
    expect(Object.keys(act.entries)).toHaveLength(2);
  });

  it('writes the same bytes, so the same reference', async () => {
    const values = await collect(bee.load, BEE_HISTORY.address);
    const store = new MemoryStore();
    expect(await writeMantaray(store.upload, values)).toBe(BEE_HISTORY.address);
  });

  it('opens what Bee granted to key 42', async () => {
    const [value] = await collect(bee.load, BEE_HISTORY.address);
    const timestamp = Number(
      9223372036854775807n - BigInt(decode(value!.path)),
    );
    // Encrypt as the publisher would, with the access key key 42 can see.
    const act = JSON.parse(decode(await bee.load(hex(value!.entry))));
    const mine = actKeys(priv(42), hexToBytes(BEE_HISTORY.publisher));
    const accessKey = beeCipher(
      mine.accessKeyDecryptionKey,
      hexToBytes(act.entries[hex(mine.lookupKey)].reference),
    );
    const plain = hex(ref(5));
    const encryptedReference = hex(beeCipher(accessKey, hexToBytes(plain)));
    const open = (key: Uint8Array) =>
      openActReference({
        load: bee.load,
        historyAddress: BEE_HISTORY.address,
        publisherPublicKey: BEE_HISTORY.publisher,
        privateKey: key,
        encryptedReference,
        timestamp,
      });
    expect(await open(priv(42))).toBe(plain);
    await expect(open(priv(43))).rejects.toBeInstanceOf(ActAccessDeniedError);
  });
});

describe('writeMantaray', () => {
  it('round-trips paths, entries and metadata', async () => {
    const store = new MemoryStore();
    const values: MantarayValue[] = [
      { path: encode('a'), entry: ref(1) },
      { path: encode('ab'), entry: ref(2) }, // under a value
      { path: encode('x'.repeat(70)), entry: ref(3) }, // longer than a prefix
      { path: encode('docs/readme.md'), entry: ref(4) },
      // JSON whose 2-byte length makes 32 and 64 bytes: Bee pads these
      // differently.
      { path: encode('m30'), entry: ref(5), metadata: { k: 'v'.repeat(22) } },
      { path: encode('m62'), entry: ref(6), metadata: { k: 'v'.repeat(54) } },
    ];
    const root = await writeMantaray(store.upload, values);
    const back = await collect(store.load, root);
    const byPath = (v: MantarayValue[]) =>
      v.map((x) => [decode(x.path), hex(x.entry), x.metadata]).sort();
    expect(byPath(back)).toEqual(byPath(values));
  });

  it('reads back with an obfuscation key', async () => {
    const store = new MemoryStore();
    const key = new Uint8Array(32).map((_, i) => 0xa0 + i);
    const root = await writeMantaray(
      store.upload,
      [
        { path: encode('b'), entry: ref(2) },
        { path: encode('a'), entry: ref(1), metadata: { name: 'a' } },
      ],
      key,
    );
    const node = decodeMantarayNode(await store.load(root));
    expect(node.forks.map((f) => decode(f.prefix))).toEqual(['a', 'b']);
    expect(node.forks[0]!.metadata).toEqual({ name: 'a' });
    expect((await collect(store.load, root)).map((v) => hex(v.entry))).toEqual([
      hex(ref(1)),
      hex(ref(2)),
    ]);
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
  const history = writeMantaray(store.upload, [
    { path: encode(historyKey(1000)), entry: ref(1) },
    { path: encode(historyKey(2000)), entry: ref(2) },
    {
      path: encode(historyKey(3000)),
      entry: ref(3),
      metadata: { encryptedglref: 'g3' },
    },
  ]);
  const at = async (t: number) =>
    (await lookupActHistory(store.load, await history, t))?.actReference;

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
      (await lookupActHistory(store.load, await history, 3500))?.metadata,
    ).toEqual({ encryptedglref: 'g3' });
  });
});

describe('granting in the client', () => {
  // Publisher 7 grants reader 42, then adds 43, then re-keys for 43 only.
  const store = new MemoryStore();
  const { load, upload } = store;
  const publisherPrivateKey = priv(7);
  const open = (
    privateKey: Uint8Array,
    historyAddress: string,
    encryptedReference: string,
    timestamp: number,
  ) =>
    openActReference({
      load,
      historyAddress,
      publisherPublicKey: pub(7),
      privateKey,
      encryptedReference,
      timestamp,
    });
  const encrypt = (historyAddress: string, plain: string, timestamp: number) =>
    encryptActReference({
      load,
      historyAddress,
      publisherPrivateKey,
      reference: plain,
      timestamp,
    });

  it('grants, adds a reader, and revokes by re-keying', async () => {
    const first = await grantActAccess({
      load,
      upload,
      publisherPrivateKey,
      grantees: [hex(pub(42))],
      timestamp: 1000,
    });
    const v1 = await encrypt(first.historyAddress, hex(ref(1)), 1000);
    expect(await open(priv(42), first.historyAddress, v1, 1000)).toBe(
      hex(ref(1)),
    );
    // The publisher can always open its own content.
    expect(await open(priv(7), first.historyAddress, v1, 1000)).toBe(
      hex(ref(1)),
    );
    await expect(
      open(priv(43), first.historyAddress, v1, 1000),
    ).rejects.toBeInstanceOf(ActAccessDeniedError);

    // Adding keeps the access key: 43 can open what came before.
    const second = await grantActAccess({
      load,
      upload,
      publisherPrivateKey,
      grantees: [pub(43)],
      historyAddress: first.historyAddress,
      timestamp: 2000,
    });
    expect(await open(priv(43), second.historyAddress, v1, 2000)).toBe(
      hex(ref(1)),
    );
    expect(await open(priv(42), second.historyAddress, v1, 2000)).toBe(
      hex(ref(1)),
    );

    // Re-keying for 43 alone revokes 42 from then on.
    const third = await grantActAccess({
      load,
      upload,
      publisherPrivateKey,
      grantees: [pub(43)],
      historyAddress: second.historyAddress,
      rekey: true,
      timestamp: 3000,
    });
    const v3 = await encrypt(third.historyAddress, hex(ref(3)), 3000);
    expect(await open(priv(43), third.historyAddress, v3, 3000)).toBe(
      hex(ref(3)),
    );
    await expect(
      open(priv(42), third.historyAddress, v3, 3000),
    ).rejects.toBeInstanceOf(ActAccessDeniedError);
    // What 42 could read before stays open at its time.
    expect(await open(priv(42), third.historyAddress, v1, 1000)).toBe(
      hex(ref(1)),
    );
    expect(await collect(load, third.historyAddress)).toHaveLength(3);
  });

  it('replaces a grant made in the same second', async () => {
    const a = await grantActAccess({
      load,
      upload,
      publisherPrivateKey,
      grantees: [pub(42)],
      timestamp: 5000,
    });
    const b = await grantActAccess({
      load,
      upload,
      publisherPrivateKey,
      grantees: [pub(43)],
      historyAddress: a.historyAddress,
      timestamp: 5000,
    });
    const values = await collect(load, b.historyAddress);
    expect(values).toHaveLength(1);
    expect(hex(values[0]!.entry)).toBe(b.actReference);
  });

  it('writes the ACT as Go does: keys sorted, no empty metadata', async () => {
    const { actReference } = await grantActAccess({
      load,
      upload,
      publisherPrivateKey,
      grantees: [pub(42), pub(43), pub(44)],
      timestamp: 6000,
    });
    const text = decode(await load(actReference));
    const keys = Object.keys(JSON.parse(text).entries);
    expect(keys).toEqual([...keys].sort());
    expect(keys).toHaveLength(4);
    expect(text).not.toContain('metadata');
  });

  it('refuses to extend a history the key did not publish', async () => {
    const theirs = await grantActAccess({
      load,
      upload,
      publisherPrivateKey: priv(8),
      grantees: [],
      timestamp: 7000,
    });
    await expect(
      grantActAccess({
        load,
        upload,
        publisherPrivateKey,
        grantees: [pub(42)],
        historyAddress: theirs.historyAddress,
        timestamp: 7001,
      }),
    ).rejects.toBeInstanceOf(ActAccessDeniedError);
  });
});
