// Reads the dSheets demo's sheet back from Swarm with the keys in its share
// link: lists its versions, checks each, and that the stored blob is
// ciphertext. SHARE_URL_FILE holds the link. Run:
//   SHARE_URL_FILE=<file> pnpm vitest run --config spike/vitest.config.ts spike/verify-e2e.spike.ts
import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { createSwarmDocumentStorage } from '../src/swarm-document-storage';

const BEE = process.env.BEE_API_URL || 'http://localhost:1633';
it('the demo sheet is versioned and encrypted on Swarm', async () => {
  const url = new URL(readFileSync(process.env.SHARE_URL_FILE!, 'utf8').trim());
  const sheet = url.searchParams.get('sheet')!;
  const m = url.hash.match(/skey=([^:]+):([^&]+)/)!;
  const owner = decodeURIComponent(m[1]!) as `0x${string}`;
  const docKey = decodeURIComponent(m[2]!);
  const storage = createSwarmDocumentStorage({
    namespace: 'dsheet',
    beeUrl: BEE,
    ownerPrivateKey: owner,
    documentKey: docKey,
  });
  const versions = await storage.listDocumentVersions(sheet);
  console.log(
    '[verify] versions:',
    versions
      .map(
        (v) =>
          `#${v.index} ${new Date(v.timestamp * 1000).toISOString().slice(11, 19)} ${v.reference.slice(0, 10)}`,
      )
      .join(', '),
  );
  const stamp = sheet.replace('e2e-', '');
  const has = (b: Uint8Array, s: string) =>
    Buffer.from(b).includes(Buffer.from(s));
  const decode = (text: string) => new Uint8Array(Buffer.from(text, 'base64'));
  for (const v of versions) {
    const snap = (await storage.loadDocumentVersion(sheet, v.index))!;
    const y = decode(snap.text);
    console.log(
      `[verify] version ${v.index}: ${y.length} B Y.Doc state; has v1 text: ${has(y, 'swarm-e2e-' + stamp)}, has v2 text: ${has(y, 'second-' + stamp)}`,
    );
  }
  const latest = (await storage.loadDocument(sheet))!;
  // The blob on Swarm, fetched without the key, must not contain the text.
  const raw = new Uint8Array(
    await (await fetch(`${BEE}/bzz/${latest.reference}/`)).arrayBuffer(),
  );
  console.log(
    `[verify] raw blob ${raw.length} B; plaintext visible without key: ${has(raw, 'swarm-e2e-' + stamp)}`,
  );
  expect(versions.length).toBeGreaterThanOrEqual(2);
  expect(has(decode(latest.text), 'second-' + stamp)).toBe(true);
  expect(has(raw, 'swarm-e2e-' + stamp)).toBe(false);
});
