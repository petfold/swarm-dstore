# swarm-dstore

[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

Document and image storage on [Ethereum Swarm](https://www.ethswarm.org/) for browser editors. No server; it needs `viem`, and `@noble/curves` for access control (both editors already depend on them).

- **Documents.** Each save uploads a snapshot, AES-256-GCM encrypted if a document key is set, and advances a feed owned by the document's key. A document keeps one address while it changes, and the feed is its version history.
- **Images.** `imageUploadFn` and `imageFetchFn` for editors with storage-agnostic image props (Fileverse dDoc 5.1.14 and later), encrypted in the browser before upload.
- **Postage stamps.** List them, check their health, buy, top up, dilute, and estimate cost.
- **Diagnostics.** Why storage is unavailable (node down, no postage batch, a document opened from someone else's link, …) and what fixes it.
- **Access control (ACT) in the browser.** Share content with named people by public key, under a key the app holds, and open what was shared with it, with no node decrypting or granting anything. Bee's format bit for bit: Bee opens what this grants, and this opens what Bee grants. Revocation and the history of who could read what when come with it.
- **Transport.** A Bee node's HTTP API, or a browser's `window.swarm` provider such as Freedom's, detected at runtime.

## Status

This is the canonical source of the Swarm modules written for Fileverse's dDocs and dSheets editors (branches `feat/swarm-storage-on-main` of `petfold/fileverse-ddoc` and `feat/swarm-storage` of `petfold/fileverse-dsheets`), merged into one. The plan is to offer it to Fileverse as a copy inside each editor's repository: swarmtyp's `docs/plan.md`, "Alongside swarmtyp", and decision D-29. Not published on npm.

## Use

```ts
import { createSwarmDocumentStorage, generateDocumentKey } from 'swarm-dstore';

const storage = createSwarmDocumentStorage({
  namespace: 'ddoc', // one per editor, part of every feed topic
  beeUrl: 'http://localhost:1633',
  postageBatchId: '<batch id>',
  ownerPrivateKey: '0x<key>',
  documentKey: generateDocumentKey(),
});

const version = await storage.saveDocument('doc-1', bytes);
const latest = await storage.loadDocument('doc-1');
const history = await storage.listDocumentVersions('doc-1');
```

Pass `transport: detectSwarmTransport(...)` instead of relying on `beeUrl` to run in a browser that exposes `window.swarm`.

Sharing through ACT. The publisher grants readers' public keys and encrypts a reference; it hands out its public key, the history address and the encrypted reference:

```ts
import {
  beeByteLoader,
  beeByteUploader,
  encryptActReference,
  grantActAccess,
  openActReference,
} from 'swarm-dstore';

const load = beeByteLoader({ beeUrl }); // any node or gateway
const upload = beeByteUploader({ beeUrl, postageBatchId });
// or, in a browser with window.swarm (Freedom), single chunks only:
// providerByteLoader(window.swarm), providerByteUploader(window.swarm)

const { historyAddress } = await grantActAccess({
  load,
  upload,
  publisherPrivateKey,
  grantees: [readerPublicKey],
  // historyAddress: to extend an earlier grant; rekey: true to revoke
});
const encryptedReference = await encryptActReference({
  load,
  historyAddress,
  publisherPrivateKey,
  reference,
});

// The reader, with its own key, which never leaves the browser:
const opened = await openActReference({
  load,
  historyAddress,
  publisherPublicKey,
  privateKey,
  encryptedReference,
}); // === reference; read it with any bzz or bytes read
```

ACT data is stored as raw bytes, not wrapped in a manifest as `uploadData` does. Over a provider, which offers single chunks, `swarm-bytes` splits and joins chunk trees in the page exactly as Bee does, so references are the same either way (pinned against bee-js's Merkle tree).

Adding grantees keeps the access key, so they can also open what was published before; `rekey: true` starts over with a new one for exactly the grantees given, which is how a reader is revoked. What was published earlier stays readable at its own time.

## Namespaces

A document's feed topic is `keccak256("<namespace>/v1/<documentId>")`. dDoc uses `ddoc` and dSheets uses `dsheet`, as their earlier copies of this code did. Changing either strands the documents already saved, so a test pins both.

## Develop

```
pnpm install
pnpm typecheck
pnpm test
pnpm build
```

Tests sit next to the code. The ones that need Swarm skip themselves unless a Bee node is reachable at `BEE_API_URL` (default `http://localhost:1633`) in the state they test, for example with a usable postage batch. The ACT key derivation and cipher are pinned against vectors from Bee's Go code. `spike/` holds live checks run by hand (`pnpm vitest run --config spike/vitest.config.ts spike/<file>`); `act-client.spike.ts` has Bee grant a key only the test holds and opens the content client-side, then grants the node's key client-side and has Bee open it, and does both through single-chunk provider methods as Freedom serves them. A Mantaray manifest written here is byte-identical to Bee's (a test pins a history Bee wrote).

## Licence

BSD-3-Clause. See `LICENSE`.
