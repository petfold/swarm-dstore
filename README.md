# swarm-dstore

[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

Document and image storage on [Ethereum Swarm](https://www.ethswarm.org/) for browser editors. No server, and no dependency beyond `viem`.

- **Documents.** Each save uploads a snapshot, AES-256-GCM encrypted if a document key is set, and advances a feed owned by the document's key. A document keeps one address while it changes, and the feed is its version history.
- **Images.** `imageUploadFn` and `imageFetchFn` for editors with storage-agnostic image props (Fileverse dDoc 5.1.14 and later), encrypted in the browser before upload.
- **Postage stamps.** List them, check their health, buy, top up, dilute, and estimate cost.
- **Diagnostics.** Why storage is unavailable (node down, no postage batch, a document opened from someone else's link, …) and what fixes it.
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

## Namespaces

A document's feed topic is `keccak256("<namespace>/v1/<documentId>")`. dDoc uses `ddoc` and dSheets uses `dsheet`, as their earlier copies of this code did. Changing either strands the documents already saved, so a test pins both.

## Develop

```
pnpm install
pnpm typecheck
pnpm test
pnpm build
```

Tests sit next to the code. The ones that need Swarm skip themselves unless a Bee node is reachable at `BEE_API_URL` (default `http://localhost:1633`) in the state they test, for example with a usable postage batch.

## Licence

BSD-3-Clause. See `LICENSE`.
