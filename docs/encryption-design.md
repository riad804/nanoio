# Phase 9 design: encryption at rest (SSE-S3, SSE-KMS, SSE-C)

Status: **implemented**; see "Implementation notes and deviations" at the end
for where the code differs from this proposal.
The architecture follows MinIO's (encryption in the API layer, reserved
internal metadata keys, a sealed plaintext ETag, per-part keys); the byte
format is NanoIO's own (section 4) and is not compatible with MinIO's DARE.

## Decisions taken

These were settled with the maintainer before this document was written.

| # | Question | Decision |
|---|----------|----------|
| 1 | Remote KMS | KES over HTTP, plus the `local` backend. No Vault Transit. |
| 2 | Chunk size | 64 KiB of plaintext per AES-256-GCM chunk. |
| 3 | Extra scope | Bucket default encryption, range GET, versioned objects, heal/drain/object-lock interop. |
| 4 | Layer, metadata, ETag, no-KMS | "Exactly like MinIO": API layer; reserved `UserDefined` keys; plaintext MD5 sealed in metadata; 501 when no KMS is configured. |
| 5 | Copy | MinIO's rule: only **self-copy** re-wraps without data I/O. Copy to a different object decrypts and re-encrypts the stream. |
| 6 | Format | Same architecture, NanoIO's own bytes. |
| 7 | Missing CopyObject | Build `UpdateObjectMetadata` in fs, xl and cluster, and the API `CopyObject`, as part of this phase. |
| 8 | SSE-C and TLS | Refuse SSE-C over a non-TLS connection unless `allowInsecureSSEC` is set. |
| 9 | KEK rotation | Versioned KEKs; `nanoio admin rewrap` sweeps stored objects to the newest version without touching data. |

### Deviations from the request, and why

* **Cross-object CopyObject re-reads the object** (decision 5). The request
  said CopyObject must not re-read; with MinIO's rule that holds only for
  self-copy, which is also the only case where the key context
  (bucket/object) is unchanged. Section 10 explains the one case where a
  cross-object re-wrap would be *possible*, and why it was not chosen.
* **The KMS data key is not the object key.** The request describes one DEK
  wrapped by a KEK. MinIO (and this design) add one indirection: the KMS
  produces a *data key* `D`; a random per-object *object key* `OK` is sealed
  under `D`. `OK` is the DEK of the request; `D` is wrapped by the KEK. The
  indirection lets SSE-C use the identical sealing code with the client's key
  in place of `D`, and binds the sealed key to the object's path (section 3).
* **A self-copy in a versioned bucket updates the version in place** instead
  of creating a new version (MinIO's behaviour for metadata-only copies; AWS
  creates a new version). A new version would have to share the old
  version's data directory, which xl's garbage collection does not support.

## 0. What exists today, and what this phase must add first

* `StorageAPI` declares `CopyObject` and `UpdateObjectMetadata`, but **every
  backend returns `ErrNotImplemented`** (fs, xl, cluster) and the API answers
  `x-amz-copy-source` on a plain PUT with 501. The request's "CopyObject
  re-wraps the DEK" and "rotation without re-encryption" both need a
  metadata-only update primitive that does not exist. Section 10 specifies it.
* There is no TLS on the S3 listener outside cluster mode, so SSE-C (which
  puts the key in a header) needs the gate of section 6.3.
* `?encryption` is in the unimplemented-bucket-subresource list.
* Part boundaries of a finished object are already persisted
  (`meta.Version.Parts[]{N, Size, ETag}`, with the *uploaded* part numbers),
  and readers seek (`io.Seeker`) on the object's logical byte stream, which
  the format of section 4 relies on.
* Drain moves a multipart object as a *single* part (TODO.md). That destroys
  the part layout this format needs; section 14 changes drain to preserve it.

## 1. Where encryption sits

```
 client ──TLS──> api (parse SSE headers, authorise, encrypt/decrypt streams)
                   │  plaintext never leaves this layer
                   ▼
              kms client (internal/kms)  ◄──► KES / local key file
                   │
 StorageAPI ◄──────┘  stores *ciphertext* + opaque metadata
   fs │ xl (erasure code, bitrot hash) │ cluster (placement, heal, drain)
```

`internal/sse` (stream format, sealing, layout arithmetic) is a leaf package
over the standard library and `internal/kms`; `internal/api` is the only
package that calls it. **The storage backends never see plaintext and never
hold a key**: for them an encrypted object is an ordinary object whose
`UserDefined` has some reserved keys. Heal, scan, drain, listing and the
cluster ring therefore work unchanged, and an fs backend gets SSE for free.

## 2. Terms

| Name | What it is |
|------|-----------|
| KEK | Key-encryption key; lives in the KMS (`local` file or KES), never in object metadata. Versioned. |
| `D` | 32-byte data key from `KMS.GenerateKey`. SSE-C: the client's 32-byte key. Never stored in the clear. |
| `W` | `D` wrapped by the KEK (KMS ciphertext, opaque, self-describing as to KEK version). |
| `OK` | The object key (DEK): 32 random bytes per object (per multipart *upload*), generated by the server. |
| `SK` | Sealing key, derived per object from `D`. |
| `K_p` | Part key, derived from `OK` and the part number. |
| `K_s` | Stream key, derived from `K_p` and a random per-stream salt. |

## 3. Key hierarchy and sealing

```
KMS KEK (versioned) ──wraps──> D (random, per object) ──derives──> SK
                                                                   │ AES-256-GCM
                              OK (random, per object) <──sealed────┘
OK ──HMAC(part no.)──> K_p ──HMAC(salt)──> K_s ──AES-256-GCM, 64 KiB chunks──> ciphertext
```

Sealing (`internal/sse/seal.go`), identical for the three modes:

```
iv      = 32 random bytes                      (stored)
SK      = HMAC-SHA256(D, iv || "nanoio-sse-v1/seal" || mode || bucket "/" object)
sealed  = nonce(12 random) || AES-256-GCM(SK, nonce, OK, aad = "nanoio-sse-v1/seal" || mode || bucket "/" object)
```

* Binding the path and the mode into both the key derivation and the AAD
  means that **moving** an object's data and metadata to another key (or
  presenting an SSE-S3 object as SSE-C) fails authentication instead of
  decrypting. A disk-level attacker cannot swap object A over object B.
* `sealed` carries a GCM tag, so unsealing with the wrong `D` fails
  authentication. That is how SSE-C's "wrong key" is detected; **nothing
  derived from the client key, not even its MD5, is persisted**.
* `mode` is `s3`, `kms` or `c`.

Per-part and per-stream keys:

```
K_p = HMAC-SHA256(OK, "nanoio-sse-v1/part"   || be32(partNumber))
K_s = HMAC-SHA256(K_p, "nanoio-sse-v1/stream" || salt16)
```

A single-part object is part number 1. Re-uploading a part number draws a new
salt, so a key and a nonce never repeat even though `K_p` does.

## 4. Stream format (per part)

```
part ciphertext = salt (16) || chunk_0 || chunk_1 || ... || chunk_{n-1}
chunk_i         = AES-256-GCM(K_s, nonce_i, plaintext_i, aad_i)   (len(plaintext_i) + 16)
```

| Item | Value |
|------|-------|
| Plaintext chunk | 65,536 bytes; only the last chunk may be shorter, and is never empty unless the part is empty |
| Tag | 16 bytes, appended by GCM |
| Nonce `nonce_i` | 12 bytes: `0x00000000 || be64(i)`. Safe because `K_s` is unique per stream (random salt), so the counter never repeats under one key |
| AAD `aad_i` | `"nanoio-sse-v1/chunk" || final`, `final` = 0x01 for the last chunk and 0x00 otherwise |
| Empty part | one chunk holding zero bytes (a bare tag), so an empty object is still authenticated |

Properties:

* **Reordering** a chunk changes its index, hence its nonce: authentication
  fails. **Truncation** at a chunk boundary makes the new last chunk carry
  `final = 0x00`: authentication fails. **Appending** chunks fails because
  the old last chunk was sealed `final = 0x01`.
* **Size arithmetic is closed-form**, so plaintext size, ciphertext size and
  the offset of any plaintext byte need no stored table:

  ```
  n          = max(1, ceil(plain / 65536))
  cipherSize = 16 + plain + 16 * n
  plain      = cipherSize - 16 - 16 * n,  n = ceil((cipherSize - 16) / 65552)
  ```

  A ciphertext size for which `n` would be 0, or the last chunk would be
  shorter than a tag, is corruption.
* A GET with a range reads only the chunks that cover it (section 13).
* Overhead: 16 bytes per part plus 16 bytes per 64 KiB, about 0.024%.

An object's ciphertext is the concatenation of its parts' streams, in
ascending part-number order, which is exactly what storage already persists.

## 5. Metadata (reserved keys in `Version.UserMeta`)

Reserved names live in `ObjectInfo.UserDefined` under the prefix
`x-nanoio-internal-sse-`. User metadata is always `x-amz-meta-*`, so the
namespaces cannot collide, and `objectHeaders` already emits only
`x-amz-meta-*` and the system headers, so **the keys are never returned to
clients**. The API additionally refuses any inbound header that begins with
the reserved prefix.

| Key | Present for | Value |
|-----|-------------|-------|
| `...-mode` | all | `s3`, `kms` or `c` |
| `...-algo` | all | `AES-256-GCM-64K-v1` (format and chunk size, so the chunk size can change later) |
| `...-iv` | all | base64 of the 32-byte `iv` |
| `...-sealed-key` | all | base64 of `sealed` |
| `...-kms-key-id` | s3, kms | KMS key name used to wrap `D` |
| `...-kms-key-version` | s3, kms | KEK version `W` was wrapped under (0 if the KMS does not expose versions) |
| `...-kms-wrapped` | s3, kms | base64 of `W` |
| `...-kms-context` | kms | base64 of the client's JSON encryption context (the path entry is added at use time, not stored) |
| `...-etag` | single-part PutObject | base64 of the sealed plaintext MD5 (section 12) |

`xl.meta` is JSON; `UserMeta` is replicated to every drive with the rest of
the version record, so the wrapped DEK lives wherever the object's metadata
quorum lives. The reserved keys are persisted through every path that copies
`UserDefined`: put, multipart create/complete, heal (republishes the whole
version list), drain (section 14) and `UpdateObjectMetadata`.

## 6. The three modes

### 6.1 SSE-S3

Request: `x-amz-server-side-encryption: AES256`.

* Server calls `KMS.GenerateKey(defaultKey, ctx)` where
  `ctx = {"aws:s3:arn": "arn:aws:s3:::bucket/object"}`, seals `OK` under the
  returned `D`, stores `W`.
* Response (PUT/COPY/GET/HEAD/multipart create): `x-amz-server-side-encryption: AES256`
  and, MinIO-style, `x-amz-server-side-encryption-aws-kms-key-id:
  arn:aws:kms:<key id>`.

### 6.2 SSE-KMS

Request: `x-amz-server-side-encryption: aws:kms`,
`x-amz-server-side-encryption-aws-kms-key-id: <key>` (optional; the default
key if absent), `x-amz-server-side-encryption-context: <base64 JSON>`
(optional).

* The context is a JSON object of string pairs. It is passed to the KMS as
  AAD together with the path entry; **a wrong or missing context fails
  `Decrypt`**, so the context is authenticated and is the caller's to repeat
  only if it is not stored. NanoIO stores it (as AWS and MinIO do) so a GET
  does not need it.
* A client entry named `aws:s3:arn` that does not match the object's ARN is
  rejected (400 `InvalidArgument`).
* Response: `x-amz-server-side-encryption: aws:kms`,
  `...-aws-kms-key-id: arn:aws:kms:<key id>`,
  `...-context: <base64 JSON>` (the client's context).

### 6.3 SSE-C

Request, on **every** request that touches the object's data
(PutObject, CreateMultipartUpload and every UploadPart, GET, HEAD,
CopyObject source and destination, UploadPartCopy source and destination):

```
x-amz-server-side-encryption-customer-algorithm: AES256
x-amz-server-side-encryption-customer-key:       base64(32 bytes)
x-amz-server-side-encryption-customer-key-MD5:   base64(MD5(key))
```

Copy sources use the same three names prefixed
`x-amz-copy-source-server-side-encryption-customer-`.

| Condition | Result |
|-----------|--------|
| Connection is not TLS and `allowInsecureSSEC` is false | 400 `InvalidRequest` (MinIO's `InsecureSSECustomerRequest`) |
| Only some of the three headers present | 400 `InvalidArgument` |
| Algorithm is not `AES256` | 400 `InvalidArgument` |
| Key is not valid base64 or not 32 bytes | 400 `InvalidArgument` |
| MD5 does not match | 400 `InvalidArgument` ("The calculated MD5 hash of the key did not match the hash that was provided.") |
| GET/HEAD/COPY of an SSE-C object with the wrong key (unseal fails) | **403 `AccessDenied`** |
| GET/HEAD of an SSE-C object with no key headers | 400 `InvalidRequest` |
| SSE-C headers on an object that is not SSE-C | 400 `InvalidRequest` |
| `x-amz-server-side-encryption` on GET/HEAD | 400 `InvalidArgument` |
| UploadPart without the upload's SSE-C headers, or with a different key | 400 / 403 as above (the key is verified against the sealed key stored with the upload, so a different key can never produce a part that does not decrypt) |

`D` is the client's key; the server holds it for the duration of the request
only, and it is zeroed afterwards (best effort in Go). It is never logged,
never put in an error, and never sent to the KMS.

SSE-C needs no KMS, so it works when none is configured. Response headers
echo `...-customer-algorithm` and `...-customer-key-MD5`.

### 6.4 When no mode is requested

If the bucket has default encryption (section 15) it applies. Otherwise the
object is stored in the clear, exactly as before this phase.

## 7. KMS abstraction (`internal/kms`)

```go
type KMS interface {
    // GenerateKey returns a fresh 32-byte data key under the latest version
    // of keyID, and that key wrapped for storage. ctx is authenticated.
    GenerateKey(ctx context.Context, keyID string, encCtx Context) (DataKey, error)
    // Encrypt wraps plaintext (a data key) under the latest version of keyID.
    Encrypt(ctx context.Context, keyID string, plaintext []byte, encCtx Context) (Wrapped, error)
    // Decrypt unwraps ciphertext with whichever version produced it.
    Decrypt(ctx context.Context, keyID string, wrapped []byte, encCtx Context) ([]byte, error)
    DescribeKey(ctx context.Context, keyID string) (KeyInfo, error)
}
```

`DataKey{KeyID, Version, Plaintext, Ciphertext}`, `KeyInfo{ID, LatestVersion,
Created}`. Sentinel errors: `ErrKeyNotFound`, `ErrDecrypt` (wrong context,
tampered or wrong key: *not* retried), `ErrUnavailable` (transport/5xx:
retryable, surfaced as 503).

Backends:

* **`local`** (dev): a JSON key file (`{"keys": {"name": [{"version": 1,
  "key": "<base64 32B>"}, ...]}}`, mode 0600 enforced) or the environment
  (`NANOIO_KMS_SECRET_KEY=name:base64`, MinIO's convention, version 1).
  `GenerateKey` and `Encrypt` seal with the *highest* version using
  AES-256-GCM, AAD = canonical JSON of the context, and prefix the result with
  the 4-byte version, so `Decrypt` picks the right key. Adding a new version
  line to the file is the rotation.
* **`kes`**: KES's REST API over HTTPS (mTLS client certificate or API key):
  `POST /v1/key/generate/<name>`, `/v1/key/encrypt/<name>`,
  `/v1/key/decrypt/<name>`, `GET /v1/key/describe/<name>`, context sent as
  base64 JSON. Rotation is whatever the KES keystore does; `Version` is taken
  from the describe response when present, else 0.

Cache (`internal/kms/cache.go`, a decorator over any `KMS`):

* Caches **only `Decrypt` results** (and `DescribeKey`), keyed by
  `sha256(keyID || wrapped || canonical context)`; `GenerateKey` and `Encrypt`
  always go to the KMS because they must produce fresh/new-version output.
* TTL (default 5 min) and a size cap (default 10,000 entries, LRU); an entry
  is zeroed on eviction. Concurrent misses on one key share one KMS call.
* Errors (including `ErrKeyNotFound`) are **not** cached, so a key created
  after a miss becomes usable immediately and a revoked key stops working at
  most one TTL later.
* A cached plaintext `D` is data-key material in process memory; the TTL
  bounds the window. `cacheTTL: 0` disables caching.

## 8. Erasure coding interaction (explicit)

> **Encryption happens before erasure coding on write, and decryption happens
> after reconstruction on read. Bitrot hashes are computed over ciphertext.**

Write: `plaintext → [api] encrypt → ciphertext → [xl] split into K data
shards, Reed-Solomon parity M, SHA-256 per block of each shard → drives`.
Read: `drives → verify per-block SHA-256 → reconstruct missing shards →
ciphertext → [api] decrypt → plaintext`.

Consequences, all deliberate:

* xl, its bitrot hashes, heal (shallow and deep), scan and `Erasure.Checksums`
  see only ciphertext, so **healing never needs a key** and never holds
  plaintext, and a corrupted shard is detected and repaired by xl *before*
  GCM would have to fail on it. GCM authentication is a second, independent
  layer, and the only one that detects tampering that recomputes a block
  hash (xl's hashes are unkeyed).
* Parity shards of an encrypted object are functions of ciphertext, so they
  reveal nothing a data shard does not.
* Object `Size` in storage is the ciphertext size; the API converts to
  plaintext size using section 4's arithmetic (section 12).
* Compression, if ever added, must sit before encryption; it is not
  implemented.

## 9. Multipart

* `CreateMultipartUpload` with an SSE mode: generate `OK`, seal it, and store
  the reserved keys in the upload's `UserDefined`. They become the final
  object's keys at completion with no further work.
* `UploadPart`: the API reads the upload's metadata (`ListObjectParts` is
  extended to return the upload's `UserDefined`), unseals `OK` (SSE-C: with
  the request's key, mismatch is 403; KMS modes: KMS `Decrypt`, cached),
  derives `K_p` for the part number, and encrypts the part as its own stream.
  The part's stored ETag is the MD5 of its ciphertext and is what `UploadPart`
  and `ListParts` return and `CompleteMultipartUpload` matches.
* A part's plaintext size is derived from its stored size (section 4).
* `CompleteMultipartUpload`: S3 requires every part but the last to be at
  least 5 MiB. Storage checks the *ciphertext* size, which is always
  at least the plaintext size, so storage can only be more lenient than S3;
  the API therefore enforces the plaintext minimum itself for encrypted
  uploads (`EntityTooSmall`) before calling storage. The composite ETag is
  computed by storage from the parts' ciphertext MD5s.
* `UploadPartCopy` decrypts the source range and encrypts it as a new part
  of the destination upload, as any other part.

## 10. CopyObject, UploadPartCopy and the metadata update primitive

### 10.1 `UpdateObjectMetadata` (new, all backends)

`StorageAPI.UpdateObjectMetadata(bucket, object, UpdateMetaOptions)` replaces
one version's `UserDefined` (and, if set, content type), **in place**. It:

* takes the locks a delete takes (bucket shared, key exclusive);
* judges nothing about object lock (metadata is not data: an object lock
  protects removal and replacement of the version, which this is not);
* is a generation-conditional commit (`OpSetMeta`, modelled on `OpSetLock`),
  applied by every drive to its own `xl.meta`, with write quorum;
* never touches a data directory, so data files are byte-identical before and
  after (a test hashes them);
* optionally refreshes `ModTime` (`Touch`), because an S3 self-copy changes
  Last-Modified while an internal re-wrap must not;
* keeps ETag, size, parts and lock.

### 10.2 `CopyObject` (API)

| Source → destination | Data I/O | What happens |
|----------------------|----------|--------------|
| plain → plain, different key | stream | storage `CopyObject`-equivalent: GET then PUT (metadata COPY or REPLACE) |
| any → different key | stream | decrypt source (source key headers for SSE-C), encrypt per destination mode with a fresh `OK`; the destination's path is its context |
| encrypted → **same** key, mode and/or key change | **none** | unseal `OK` with the source credentials, seal it under the destination mode (new `D`/`W`, or new SSE-C key), `UpdateObjectMetadata` |
| encrypted → same key, metadata REPLACE only | none | `UpdateObjectMetadata` with the new content type/headers and the existing reserved keys |
| plain → same key + SSE, or encrypted → same key without SSE | stream | must write a new representation; replaces the object (or creates the new version) |

Why a cross-object copy is not a re-wrap: `OK` and the ciphertext do not
depend on the path, so re-sealing `OK` for another key *would* work and
would allow sharing or copying ciphertext without decrypting. It was not
chosen because (a) the request settled on MinIO's rule, and (b) two objects
sharing one `OK` weakens the per-object key guarantee that makes a single
leaked `OK` cost one object. The single-file wire copy of ciphertext is
left as a possible later optimisation.

Self-copy with nothing to change is `InvalidRequest` (as in S3). The
`x-amz-copy-source-if-*` conditions and `x-amz-copy-source-version-id` apply
to the source.

## 11. KEK rotation without re-encrypting data

Rotation is a change of the *KEK version*, never of `OK` or the data.

* Operators rotate in the KMS: a new version line in the `local` key file, or
  a KES rotation. New writes immediately use the latest version; existing
  objects keep decrypting because `W` names (self-describes) its version.
* `nanoio admin rewrap` (and the same code path as self-copy) walks every
  object version carrying `...-kms-wrapped`, compares `...-kms-key-version`
  with `DescribeKey().LatestVersion` (and `...-kms-key-id` with the
  configured default for SSE-S3), and for each stale one:

  ```
  D  = KMS.Decrypt(keyID, W, ctx)
  W' = KMS.Encrypt(keyID', D, ctx)
  UpdateObjectMetadata(replace: kms-wrapped = W', kms-key-version = v')
  ```

  `sealed-key`, `iv` and every data byte are unchanged. A test hashes the
  data directory before and after.
* Progress and failures are reported; the sweep is idempotent and resumable;
  a failed object is left on its old (still decryptable) wrap.
* SSE-C has no server-side KEK: a client rotates its key with a self-copy
  carrying `...-copy-source-...-customer-*` (old) and `...-customer-*` (new)
  headers.
* The old KEK version must stay in the KMS until a sweep has finished; the
  sweep reports how many objects remain on each version so an operator can
  tell.

## 12. ETag, size and listing

* Single-part PutObject: the API hashes the **plaintext** with MD5 while
  streaming. The backend's `PutOptions.Finalize` hook (new) runs after the
  body is read and before commit and adds
  `...-etag = seal(MD5, key = OK, aad = path)`. The stored ETag field is the
  MD5 of the ciphertext, so a disk reader learns no plaintext hash. GET, HEAD
  and the PUT response return the unsealed plaintext MD5, as MinIO does.
  `If-Match`/`If-None-Match` accept either value.
* Multipart: ETag is the composite of ciphertext part MD5s, as stored and as
  returned everywhere. No plaintext hash exists on disk or on the wire.
* **ListObjects/ListObjectVersions return the stored (ciphertext) ETag** for
  encrypted single-part objects, so a list ETag differs from the GET ETag of
  the same object. Unsealing would need one KMS call per listed object.
  Documented limitation (MinIO has the same discrepancy class; AWS never
  returns an MD5 for SSE-KMS/SSE-C either).
* Listing and HEAD report plaintext `Size`, from section 4's arithmetic over
  the stored size and, for multipart, over each stored part.
* `Content-MD5` and `x-amz-content-sha256` are verified by the API over the
  plaintext (the backend is given neither, since it would see ciphertext).

## 13. Range GET

The API opens the object once (a snapshot, as today), maps the plaintext range
`[a, b)` to chunks `c_first..c_last` within each involved part, `Seek`s the
reader to each part's 16-byte salt and then to the first chunk, and decrypts
only those chunks. The first and last chunk are trimmed. Cost is at most two
extra chunks (128 KiB) read per range plus 16 bytes per part crossed. A
reader without `io.Seeker` falls back to discarding, as the plain path does.
Integrity: every chunk read is authenticated; a failure after headers are
written cuts the connection (existing truncated-body behaviour) and is logged.

## 14. Versioning, object lock, heal, drain

* **Versioning.** Each version is an independent object with its own
  `UserMeta`, hence its own `OK`. A new version of an encrypted key may use a
  different mode. Version IDs are not part of the sealing context, so a
  version is portable to the same key (necessary for in-place metadata
  updates). Delete markers carry no encryption.
* **Object lock.** Retention and legal hold are unaffected: the data and
  its version identity do not change. `UpdateObjectMetadata` is allowed on a
  locked version (section 10.1) and preserves its `Lock`.
* **Heal.** Rebuilds ciphertext shards from ciphertext shards; metadata is
  republished with `UserMeta` intact. No key and no KMS are needed, and the
  KMS being down never blocks heal.
* **Drain.** Cluster drain moved a multipart object as one part, which would
  make it undecryptable (part salts live inside the stream; the layout comes
  from `Parts`). Drain is changed to move a multi-part object with
  `NewMultipartUpload` + one `PutObjectPart` per source part (same numbers,
  same ciphertext) + `CompleteMultipartUpload`, which also preserves the
  multipart ETag, a pre-existing drain limitation. Single-part objects are
  copied as today; `UserDefined` (with the reserved keys) is passed through.
* **Bucket default encryption** does not re-encrypt existing objects.

## 15. Bucket default encryption

`PUT/GET/DELETE /bucket?encryption` with the S3
`ServerSideEncryptionConfiguration` XML (one rule;
`SSEAlgorithm` `AES256` or `aws:kms`, optional `KMSMasterKeyID`;
`BucketKeyEnabled` is accepted and ignored). Persisted in the bucket marker
next to versioning and object lock (new `encryption` document and sequence,
reconciled across drives and sets the same way). A PUT/multipart-create to
that bucket with no SSE header applies it. SSE-C headers always win. A
bucket config naming `aws:kms` with a key the KMS does not know is rejected
at PUT. Without a KMS the PUT is 501 (decision 4). `GET` of an unconfigured
bucket is 404 `ServerSideEncryptionConfigurationNotFoundError`.
IAM actions: `s3:PutEncryptionConfiguration`, `s3:GetEncryptionConfiguration`.

## 16. Configuration

```json
"kms": {
  "backend": "local",            // "" (none), "local" or "kes"
  "defaultKey": "nanoio-default", // SSE-S3 key; default for SSE-KMS without key id
  "cacheTTL": "5m",
  "cacheSize": 10000,
  "local": { "keyFile": "/etc/nanoio/kms.keys" },
  "kes":   { "endpoint": "https://kes:7373", "apiKey": "", "clientCert": "", "clientKey": "", "ca": "" }
},
"allowInsecureSSEC": false
```

Environment: `NANOIO_KMS_BACKEND`, `NANOIO_KMS_DEFAULT_KEY`,
`NANOIO_KMS_SECRET_KEY` (`name:base64`), `NANOIO_KMS_LOCAL_KEY_FILE`,
`NANOIO_KMS_KES_ENDPOINT`, `NANOIO_KMS_KES_API_KEY`,
`NANOIO_KMS_KES_CLIENT_CERT`, `NANOIO_KMS_KES_CLIENT_KEY`,
`NANOIO_KMS_KES_CA`, `NANOIO_ALLOW_INSECURE_SSEC`. Secrets prefer the
environment (the config loader already warns on world-readable files). The
`defaultKey` must exist in the KMS at startup (`DescribeKey`) or the server
refuses to start, so a typo cannot silently produce unencryptable PUTs.

## 17. Errors

| Condition | HTTP | Code |
|-----------|------|------|
| SSE-S3/KMS requested, no KMS configured | 501 | `NotImplemented` ("Server side encryption specified but KMS is not configured") |
| Unknown KMS key | 400 | `KMS.NotFoundException` |
| KMS unreachable / 5xx | 503 | `ServiceUnavailable` |
| `x-amz-server-side-encryption` value not `AES256` / `aws:kms` | 400 | `InvalidArgument` |
| Context not base64 JSON of string pairs, or > 8 KiB | 400 | `InvalidArgument` |
| SSE-C cases | see 6.3 | |
| Unsealing fails for a KMS mode (tampered metadata, wrong context) | 500 | `InternalError`, logged with the object name, never the key |
| Chunk authentication fails mid-stream | connection aborted | logged |
| Encrypted-object operation unsupported (e.g. `x-amz-tagging`) | unchanged | |

All new codes are added to the exhaustiveness test over `storage.AllErrors()`
where they correspond to storage sentinels.

## 18. Implementation order and tests

1. `internal/kms`: interface, `local`, `kes`, cache. Tests: round trip,
   context mismatch, version rotation, cache TTL/eviction/single-flight,
   `kes` against an `httptest` fake that enforces the documented request shape.
2. `internal/sse`: sealing, stream encrypt/decrypt, layout arithmetic. Tests:
   round trip over sizes {0, 1, 65535, 65536, 65537, 1 MiB±1}, truncation,
   reorder, tamper, wrong key, range decryption against full decryption,
   size arithmetic property test, fuzz.
3. `UpdateObjectMetadata` in fs, xl (+ `disk` op, remote RPC), cluster, with
   the shared `storagetest` conformance cases (data bytes unchanged, versions,
   conflict with concurrent put, heal after a stale drive).
4. Bucket encryption config persistence (fs, xl/disk, cluster reconcile).
5. Drain preserves parts.
6. API: parsing and gating; PUT/GET/HEAD/range; multipart; CopyObject and
   UploadPartCopy; bucket `?encryption`; admin rewrap; startup wiring.
7. Cross-cutting tests (api, over HTTP, fs and xl 4-layout and cluster):
   round trip each mode; wrong key 403, MD5 mismatch 400; SSE-C multipart
   (missing/different key per part); CopyObject matrix between modes
   including self-copy with an assertion that no data file changed; KEK
   rotation with `rewrap` and the data-hash assertion; ranges; versioned
   bucket; heal of a damaged encrypted object; drain of an encrypted
   multipart object; stolen-disk test (section 19).

## 19. Threat model

Assets: object contents, user metadata values (not encrypted: see below),
keys. Attackers considered, with the capabilities *given*:

**A. Steals or images one or more drives, or reads backups of them.**
(Offline; no process memory, no network.)

| Mode | Attacker gets | Cannot get |
|------|---------------|-----------|
| none | everything | |
| SSE-S3 | Object ciphertext; `xl.meta` incl. `W`, `sealed-key`, `iv`, key ID, sizes (plaintext size derivable), content type, `x-amz-meta-*`, timestamps, key names | Contents: needs `D`, which needs the KMS (or its key file/secret). **If the `local` key file/env secret was on the same disk, they get it and all SSE-S3/SSE-KMS objects are readable**; that is why `local` is "for dev" |
| SSE-KMS | As SSE-S3, plus the client context | Contents: needs the KMS and the exact context |
| SSE-C | Ciphertext, `sealed-key`, `iv`, sizes, metadata | Contents: needs the client key, which is never stored (a **guessable** key is brute-forceable offline against `sealed-key`, which is a GCM tag oracle: clients must use 256 random bits) |

In every mode the attacker also sees: object names (paths), bucket names,
which objects are encrypted and in which mode, sizes within 16 bytes per
chunk, ETag of ciphertext (not plaintext), and **user metadata and system
headers in the clear** (`x-amz-meta-*`, `Content-Type`). Do not put secrets
in object metadata. Part-size patterns and exact lengths are visible.

**B. Same, but also holds the cluster secret / a node's disk with config.**
Same as A: the cluster secret authenticates RPC, it is not a key for data.
With KES/mTLS credentials present on the stolen disk the attacker can call the
KMS as the server would; protect those credentials like the KEK (this is the
standard KES caveat).

**C. Tampers with the disk (write access, offline).**
* Flips bits in a shard: caught by xl's block hash (unkeyed) and repaired
  from parity; if both data and hash are rewritten consistently, GCM
  authentication fails the read. Never silently decrypts to wrong data.
* Swaps object A's files over object B's: fails, because the sealed key is
  bound to B's path (section 3).
* Rolls an object back to an older version of itself with consistent
  metadata: **not detected** (no global version authentication). Out of
  scope.
* Truncates/reorders/duplicates chunks: fails (section 4).
* Replaces `W` with a `W` of an attacker-chosen key in a KMS they control:
  needs KMS access; then `sealed-key` still fails to unseal.

**D. Network observer between client and server.** SSE-S3/SSE-KMS rely on
TLS for confidentiality in transit (as before this phase). SSE-C sends the
key on the wire: hence the TLS gate; with `allowInsecureSSEC` set, the key is
visible to any on-path observer.

**E. Compromised running server (process memory, KMS credentials).** Not
defended. The server holds `D`/`OK` of in-flight and cached objects and can
call the KMS. Encryption at rest does not protect against a root-compromised
node.

**F. Malicious or curious operator with S3 admin but no disk or KMS.** SSE-S3
and SSE-KMS objects are transparent to anyone IAM allows to GET them
(encryption at rest is not access control). SSE-C objects are not readable by
the operator without the client's key.

**G. Lost KMS key.** All SSE-S3/SSE-KMS objects wrapped under it are
unrecoverable. Back up the key file (or the KES store). The `kms-key-version`
accounting in `rewrap` reports which versions are still referenced.

Non-goals: hiding object names, sizes or access patterns; encrypting user
metadata; protecting against a compromised server; replay/rollback
protection; post-quantum.

## 20. Not solved (mirrored in TODO.md)

* No Vault Transit backend.
* ListObjects ETags of encrypted single-part objects differ from GET's.
* `rewrap` walks every version of every key: O(objects) KMS calls; no
  incremental or scheduled mode.
* A self-copy in a versioned bucket updates in place (deviates from AWS).
* Cross-object copy of an encrypted object always re-reads and re-encrypts.
* `x-amz-checksum-*` over encrypted payloads is still not verified.
* Decrypted objects are not cached; every GET performs a (cached) KMS
  decrypt.
* No per-bucket KMS key *policy* (any caller allowed to PUT may name any
  existing KMS key); KES policy is the control.

## 21. Implementation notes and deviations

Where the code differs from sections 1-20, or settles something they left
open. Everything else was built as written.

* **Bucket default encryption is not in the bucket marker** (section 15). It
  is a JSON document stored as an ordinary object,
  `nanoio-sys-config/<bucket>/encryption`, so it inherits quorum, healing and
  cluster placement without a new drive operation. The API treats that bucket
  as nonexistent (404; `PUT` is `InvalidBucketName`; hidden from
  `ListBuckets`), removes a bucket's document on `DeleteBucket` and again on
  `CreateBucket`, and caches reads for 5 s (a change through the same node is
  immediate). The name is reserved: an existing user bucket of that name
  would be unreachable through the API.
* **`StorageAPI.CopyObject` is still `ErrNotImplemented` everywhere.** The
  API composes CopyObject from `GetObject`, `PutObject` and
  `UpdateObjectMetadata`; the storage-level method was never needed.
* **`UpdateObjectMetadata` details** (section 10.1): nil `UserDefined` leaves
  the map alone and an empty non-nil map clears it (`MetaUpdate.ClearUserMeta`
  carries that across the RPC); `IfETag` makes the update conditional so a
  re-wrap computed for a version that was overwritten meanwhile cannot clobber
  its successor (without it, a concurrent PUT could be left with its
  predecessor's sealed key and become unreadable). It is a new commit op,
  `OpSetMeta`, appended after `OpSetLock`, so existing op numbers are
  unchanged.
* **`PutOptions.Finalize`** (section 12) is the hook that records the sealed
  plaintext MD5 after the body is read; it runs in fs and xl only for
  single-part `PutObject`.
* **`ListPartsResult.UserDefined`** (section 9) is how the API reads an
  upload's encryption description; each `UploadPart` therefore does one extra
  metadata read.
* **The encryption context entry** is `aws:s3:arn` = `arn:aws:s3:::bucket/key`
  (AWS's name); a client entry with that name and another value is rejected.
  A key id may be given as `arn:aws:kms:<id>`; responses use that form.
* **KES**: key versions are not exposed, so `DataKey.Version` is 0 and the
  rewrap sweep recognises staleness there only by a changed key name. The
  `DescribeKey` call uses `GET /v1/key/describe/<name>`; the generate,
  encrypt and decrypt calls follow the documented request shapes and are
  tested against a fake that enforces them, not against a real KES.
* **Rewrap is a root-authenticated HTTP endpoint**, `POST
  /_nanoio/admin/rewrap`, served by the S3 handler (action
  `nanoio:RewrapKeys`, which no policy can grant), and `nanoio admin rewrap`
  signs a request to it. It works for every backend, which the cluster-RPC
  admin channel (cluster mode only) would not.
* **Self-copy without encryption headers on an encrypted object** keeps the
  existing encryption (metadata REPLACE, or an error if nothing would
  change); it never silently decrypts. A cross-object copy without headers
  stores the destination in the clear unless the bucket has a default.
* **Reserved headers**: any inbound header starting with
  `x-nanoio-internal-sse-` is refused with 400.
* **Zeroing** of keys is best effort (Go gives no guarantee); the KMS cache
  zeroes entries on eviction.
* **Tests**: `internal/kms` and `internal/sse` unit tests (plus a fuzz target
  for the decrypter); `storagetest` cases for `UpdateObjectMetadata` and
  `Finalize` run on fs, xl (four layouts), distributed xl and cluster;
  `internal/api/sse_test.go` covers sections 6, 9, 10, 11, 13, 14 and 15 over
  HTTP on fs and on a 2+2 xl set, including shard corruption, a lost drive and
  deep heal; cluster tests cover part-preserving drain and decryption after
  a drain; `cmd/nanoio` tests cover start-up validation, a restart with the
  right and wrong master key, the SSE-C TLS gate and the rewrap command.
