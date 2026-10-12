# Phase 10: bucket configuration (policies, ACLs, CORS, tags, storage classes)

Status: **implemented**, as five independent sub-phases (10a-10e) on top of
Phases 3 and 9.

Decisions taken with the maintainer:

| # | Question | Decision |
|---|----------|----------|
| 1 | Where configuration documents live | The reserved bucket `nanoio-sys-config` (as bucket default encryption already did), one document per bucket per kind. No bucket-marker fields. |
| 2 | Anonymous requests | Evaluated against the bucket policy (and ACLs mapped to it); otherwise `AccessDenied` as before. Invalid credentials are never downgraded to anonymous. |
| 3 | Principals | `"*"`, `{"AWS": "..."}` with `arn:aws:iam::nanoio:user/<access key>`, `arn:aws:iam::nanoio:root` or a bare access key; wildcards allowed. Other accounts and principal types are rejected at PUT. |
| 4 | Custom storage classes | A config map name -> parity; data = drives - parity. |

## Where configuration is stored

`internal/api/bucketconf.go`. A document is the object `<bucket>/<kind>` in the
reserved bucket (kinds: `encryption`, `policy`, `acl`, `cors`, `tagging`), so
it inherits the backend's quorum, healing and cluster placement. The API never
serves that bucket (404; creating it is `InvalidBucketName`; hidden from
`ListBuckets`). Reads go through a 5 s cache (bounded to 10,000 entries, absent
documents cached too), so a change made on another node is seen within 5 s; a
change through the serving node is immediate. `DeleteBucket` and `CreateBucket`
both remove a bucket's documents, so a crash between deleting a bucket and its
documents cannot hand a new bucket the old one's policy.

Per-object data (ACL, tags) is not a document: it is a reserved key in the
object version's user metadata (`x-nanoio-internal-acl`,
`x-nanoio-internal-tags`), changed with `UpdateObjectMetadata` conditional on
the ETag. Every header in the `x-nanoio-internal-` namespace is refused from
clients, and none is ever returned.

## 10a Bucket policies

`PUT/GET/DELETE /bucket?policy`; actions `s3:PutBucketPolicy`,
`s3:GetBucketPolicy`, `s3:DeleteBucketPolicy`. The document is validated
strictly (`iam.ParseBucketPolicy`): `Version`, a `Principal` or `NotPrincipal`
in every statement, only `s3:` actions, `Resource` entries naming the bucket
or its objects (a policy cannot reach another bucket), the supported condition
operators, at most 20 KiB. Malformed is 400 `MalformedPolicy`; GET without a
policy is 404 `NoSuchBucketPolicy`; GET returns the document as submitted.

### Evaluation (`api.decide`)

```
deny  = explicit Deny in the caller's identity policies  OR  in the bucket policy
allow = explicit Allow in either  OR  an ACL grant (10b)
result = allow AND NOT deny           (default deny)
```

* Anonymous requests have no identity policy, so only the bucket policy and
  ACLs speak. A request that carries credentials which fail verification is
  rejected, never treated as anonymous.
* The root credential is subject to neither kind of policy (as before), so a
  bad bucket policy cannot lock the operator out. AWS applies explicit Denies
  to the account root; NanoIO deliberately does not.
* A failure to read the bucket's policy fails the request closed (503), never
  open.
* Condition keys supplied: `aws:SourceIp`, `aws:SecureTransport`,
  `aws:Referer`, `aws:UserAgent`, `s3:prefix`, `s3:delimiter`, `s3:max-keys`,
  `s3:x-amz-storage-class`, `s3:RequestObjectTag/<key>`,
  `s3:ExistingObjectTag/<key>` (read on demand, only when a statement asks).
  A key that is absent makes a positive operator false and a negated one
  true, as in AWS.
* Anonymous requests to features without a policy action (unimplemented
  subresources) and anonymous multi-object delete are `AccessDenied`.

## 10b ACLs

`GET/PUT ?acl` on buckets and objects (`?versionId=` supported);
`x-amz-acl` and `x-amz-grant-{read,write,read-acp,write-acp,full-control}` on
PUT object, CreateMultipartUpload, CopyObject and CreateBucket (which needs
`s3:PutObjectAcl` / `s3:PutBucketAcl` in addition, as in S3).

There is **no second authorisation path**: a bucket's or object's grants are
turned into policy statements (`iam.ACLStatements`) and evaluated by the same
engine in `decide`, last and only when nothing else has allowed (ACLs only add
Allows).

| Grant on a bucket | Allows |
|-------------------|--------|
| READ | `s3:ListBucket`, `ListBucketVersions`, `ListBucketMultipartUploads` |
| WRITE | `s3:PutObject`, `DeleteObject`, `DeleteObjectVersion`, `AbortMultipartUpload` on its objects |
| READ_ACP / WRITE_ACP | `s3:GetBucketAcl` / `s3:PutBucketAcl` |

| Grant on an object | Allows |
|--------------------|--------|
| READ | `s3:GetObject`, `GetObjectVersion` |
| READ_ACP / WRITE_ACP | `s3:GetObjectAcl` / `PutObjectAcl` (+ version forms) |

A bucket READ grant lists but does not expose objects; an object's grants
apply to that object only (literal match, so a key containing `*` or `?`
cannot widen its own grant). Canned ACLs: `private`, `public-read`,
`public-read-write`, `authenticated-read`. Grantees: a user by access key
(`CanonicalUser` ID), `AllUsers`, `AuthenticatedUsers`; e-mail grantees and
other groups are refused. A copy does not carry its source's ACL.

## 10c CORS

`PUT/GET/DELETE ?cors` (`s3:PutBucketCORS`, `s3:GetBucketCORS`). At most 100
rules; methods GET, PUT, POST, DELETE, HEAD; one `*` per origin and per
`AllowedHeader`; no wildcard in `ExposeHeader`.

* **Preflight** (`OPTIONS` with `Origin` and `Access-Control-Request-Method`)
  is answered before authentication, from the bucket's rules: the first rule
  whose origin, method and every requested header match answers with
  `Access-Control-Allow-Origin` (`*` when the rule's origin is `*`, otherwise
  the origin, with `Allow-Credentials: true`), `Allow-Methods`, `Allow-Headers`
  (the requested ones), `Max-Age`, `Expose-Headers` and `Vary`. No match, or
  no configuration, is 403 `AccessForbidden`.
* **Actual requests** with an `Origin` get `Allow-Origin`/`Expose-Headers`
  from the first rule matching origin and method, on every response
  including errors, plus `Vary: Origin` for any bucket with a configuration.

## 10d Tagging

* Object: `PUT/GET/DELETE /bucket/key?tagging[&versionId]`, the
  `x-amz-tagging` header on PUT, CreateMultipartUpload and CopyObject (with
  `x-amz-tagging-directive` COPY/REPLACE; COPY is the default), and
  `x-amz-tagging-count` on GET/HEAD for callers allowed `s3:GetObjectTagging`.
  Tags are per version. At most 10; keys 1-128 and values 0-256 characters of
  letters, digits, spaces and `+ - = . _ : / @`; no duplicates; no `aws:`
  prefix. `PUT` with the header needs `s3:PutObjectTagging` in addition.
* Bucket: `PUT/GET/DELETE /bucket?tagging`, at most 50; GET without tags is
  404 `NoSuchTagSet`.
* Condition keys for the policy engine: see 10a. `RequestObjectTagKeys` is not
  offered (it is only useful with `ForAllValues`, which the engine does not
  support).

## 10e Storage classes

`x-amz-storage-class` on PUT, CreateMultipartUpload and CopyObject;
`x-amz-storage-class` returned on GET/HEAD for non-STANDARD objects and the
class shown in listings.

* STANDARD is the set's own layout (`parity`). `REDUCED_REDUNDANCY` defaults
  to parity 1. Custom classes come from `storageClasses` in the config
  (`{"COLD": {"parity": 1}}`); data blocks = drives in the set - parity.
* **A class may be less redundant than STANDARD, never more.** An object's
  metadata is committed to and read from a quorum sized for the set's own
  layout, so an object that tolerated more lost drives than STANDARD could
  not be found once they were gone. Config is refused at startup otherwise.
* Each object records its own layout (`Erasure.DataBlocks/ParityBlocks`) and
  class; readers, heal and drain use the object's, so changing the class
  table never strands data. A write must reach `max(its own layout's quorum,
  the set's)` drives, so a REDUCED_REDUNDANCY write is refused when more
  drives are down than it could survive.
* `xl.meta` files with any class are written as **format 4**: a build that
  predates storage classes refuses them rather than treating a 7+1 object as
  damaged.
* The fs backend accepts only STANDARD (`InvalidStorageClass` otherwise).
  Self-copy with another class rewrites the object into that layout; without
  the header it keeps its class.
* Drain preserves the class.

## Tests

Each sub-phase has a table-driven authorisation test crossing principals,
actions, resources and conditions (`internal/api/policy_test.go`,
`acl_test.go`, `cors_test.go`, `tagging_test.go`, `storageclass_test.go`),
plus unit tests of the engine additions (`iam/bucketpolicy_test.go`) and the
xl layouts (`xl/storageclass_test.go`: geometry, fault tolerance, write
quorum, multipart, heal, restart with a different class table, config
validation).

## Not solved

See "Known limitations of bucket configuration" in TODO.md.
