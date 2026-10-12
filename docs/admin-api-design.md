# Admin API and identity federation (Phase 14)

Packages: `internal/api/madmin*.go`, `maintain.go`, `identity.go`, `sts.go`
(HTTP layer), `internal/madmincrypt` (admin envelope), `internal/identity/{oidc,ldap}`
(providers), `internal/iam` (resolver for temporary credentials),
`test/madmin-oracle` (separate Go module).

## 14a Admin API

`/minio/admin/v3/<op>` (and `/minio/kms/v1/<op>`, `/minio/health/*`) speak
MinIO's admin wire format, hand-implemented. `madmin-go` (AGPL-3.0) is used
**only** as a test oracle in `test/madmin-oracle`, a separate module that
drives a built `nanoio` binary; it is never linked into the server.

### Authentication and authorisation

* Every admin request must be SigV4-signed. There is no unauthenticated
  admin surface; the only open paths are the health probes
  (`/minio/health/live|ready|cluster`), which reveal nothing but status. A
  server running with `--insecure-no-auth` refuses admin requests outright.
* Authorisation is by policy action: each route names an `admin:<Action>`
  (or `kms:<Action>`); root passes, anyone else needs a policy that allows
  it. The canned `consoleAdmin` allows `admin:*`/`kms:*`; `diagnostics` is
  the read-only set. Policies for these actions may omit `Resource`.
* The admin SDK signs with an *empty* credential-scope region. The verifier
  accepts an empty region only under the paths listed in
  `auth.Verifier.RegionlessPrefixes` (`/minio/admin/`, `/minio/kms/`, and `/`
  for STS), never for S3.
* Sensitive request and response bodies use MinIO's envelope
  (`internal/madmincrypt`: Argon2id of the caller's secret key, then DARE
  with AES-256-GCM or ChaCha20-Poly1305). A body that does not authenticate
  is refused before it is parsed.

### What is implemented

| Area | Operations |
| --- | --- |
| Info | `info`, `storageinfo`, `datausageinfo` (counts of objects/versions are reported as 0: NanoIO keeps no usage index) |
| IAM | users (add/remove/list/info/status), groups, canned policies, user/group policy attach & detach, policy entities, service accounts (add/update/delete/list/info), access keys (info, bulk list), `export-iam`/`import-iam[-v2]` |
| Config | `get/set/del-config-kv`, `help-config-kv`, `config` (export/replace), history (list/restore/clear) |
| IDP | `idp-config/{openid,ldap}`, `idp/ldap/policy/{attach,detach}`, `idp/ldap/policy-entities`, LDAP access keys |
| Maintenance | `heal/<bucket>/<prefix>` (start, poll by token, stop), `background-heal/status`, `pools/{list,status,decommission,cancel}` |
| Tiers | `tier` (add/list), `tier/<name>` (edit credentials, verify, remove), `tier-stats` (zero counters) |
| KMS | `status`, `version`, `apis`, `key/status` (a real wrap/unwrap round trip), `key/list` (the default key) |
| Observability | `trace` (S3 and admin calls, NDJSON, headers redacted), `log` (console ring), `top/locks` (empty) |
| Bucket metadata | `export-bucket-metadata`, `import-bucket-metadata` |

### What is deliberately not implemented

These return a clear error (never a silent success):

* **Rebalance**: objects are placed by consistent hashing and move only on
  decommission. `rebalance status` reports "not started", `start` is 501.
* **Service restart/stop/freeze**: run NanoIO under a process manager.
* **Heal dry-run, remove, recreate, update-parity**: the healer cannot look
  at an object without repairing it.
* **Decommission** works only for a pool that is *configured* draining (see
  cluster operations); the API starts and cancels the drain.
* **KMS key create/delete/import and KES policies/identities**: NanoIO's KMS
  interface cannot enumerate or manage keys.
* **Scanner metrics stream, speedtest, site-replication through
  `mc admin replicate`**: site replication has its own routes (Phase 13).
* **Config**: only sub-systems that something reads are accepted
  (`identity_ldap`, `identity_openid`). A setting NanoIO would store and
  ignore is refused, so "set succeeded" means "in effect".
* **`export-iam` includes users' secret keys** in clear (as MinIO's does);
  it needs `admin:ExportIAM` and the archive must be handled as a secret.
* **Archive formats**: `export-iam` / `export-bucket-metadata` use MinIO's
  file names but NanoIO's JSON contents. They move between NanoIO servers,
  not between NanoIO and MinIO. Replication targets (which hold remote
  secrets) are not exported.

### Acceptance with `mc`

The official `mc` (RELEASE 2025-05) was run unmodified against the server:
`admin info`, `user add/list/info/enable/disable/remove`, `user svcacct`,
`accesskey`, `group`, `policy create/list/info/attach/detach/remove`,
`policy entities`, `config get/set/export/history/reset`, `idp openid|ldap`
(`add/ls/info/rm`, `policy entities`), `heal`, `decommission status`,
`rebalance status`, `tier ls`, `kms key status`, `cluster iam export`,
`cluster bucket export`, `prometheus generate`. Commands that need a TTY
(`scanner status`, `service restart`) cannot run non-interactively and were
not exercised.

## 14b Identity federation

### Temporary credentials

Temporary credentials (STS, `Kind: "sts"`) are **one document each** under
`_sts/` in the system bucket, not entries in the IAM store. Issuing one is a
single write and never rebuilds the store. `iam.Store.SetResolver` fetches
them lazily and caches each answer for a TTL (see below).

A temporary credential carries a random session token. Every request made
with it must present exactly that token in `X-Amz-Security-Token` (signed;
or in the presigned query). Without it, or with a wrong one, the request
fails with `InvalidToken`. A credential's lifetime is 15 minutes to 12 hours
(default 1 h) and never exceeds the web identity token it came from.

Permission model: a credential acts through its own attached policies
(OIDC claim, LDAP mapping) or, for `AssumeRole`, as its parent user; a
session policy (`Policy` parameter, at most 2048 characters) can only
narrow, never widen. Derived credentials (service accounts, temporary
credentials) cannot call `AssumeRole`.

### STS actions (`POST /`)

| Action | Authentication |
| --- | --- |
| `AssumeRole` | SigV4 (service `sts` or `s3`) by a long-lived user |
| `GetCallerIdentity` | SigV4 |
| `AssumeRoleWithWebIdentity` | the OIDC ID token in the request |
| `AssumeRoleWithLDAPIdentity` | LDAP username and password in the request |

### OpenID Connect (`identity_openid`)

* Discovery document and JWKS are fetched from `config_url` (`https`, or
  `http` for loopback only). The key set is cached for an hour and refetched
  on an unknown `kid`, but never more often than every 10 s, so a flood of
  tokens with made-up key IDs cannot make NanoIO hammer the provider. On
  refresh the key set is *replaced*: a withdrawn key stops verifying at once.
* Accepted algorithms: RS/PS/ES 256/384/512. `none` and HMAC algorithms are
  refused before any key is consulted.
* Checked: signature, `iss` equals the discovery issuer, `aud` contains
  `client_id`, `exp` (30 s skew), `nbf`, `sub` present.
* Policy mapping: the claim named by `claim_name` (default `policy`; a
  string, comma list or array) must name policies that exist; otherwise
  `role_policy` if set; otherwise `AccessDenied`.
* Revocation: an OIDC credential is bounded by the token's expiry. To end
  one sooner delete it (`mc admin accesskey rm <key>`); other nodes honour
  that within the resolver TTL (15 s).

### LDAP (`identity_ldap`)

* Search-then-bind: a lookup account finds the user's DN with
  `user_dn_search_filter` (`%s` is the escaped login name; exactly one match
  is required), then the password is verified by binding as that DN on a
  separate connection. An empty password is refused before any bind (LDAP
  would otherwise treat it as an anonymous bind that succeeds).
* Groups: `group_search_filter` (`%s` login name, `%d` user DN) under
  `group_search_base_dn`.
* TLS: `ldaps://` or `server_starttls=on`; plain LDAP requires an explicit
  `server_insecure=on`. `tls_skip_verify` and `tls_ca` are available.
* Policy mapping: `mc idp ldap policy attach <alias> <policy> --user <DN>` /
  `--group <DN>`. A user's policies are those of their DN plus those of each
  group they belong to. DNs are compared normalised (case, spacing).
* Unknown or wrong users, wrong passwords and empty passwords all return the
  same `AccessDenied`. After 10 failed sign-ins for one login name within a
  minute the endpoint answers `Throttling` (429) for that name until the
  window passes (per node, in memory; the directory's lockout policy still
  applies).

### The revocation TTL is a security-relevant knob

`identity_ldap cache_ttl` (default **60 s**, range 1 s–24 h) is how long a
node trusts what it learned about an LDAP credential. When the cached answer
expires the node asks the directory again: the account must still exist and
match the user filter, and its policies are recomputed from its *current*
groups. So:

* a user removed from the directory (or moved out of the search base) loses
  access within `cache_ttl` of the node's last check;
* a user removed from a group loses that group's policies within `cache_ttl`;
* a longer TTL means fewer directory round trips and a longer window in which
  a revoked user keeps working. **Set it to the longest period of continued
  access you can accept after an account is disabled.**

If the directory is unreachable at revalidation time the credential is
denied (fail closed) until the next successful check; a directory outage
therefore stops federated access rather than extending it. Static (root and
IAM-file) users are unaffected.

An OIDC credential has no directory to ask: its bound is the token's own
expiry (set short in the provider) plus the explicit delete above.

### Tests

* `internal/identity/oidc`: key rotation, expiry, `alg` confusion, tampering.
* `internal/api/identity_test.go`: mock OpenID provider through the real HTTP
  stack (policy claim mapping, session token enforcement, session policy
  narrowing, expiry, rotation, revocation) and AssumeRole/GetCallerIdentity.
* `internal/api/ldap_test.go`: a real OpenLDAP container (`osixia/openldap:1.5.0`,
  skipped when Docker or the image is absent; `NANOIO_TEST_LDAP=off` skips):
  bind, group and direct-DN mapping, bad logins and filter injection, removed
  user denied within `cache_ttl`, removal from a group.
* `test/madmin-oracle`: `madmin-go` and `minio-go` against a built binary.

Known gaps: no OIDC `userinfo`/`claim_prefix`/multiple named providers; one
LDAP and one OpenID provider per server; STS credentials are cluster-local
(not replicated to sites); LDAP service-account-style long-lived keys are not
supported.
