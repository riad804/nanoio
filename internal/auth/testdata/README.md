# AWS Signature Version 4 test suite

`aws4_testsuite/` is the official AWS SigV4 test suite
("AWS Signature Version 4 Test Suite", Copyright 2019 Amazon.com, Inc. or its
affiliates), Apache License 2.0 — see `aws4_testsuite/LICENSE` and
`aws4_testsuite/NOTICE`.

AWS no longer hosts the zip; this copy comes from the botocore repository
(`tests/unit/auth/aws4_testsuite`, branch `develop`), which vendors it
unmodified. The `.sreq` (signed request) files were dropped: they are
redundant with `.authz` and the tests do not read them.

Each vector is a directory holding:

| File    | Content                                   |
| ------- | ----------------------------------------- |
| `.req`  | the raw HTTP request to sign              |
| `.creq` | the expected canonical request            |
| `.sts`  | the expected string to sign               |
| `.authz`| the expected Authorization header         |

Test credentials: access key `AKIDEXAMPLE`, secret
`wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, region `us-east-1`, service
`service`. The suite targets generic AWS services, which normalise and
double-encode the path; S3 does neither (see `normalize-path.txt`), so
`internal/auth` runs these vectors in its generic canonicalisation mode.
