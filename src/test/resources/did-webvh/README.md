# WebVH interoperability fixtures

Copied unchanged from `didwebvh-java` v0.3.1, commit `a0f7a546b6ad14002b98aa24890ad1326407435a`, under `didwebvh-core/src/test/resources/interop/` (Apache-2.0).

Upstream provenance: https://github.com/decentralized-identity/didwebvh-java/tree/v0.3.1/didwebvh-core/src/test/resources/interop

That project records these vectors as originating in `swcurran/didwebvh-test-suite`, commit `c11fda313dcc8ef0d1d50cff907fa754f33df73e`. The fixtures contain public DID logs and proofs, not private keys.

Positive history tests cover Python creation, TypeScript updates, Java EECC key rotation, and Rust pre-rotation. Negative tests cover deactivation and cross-DID witness replay. `witness-update-rust` is deliberately rejected because it uses bare multikey witness identifiers instead of the `did:key` identifiers required by the supported v1.0 profile. Locally generated signed fixtures additionally test witness thresholds, credential verification, caching, and malformed inputs.
