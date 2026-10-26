# HPKE

Hybrid Public Key Encryption is specified in [RFC 9180][] and extended to
ML-KEM by [draft-ietf-hpke-pq-05][].

We include vectors for *only* the base mode (`mode_base`) and the following
*subset* of KEMs:

- ML-KEM-512  (KEM id `0x0040`)
- ML-KEM-768  (KEM id `0x0041`)
- ML-KEM-1024 (KEM id `0x0042`)
- DHKEM(X25519, HKDF-SHA256) (KEM id `0x0020`)

For each of these KEMs there are three files:

- `hpke_{KEM}_encap_test.json`
  ([schema](../schemas/hpke_encap_test_schema.json)): `SetupBaseS` and
  `Seal`, validating the recipient key `pkRm`;
- `hpke_{KEM}_decrypt_test.json`
  ([schema](../schemas/hpke_decrypt_test_schema.json)): single-shot
  `SetupBaseR` and `Open`;
- `hpke_{KEM}_sequence_test.json`
  ([schema](../schemas/hpke_sequence_test_schema.json)): several `Open`
  calls, in order, on one context.

The schemas describe every field and the meaning of `valid`, `invalid`, and
`acceptable`. Each file's `notes` explain every flag: what the case tests,
why it has its result, and known implementations it caught.

Most `invalid` decryption cases fail at the AEAD tag. Where the property
under test is in the KEM, a tag failure would prove nothing, so `ct` is
instead sealed under the key that a buggy receiver derives (for example, the
all-zero X25519 output for `SmallOrderEnc`). For ML-KEM, the
`ImplicitRejection`, `Strcmp`, and `MalleableCiphertext` cases are `valid`:
`ct` is sealed under the implicit-rejection secret `K-bar = J(z || c)`, so
`Open` must succeed.

## Deterministic encapsulation

`ikmE` is the 32-byte randomness input to deterministic encapsulation, as in
RFC 9180 Appendix A (`EncapDerand` in draft-ietf-hpke-hpke-05 Appendix C.1).
For DHKEM(X25519), `(skE, pkE) = DeriveKeyPair(ikmE)` and `skEm` is the
derived ephemeral private key, for test hooks that take the raw key. For
ML-KEM, `ikmE` is the randomness `m` passed to FIPS 203
`ML-KEM.Encaps_internal`, and there is no `skEm`.

With such a hook, run `SetupBaseS(pkRm, info)` derandomized with `ikmE` (or
`skEm`), then `Seal`, and compare `enc` and `ct` byte for byte. This also
checks the sender direction of decryption and sequence cases that carry
`ikmE`. In the encapsulation files `ikmE` is present on every case,
including `invalid` ones, and a derandomized path must still reject those
keys: some libraries check the key only on the public, randomized path.

An API that takes `enc || ct` as one buffer turns the `WrongLengthEnc` and
`EncTrailingByteInContext` cases into ciphertext tampering. They still fail,
but no longer test the `enc` length check.

## X25519 private keys are unclamped

`skRm` and `skEm` are the 32-byte strings that `DeriveKeyPair` outputs,
*unclamped*. This matches the values printed in RFC 9180 Appendix A and in
draft-ietf-hpke-hpke-05, whose Section 7.1.2 says X25519 private keys "are
identical to their byte string representation". The text of RFC 9180
Section 7.1.2 instead says `SerializePrivateKey()` "MUST clamp its output",
which contradicts its own Appendix A. [Erratum 7121][] records this and lists
clamped replacement values (see also [cfrg/draft-irtf-cfrg-hpke#255][cfrg-255]).
The revised specification resolves it the other way, by removing the clamping
requirement ([hpkewg/hpke#39][hpke-clamp-issue], [hpkewg/hpke#42][hpke-clamp]).

X25519 clamps the scalar internally (RFC 7748 Section 5), so clamped and
unclamped scalars give the same public key and shared secret. In practice:

- Implementations that follow RFC 9180 Section 7.1.2 re-serialize `skRm` to
  different, clamped bytes: Go's `crypto/hpke` (`PrivateKey.Bytes()`) and
  [rust-hpke][rust-hpke-clamp] from 0.15.0. BoringSSL and AWS-LC return the
  bytes as given. Compare public keys or decryption results, not
  re-serialized private keys.
- Some X25519 APIs require an already-clamped scalar. For example, wolfSSL's
  `wc_curve25519_make_pub` and `wc_curve25519_generic` reject an unclamped
  scalar. Clamp before passing the scalar to such an API.

## Not covered

- PSK, Auth, and AuthPSK modes.
- Other KEMs, including the other DHKEMs and the hybrid KEMs of
  draft-ietf-hpke-pq-05 (MLKEM768-X25519, which takes over KEM id `0x647a`,
  registered by IANA as X-Wing; MLKEM768-P256; MLKEM1024-P384).
- `DeriveKeyPair` vectors (`ikmR` to `skRm` and `pkRm`).
- The secret export interface (`Export`).
- `MessageLimitReachedError` (RFC 9180 Section 5.2). Reaching it requires
  setting the sequence number directly, and the vector format has no way to
  express that.
- A 16-bit sequence counter, which would take 65537 messages to detect.

[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180
[draft-ietf-hpke-pq-05]: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05
[draft-ietf-hpke-hpke-05]: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-05
[Erratum 7121]: https://www.rfc-editor.org/errata/eid7121
[cfrg-255]: https://github.com/cfrg/draft-irtf-cfrg-hpke/issues/255
[hpke-clamp]: https://github.com/hpkewg/hpke/pull/42
[hpke-clamp-issue]: https://github.com/hpkewg/hpke/issues/39
[rust-hpke-clamp]: https://github.com/rozbb/rust-hpke/pull/122
