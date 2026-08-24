# Variable-length block headers and BLAKE2b proof of work

Work in progress. This branch teaches Fulcrum to index and serve a chain whose
block headers are not 80 bytes and whose proof of work is not SHA256d — the
BLAKE2b hardfork of [bitcoinknots/bitcoin#359](https://github.com/bitcoinknots/bitcoin/pull/359),
where a v2 header is 164 bytes.

## What a v2 header is

Bit 31 of the version word marks the new layout, so the format is
self-describing: read four bytes, and you know whether the header is 80 or 164
bytes long. No mainnet block has ever set that bit (all ~962k scanned), which is
why it was available.

The extra 84 bytes are, in wire order: `nonce2`, `nonce3`, a 128-bit
`extranonce`, a time offset, the transaction count, a flags byte, the number of
cleared XOR-mask bits, a 128-bit `xor_key`, the height, and a 32-byte
merge-mining commitment.

Proof of work is a BLAKE2b pipeline over those fields rather than SHA256d over
the serialized header. `BTC::HeaderPoWHashRev()` implements it, transcribed from
`CBlockHeader::GetHash()` in Bitcoin Knots v29.4.1.knots20260508rc2, and the
`headerv2` unit test checks it against real testnet4 blocks — including one
before the fork, so the same entry point has to get both algorithms right.

## Status

Working end to end against a Bitcoin Knots v29.4.1.knots20260508rc2 node on
testnet4, which activated the fork at height 149537.

- `src/bitcoin/crypto/blake2b.{h,cpp}` — vendored from Knots (CC0 / OpenSSL /
  Apache-2.0), adapted only in its includes and its buffer wipe.
- `src/bitcoin/block.h`, `block_pow_v2.cpp` — `CBlockHeader` reads and writes
  the v2 layout, and `GetHash()` picks the algorithm.
- `src/BTC_HeaderV2.{h,cpp}` — the byte-level view: v1/v2 detection,
  size-for-header, proof-of-work hash, and the test vectors.
- **Storage** — header records are sized by the new `extended_headers` config
  option, written padded and read trimmed to the length the version word
  implies. The record array stores its own record size and refuses to open under
  a different one, so switching the option on an existing DB is an error rather
  than a silent misread.
- **Controller / HeaderVerifier** — block ids and prev-links come from the
  proof-of-work hash rather than from SHA256d.
- **Protocol** — `blockchain.pow_algorithms`, and max protocol version 1.7.

Left to do:

- `blockchain.headers.subscribe` and the header merkle root used by `cp_height`
  still need reviewing on a chain with mixed header lengths.
- A client. Sparrow derives the block id the same wrong way, which is what
  Shrike (`AcesHigh70/sparrow`, branch `blake2b-header`) fixes on its side.

## The protocol side

Less than it first appears. Protocol 1.6 already returns `blockchain.block.headers`
as a list of hex strings rather than one concatenated blob (`headersAsList` in
`Servers.cpp`), so header boundaries are explicit and a 164-byte entry needs
nothing new. Clients negotiating 1.5 or lower get the concatenated form and
recover headers by slicing every 80 bytes; on a chain with mixed header lengths
that cannot be served correctly, which argues for gating such a chain behind
1.6+ rather than changing the old shape.

What is genuinely missing is telling the client **which algorithm applies from
which height**, since a light client verifies the work itself and cannot guess.
One activation height and one algorithm name, offered once per connection:

```
blockchain.pow_algorithms()
→ [{"from_height": 0, "algorithm": "sha256d"},
   {"from_height": 149537, "algorithm": "blake2b-v2"}]
```

A client that does not implement the named algorithm can then decline politely
instead of rejecting every valid header as bad work.
