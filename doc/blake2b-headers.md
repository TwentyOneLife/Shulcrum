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

Done:

- `src/bitcoin/crypto/blake2b.{h,cpp}` — vendored from Knots (CC0 / OpenSSL /
  Apache-2.0), adapted only in its includes and its buffer wipe.
- `src/BTC_HeaderV2.{h,cpp}` — v1/v2 detection, size-for-header, and the PoW
  hash for both, with the test vectors.

Not done yet, in the order it is being worked:

1. **`bitcoin::CBlockHeader`** — the deserializer still reads a fixed 80 bytes,
   so a v2 block cannot be parsed for its transactions at all.
2. **Storage** — the headers `DBRecordArray` has a fixed record size of 80.
   The plan is an instance record size (80 by default, 164 for a chain that opts
   in) stored in the DB metadata, so an existing database keeps its layout and
   refuses to open under the wrong one rather than silently misreading it.
   Padding to 164 costs ~84 MB per million blocks, which is the cheap side of
   this trade.
3. **Controller** — block download hardcodes `HEADER_SIZE` and derives the block
   id with `BTC::HashRev`, which is only the proof-of-work hash for a v1 header.
4. **`BTC::HeaderVerifier`** — the prev-link check hashes with SHA256d.
5. **Protocol** — see below.

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
