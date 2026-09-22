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

Verified end to end on 2026-08-24 against a Bitcoin Knots
v29.4.1.knots20260508rc2 node on testnet4, which activated the fork at height
149537. Fulcrum indexed all 169k blocks across the boundary without an error and
now serves that chain:

```
blockchain.block.header(149536)      -> 80 bytes
blockchain.block.header(149537)      -> 164 bytes
blockchain.block.headers(149535, 5)  -> [80, 80, 164, 164, 164]
blockchain.pow_algorithms()          -> [{"from_height": 0,      "algorithm": "sha256d"},
                                         {"from_height": 149537, "algorithm": "blake2b-v2"}]
```

The activation height in that last answer is not configured anywhere: it is
what the binary search over the stored headers found.

A checkpoint proof spanning the fork was then folded by hand the way a light
client would - BLAKE2b hash of the v2 header at 149537, up an 18-step branch -
and it reproduces the root the server serves for cp_height 169000. That is the
whole point of the exercise: a client can verify this chain without trusting
the server.

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
- **Protocol** — `blockchain.pow_algorithms`; protocol 1.8 on a chain that has
  produced a v2 header, with headers refused to clients below it, and a
  `blake2b_fork` point in `server.features`. See `ProtocolV2.h`.

Left to do:

- The header merkle root used by `cp_height` still needs reviewing on a chain
  with mixed header lengths.
- A client. Sparrow derives the block id the same wrong way, which is what
  Shrike (`privkeyio/shrike`) fixes on its side. It continues
  `AcesHigh70/sparrow` branch `blake2b-header`, which is no longer maintained.

## The protocol side

Less than it first appears. Protocol 1.6 already returns `blockchain.block.headers`
as a list of hex strings rather than one concatenated blob (`headersAsList` in
`Servers.cpp`), so header boundaries are explicit and a 164-byte entry needs
nothing new. Clients negotiating 1.5 or lower get the concatenated form and
recover headers by slicing every 80 bytes; on a chain with mixed header lengths
that cannot be served correctly.

That gating is now in, and higher than 1.6. A chain that has produced a v2 header
offers protocol 1.8, the version that states a header's length is read from its
version word, and serves headers only to a client that negotiated it. A client
below 1.8 may still connect, because one that never asks for a header works
correctly here, but every method that returns a header refuses it and says why,
and a subscriber that cannot read a new v2 tip is disconnected rather than sent
it. The rules and the reasoning are in `ProtocolV2.h`; they follow the draft
specification `docs/electrum-header-v2.md` in `paulscode/electrs-pruned`.

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
