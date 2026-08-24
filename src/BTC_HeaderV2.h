//
// Fulcrum - A fast & nimble SPV Server for Bitcoin & friends
//
// Block header v2 support for the BLAKE2b proof-of-work hardfork
// (bitcoinknots/bitcoin#359).  A v2 header is 164 bytes instead of 80 and its
// proof of work is a BLAKE2b pipeline rather than SHA256d, so every place that
// assumed a fixed 80 bytes or a double-SHA256 block id needs to ask here first.
//
#pragma once

#include "ByteView.h"

#include <QByteArray>

#include <cstdint>

namespace BTC {

    /// Classic header size.  Also the size of every header on a chain that never forked.
    inline constexpr int HeaderSizeV1 = 80;
    /// Header size once the BLAKE2b hardfork activates.
    inline constexpr int HeaderSizeV2 = 164;
    /// Bit 31 of the version word marks the v2 layout.  No mainnet block has ever set it
    /// (all 962k scanned as of 2026-08-16), which is why it is available as the flag.
    inline constexpr uint32_t HeaderV2VersionFlag = 0x80000000u;

    /// True iff the first 4 bytes (little-endian version word) have bit 31 set.
    /// False for anything shorter than 4 bytes -- callers should size-check separately.
    bool IsHeaderV2(const ByteView &header) noexcept;

    /// Returns HeaderSizeV1 or HeaderSizeV2 by looking at the version flag, or 0 if
    /// there are not even 4 bytes to look at.  This is what makes the format
    /// self-describing: a stream of concatenated headers can be split with it.
    int HeaderSizeFor(const ByteView &header) noexcept;

    /// The proof-of-work hash of a header, in display order (big-endian, the way
    /// bitcoind prints block hashes and the way we send them to clients).
    ///
    /// v1: SHA256d, identical to BTC::HashRev(header).
    /// v2: the BLAKE2b pipeline of CBlockHeader::GetHash() in Bitcoin Knots.
    ///
    /// Throws std::invalid_argument if the header is not exactly the size its own
    /// version word claims -- a caller that got here with a truncated header has a
    /// bug worth surfacing rather than a hash worth returning.
    QByteArray HeaderPoWHashRev(const ByteView &header);

} // namespace BTC
