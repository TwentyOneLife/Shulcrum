// The BLAKE2b proof-of-work hash of a v2 block header.
//
// Transcribed from CBlockHeader::GetHash() in Bitcoin Knots
// v29.4.1.knots20260508rc2 (src/primitives/block.cpp), for the hardfork
// proposed in bitcoinknots/bitcoin#359.  Verified against real testnet4
// headers by the "headerv2" test in src/BTC_HeaderV2.cpp.

#include "block.h"

#include "crypto/blake2b.h"
#include "crypto/sha256.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace bitcoin {

namespace {

using Bytes = std::vector<uint8_t>;
using Hash32 = std::array<uint8_t, 32>;

Hash32 Sha256(const uint8_t *data, size_t len) {
    Hash32 out;
    CSHA256().Write(data, len).Finalize(out.data());
    return out;
}

/// BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
Hash32 TaggedHash(const char *tag, const Bytes &data) {
    const auto th = Sha256(reinterpret_cast<const uint8_t *>(tag), std::strlen(tag));
    CSHA256 h;
    h.Write(th.data(), th.size());
    h.Write(th.data(), th.size());
    h.Write(data.data(), data.size());
    Hash32 out;
    h.Finalize(out.data());
    return out;
}

void Append(Bytes &b, const uint8_t *p, size_t n) { b.insert(b.end(), p, p + n); }
void Append(Bytes &b, const Hash32 &a) { Append(b, a.data(), a.size()); }
template <unsigned BITS> void Append(Bytes &b, const base_blob<BITS> &blob) {
    Append(b, reinterpret_cast<const uint8_t *>(blob.begin()), blob.size());
}
void AppendLE32(Bytes &b, uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8*i))); }

Hash32 Blake2b256(const Bytes &in) {
    Hash32 out;
    if (0 != blake2b_nokey(out.data(), out.size(), in.data(), in.size()))
        throw std::runtime_error("blake2b_nokey failed");
    return out;
}

} // namespace

uint256 CBlockHeader::GetBlake2bPoWHash() const {
    // The pooling miner does not learn m_xor_key until it finds a block, which is
    // what stops it from recognizing (and withholding) one.  A full header always has it.
    Bytes xorKey;
    Append(xorKey, m_xor_key);
    const auto xorKeyHash = TaggedHash("Bitcoin block hash PoW XOR key", xorKey);

    Hash32 xorMask{}; // all zeroes when solo mining, i.e. a null key
    if (!m_xor_key.IsNull()) {
        xorMask = TaggedHash("Bitcoin block hash PoW XOR mask", xorKey);
        const unsigned clearBytes = m_xor_key_mask_clear_bits / 8u;
        std::fill_n(xorMask.begin(), std::min<size_t>(clearBytes, xorMask.size()), uint8_t{0});
        if (clearBytes < xorMask.size())
            xorMask[clearBytes] &= uint8_t(0xffu >> (m_xor_key_mask_clear_bits % 8u));
    }

    // hashPrevBlock out of wire order, which is what both tagged hashes below want.
    Bytes prevSane;
    Append(prevSane, hashPrevBlock);
    std::reverse(prevSane.begin(), prevSane.end());
    auto prevHidden = TaggedHash("Bitcoin prevblock header, hashed", prevSane);

    // h1 commits to everything the mining machine never sees, so the hasher cannot
    // be bricked by a future version, time or difficulty.
    Bytes b1;
    b1.reserve(119);
    AppendLE32(b1, GetCompleteVersion());
    Append(b1, prevSane.data(), prevSane.size());
    AppendLE32(b1, uint32_t(m_height));
    Append(b1, hashMerkleRoot);
    AppendLE32(b1, nTime); // the wire value, offset not applied
    b1.push_back(0u);      // reserved for extended 40-bit time
    AppendLE32(b1, nBits);
    AppendLE32(b1, uint32_t(m_txcount));
    b1.push_back(m_flags);
    b1.push_back(m_xor_key_mask_clear_bits);
    Append(b1, xorKeyHash);
    if (b1.size() != 119) throw std::runtime_error("GetBlake2bPoWHash: h1 preimage is not 119 bytes");
    const auto h1 = TaggedHash("Bitcoin block header 1", b1);

    Bytes b2;
    b2.reserve(96);
    Append(b2, h1);
    b2.insert(b2.end(), 32, 0u); // two null uint128s
    Append(b2, m_mm_rhs);
    if (b2.size() != 96) throw std::runtime_error("GetBlake2bPoWHash: h2 preimage is not 96 bytes");
    const auto h2 = TaggedHash("Merge-mining hook", b2);

    // What a Stratum v1 miner receives as "coinb1" plus its extranonce.
    Bytes work;
    work.reserve(52);
    AppendLE32(work, 0u);
    Append(work, h2);
    Append(work, m_extranonce);
    if (work.size() != 52) throw std::runtime_error("GetBlake2bPoWHash: Sv1 preimage is not 52 bytes");
    const auto inner = Blake2b256(work);

    // What the ASIC itself hashes, laid out per the profile in the low 2 bits of m_flags.
    Bytes asic;
    asic.reserve(112);
    const auto appendNoncesAndInner = [&] {
        AppendLE32(asic, nNonce);
        AppendLE32(asic, m_nonce2);
        AppendLE32(asic, m_time_offset);
        AppendLE32(asic, m_nonce3);
        Append(asic, inner);
    };
    switch (m_flags & 3u) {
    case 3:
        asic.insert(asic.end(), 32, 0u);
        [[fallthrough]];
    case 2:
        asic.insert(asic.end(), 48, 0u);
        Append(asic, h2);
        appendNoncesAndInner();
        break;
    case 0:
        // Profile 0 is the Siacoin ASIC layout: the first 6 bytes of the prev
        // commitment are zeroed because in a Sia header those bytes mean something else.
        std::fill_n(prevHidden.begin(), 6, uint8_t{0});
        Append(asic, prevHidden);
        appendNoncesAndInner();
        break;
    case 1:
        AppendLE32(asic, nNonce);
        AppendLE32(asic, m_nonce2);
        AppendLE32(asic, m_nonce3);
        AppendLE32(asic, m_time_offset);
        Append(asic, inner);
        Append(asic, h2);
        break;
    }
    const auto outer = Blake2b256(asic);

    // The node writes the XORed bytes back to front, so the uint256 it returns
    // reads as hash ^ mask reversed.
    uint256 ret;
    auto *out = reinterpret_cast<uint8_t *>(ret.begin());
    for (size_t i = 0; i < outer.size(); ++i)
        out[outer.size() - 1 - i] = uint8_t(outer[i] ^ xorMask[i]);
    return ret;
}

} // end namespace bitcoin
