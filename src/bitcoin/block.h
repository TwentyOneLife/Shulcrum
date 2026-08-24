// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "transaction.h"
#include "serialize.h"
#include "uint256.h"

#include <utility>

namespace bitcoin {
/**
 * Nodes collect new transactions into a block, hash them into a hash tree, and
 * scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements. When they solve the proof-of-work, they broadcast the block to
 * everyone and the block is added to the block chain. The first transaction in
 * the block is a special one that creates a new coin owned by the creator of
 * the block.
 */
class CBlockHeader {
public:
    /// Bit 31 of the version word marks the 164-byte v2 layout of the BLAKE2b
    /// hardfork (bitcoinknots/bitcoin#359). No block before that fork ever set it.
    static constexpr uint32_t VERSION_HEADER_V2_FLAG = 0x80000000u;
    /// Bit 2 of m_flags: nTime on the wire is the real time minus m_time_offset.
    static constexpr uint8_t FLAG_USE_TIME_OFFSET = 4u;

    // header
    bool m_header_v2; ///< not serialized as such: it is bit 31 of the version word
    int32_t nVersion; ///< version with bit 31 masked off
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime; ///< as it appears on the wire; see GetBlockTime() for v2
    uint32_t nBits;
    uint32_t nNonce;

    // -- v2 only, all zero on a v1 header
    uint32_t m_nonce2, m_nonce3;
    uint128 m_extranonce;
    uint32_t m_time_offset;
    uint16_t m_txcount;
    uint8_t m_flags;
    uint8_t m_xor_key_mask_clear_bits;
    uint128 m_xor_key;
    int32_t m_height;
    uint256 m_mm_rhs; ///< merge-mining commitment

    CBlockHeader() noexcept { SetNull(); }

    /// The version word as it goes on the wire, bit 31 included.
    uint32_t GetCompleteVersion() const noexcept {
        return (m_header_v2 ? VERSION_HEADER_V2_FLAG : 0u) | (uint32_t(nVersion) & ~VERSION_HEADER_V2_FLAG);
    }

    SERIALIZE_METHODS(CBlockHeader, obj) {
        uint32_t v;
        SER_WRITE(obj, v = obj.GetCompleteVersion());
        READWRITE(v);
        SER_READ(obj, obj.m_header_v2 = (v & VERSION_HEADER_V2_FLAG) != 0u);
        SER_READ(obj, obj.nVersion = int32_t(v & ~VERSION_HEADER_V2_FLAG));
        READWRITE(obj.hashPrevBlock);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.nTime);
        READWRITE(obj.nBits);
        READWRITE(obj.nNonce);
        if (obj.m_header_v2) {
            READWRITE(obj.m_nonce2, obj.m_nonce3, obj.m_extranonce, obj.m_time_offset, obj.m_txcount,
                      obj.m_flags, obj.m_xor_key_mask_clear_bits, obj.m_xor_key, obj.m_height, obj.m_mm_rhs);
        } else {
            SER_READ(obj, obj.ClearV2Fields());
        }
    }

    void ClearV2Fields() noexcept {
        m_nonce2 = m_nonce3 = 0u;
        m_extranonce.SetNull();
        m_time_offset = 0u;
        m_txcount = 0u;
        m_flags = 0u;
        m_xor_key_mask_clear_bits = 0u;
        m_xor_key.SetNull();
        m_height = 0;
        m_mm_rhs.SetNull();
    }

    void SetNull() noexcept {
        m_header_v2 = false;
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0u;
        nBits = 0u;
        nNonce = 0u;
        ClearV2Fields();
    }

    bool IsNull() const noexcept { return nBits == 0; }

    /// SHA256d for a v1 header, the BLAKE2b pipeline for a v2 one.
    uint256 GetHash() const;
    /// The v2 pipeline itself. Only meaningful when m_header_v2; see block_pow_v2.cpp.
    uint256 GetBlake2bPoWHash() const;

    /// v1, and v2 without the time-offset flag: the wire value. Otherwise the
    /// wire value plus the offset, wrapping at 2^32 the way the node does it.
    int64_t GetBlockTime() const noexcept {
        if (!m_header_v2 || !(m_flags & FLAG_USE_TIME_OFFSET)) return int64_t(nTime);
        return int64_t(uint32_t(nTime + m_time_offset));
    }
};

class CBlock : public CBlockHeader {
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    /// Litecoin only
    litecoin_bits::MimbleBlobPtr mw_blob;

    // memory only
    mutable bool fChecked;

    CBlock() noexcept { SetNull(); }

    CBlock(const CBlockHeader &header) {
        SetNull();
        *(static_cast<CBlockHeader *>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj) {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vtx);
        // Litecoin only -- Deserialize the mimble-wimble blob at the end under certain conditions (post-activation).
        if constexpr (ser_action.ForRead()) obj.mw_blob.reset();
        if (s.GetVersion() & SERIALIZE_TRANSACTION_USE_MWEB && obj.vtx.size() >= 2 && obj.vtx.back()->IsHogEx()) {
            if constexpr (ser_action.ForRead()) {
                obj.mw_blob = litecoin_bits::EatBlockMimbleBlob(s);
            } else {
                if (obj.mw_blob) {
                    s.write(reinterpret_cast<const char *>(std::as_const(*obj.mw_blob).data()), obj.mw_blob->size());
                }
            }
        }
    }

    void SetNull() {
        CBlockHeader::SetNull();
        vtx.clear();
        mw_blob.reset();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const { return *this; }

    std::string ToString(bool fVerbose = false) const;
};

/**
 * Describes a place in the block chain to another node such that if the other
 * node doesn't have the same branch, it can find a recent common trunk.  The
 * further back it is, the further before the fork it may be.
 */
struct CBlockLocator {
    std::vector<uint256> vHave;

    constexpr CBlockLocator() noexcept {}

    explicit CBlockLocator(const std::vector<uint256> &vHaveIn)
        : vHave(vHaveIn) {}

    SERIALIZE_METHODS(CBlockLocator, obj) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH)) READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull() { vHave.clear(); }

    bool IsNull() const { return vHave.empty(); }
};

} // end namespace bitcoin
