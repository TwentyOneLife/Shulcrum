// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "block.h"

#include "crypto/common.h"
#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

namespace bitcoin {

uint256 CBlockHeader::GetHash() const {
    // A v2 header is not hashed by serializing it: its proof of work is a BLAKE2b
    // pipeline over a different commitment structure entirely.
    if (m_header_v2) return GetBlake2bPoWHash();
    return SerializeHash(*this);
}

std::string CBlock::ToString(bool fVerbose) const {
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, "
                   "hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, "
                   "vtx=%u)\n",
                   GetHash().ToString(), nVersion, hashPrevBlock.ToString(),
                   hashMerkleRoot.ToString(), nTime, nBits, nNonce, vtx.size());
    for (const auto &tx : vtx) {
        s << "  " << tx->ToString(fVerbose) << "\n";
    }
    return s.str();
}

} // end namespace bitcoin
