//
// Fulcrum - A fast & nimble SPV Server for Bitcoin & friends
//
// See BTC_HeaderV2.h.  The BLAKE2b pipeline itself lives in
// bitcoin/block_pow_v2.cpp, next to the header class it hashes; this file is
// the byte-level view of it that the rest of Fulcrum works with, since headers
// arrive and are stored as raw bytes rather than as objects.
//
#include "BTC_HeaderV2.h"

#include "BTC.h"

#include "bitcoin/block.h"

#include "App.h"

#include <algorithm>
#include <stdexcept>

namespace {
    inline uint32_t ReadLE32(const uint8_t *p) noexcept {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    }
}

namespace BTC {

    bool IsHeaderV2(const ByteView &header) noexcept
    {
        if (header.size() < 4) return false;
        return (ReadLE32(reinterpret_cast<const uint8_t *>(header.data())) & HeaderV2VersionFlag) != 0u;
    }

    int HeaderSizeFor(const ByteView &header) noexcept
    {
        if (header.size() < 4) return 0;
        return IsHeaderV2(header) ? HeaderSizeV2 : HeaderSizeV1;
    }

    QByteArray HeaderPoWHashRev(const ByteView &header)
    {
        if (!IsHeaderV2(header)) {
            if (header.size() != size_t(HeaderSizeV1))
                throw std::invalid_argument("HeaderPoWHashRev: v1 header is not 80 bytes");
            return BTC::HashRev(header.toByteArray(false)); // plain SHA256d, no need to deserialize
        }
        if (header.size() != size_t(HeaderSizeV2))
            throw std::invalid_argument("HeaderPoWHashRev: v2 header is not 164 bytes");
        const auto hdr = BTC::Deserialize<bitcoin::CBlockHeader>(header.toByteArray(false));
        return BTC::Hash2ByteArrayRev(hdr.GetBlake2bPoWHash());
    }

    QByteArray HeaderPoWHash(const ByteView &header)
    {
        QByteArray ret = HeaderPoWHashRev(header);
        std::reverse(ret.begin(), ret.end());
        return ret;
    }

} // namespace BTC

#ifdef ENABLE_TESTS
namespace {
    // Real testnet4 blocks past the BLAKE2b activation at height 149537, taken from a
    // Bitcoin Knots v29.4.1.knots20260508rc2 node on 2026-08-24.  The v1 vector is the
    // block immediately before activation, so the same call has to cover both algorithms.
    void headerV2Tests()
    {
        struct Vec { const char *height, *hash, *header; };
        static const std::vector<Vec> vecs = {
            {"149537", "000000000068f60429c933dc0c8befbcc7edadb1cf8f8d0d7804c608fd736d82",
             "000000a05119dc259b59eaefbccf48ecc15bfd50c499d9d65b500b361b1b60000000000063be46460c5e75edfe6e1fba731e3fc096396af99c299e70625484ffc6f9184101fb896affff001d986cd88b510d792301fb896a00000000b14cf00d0100000000000000000000000f00000000000000000000000000000000000000214802000000000000000000000000000000000000000000000000000000000000000000"},
            {"160000", "000000000003b300f5eb68065049c97c2f0cc76a845fd389095eed209ff8a030",
             "000000a0afad48a12f8e2e9bb4439b15a113dc5e6bc088fcdfd396167701030000000000f668d99148885430254526bcc5ea12c1c49b6e0dc67bce7f65cae28b0124046102178a6ac0ff3f1bacb6950adb0cf10302178a6a00000000b18cf00d0400000000000000000000000100000000000000000000000000000000000000007102000000000000000000000000000000000000000000000000000000000000000000"},
            {"169500", "0000000000000fa9dc8265b426d36648d7039d770cd5f06a7e720d91151a4350",
             "000000a024218550bb045437bebe782e2904b814c05773f3076e2cdc7a0c000000000000765cd861b9ce07f892cb84ccc4002d6627a0412a92e39c1c290b7a862773b936ce108c6af0ff0f1abb92f69b99b4c7950000000000000000b10cf00d0200000000000000000000001b000430f829c56dd49838799520cb5e564d8f081c9602000000000000000000000000000000000000000000000000000000000000000000"},
        };
        for (const auto &v : vecs) {
            const QByteArray hdr = QByteArray::fromHex(v.header);
            if (hdr.size() != BTC::HeaderSizeV2)
                throw Exception(QString("header at height %1 deserialized to %2 bytes, expected 164").arg(v.height).arg(hdr.size()));
            if (BTC::HeaderSizeFor(hdr) != BTC::HeaderSizeV2)
                throw Exception(QString("header at height %1 was not detected as v2").arg(v.height));
            const QByteArray got = BTC::HeaderPoWHashRev(hdr).toHex();
            if (got != QByteArray(v.hash))
                throw Exception(QString("PoW hash mismatch at height %1: got %2, expected %3").arg(v.height, QString(got), v.hash));
            // The object path has to agree with the byte path, and round-trip back to the same bytes.
            const auto obj = BTC::Deserialize<bitcoin::CBlockHeader>(hdr);
            if (!obj.m_header_v2)
                throw Exception(QString("deserialized header at height %1 lost its v2 flag").arg(v.height));
            if (BTC::Hash2ByteArrayRev(obj.GetHash()).toHex() != QByteArray(v.hash))
                throw Exception(QString("CBlockHeader::GetHash() disagrees at height %1").arg(v.height));
            if (BTC::Serialize(obj) != hdr)
                throw Exception(QString("header at height %1 did not round-trip through serialization").arg(v.height));
            Log() << "headerv2: height " << v.height << " hashes to " << v.hash << " OK";
        }

        // Height 149536, the last SHA256d header on that chain: same entry point, other algorithm.
        static constexpr auto v1Hash = "0000000000601b1b360b505bd6d999c450fd5bc1ec48cfbcefea599b25dc1951";
        const QByteArray v1 = QByteArray::fromHex("00c07a2d48a589a1d9402520f5b20e264ce5159b58379f65b8656807d03ed10000000000d8ac297368de27e58b3c40c768bfbc64bd76e1abe63bea50544d0e8cabd1f7e864098a6affff001d6c015cc3");
        if (v1.size() != BTC::HeaderSizeV1)
            throw Exception(QString("the v1 vector deserialized to %1 bytes, expected 80").arg(v1.size()));
        if (BTC::HeaderSizeFor(v1) != BTC::HeaderSizeV1)
            throw Exception("an 80-byte header was misdetected as v2");
        if (BTC::HeaderPoWHashRev(v1).toHex() != QByteArray(v1Hash))
            throw Exception("v1 PoW hash is wrong");
        if (BTC::HeaderPoWHashRev(v1) != BTC::HashRev(v1))
            throw Exception("v1 PoW hash did not match plain SHA256d");
        {
            const auto obj = BTC::Deserialize<bitcoin::CBlockHeader>(v1);
            if (obj.m_header_v2)
                throw Exception("an 80-byte header deserialized with the v2 flag set");
            if (BTC::Hash2ByteArrayRev(obj.GetHash()).toHex() != QByteArray(v1Hash))
                throw Exception("CBlockHeader::GetHash() disagrees on the v1 header");
            if (BTC::Serialize(obj) != v1)
                throw Exception("the v1 header did not round-trip through serialization");
        }
        Log() << "headerv2: height 149536 (v1) hashes to " << v1Hash << " with SHA256d OK";

        Log() << "headerv2: all vectors OK";
    }
    const auto t1 = App::registerTest("headerv2", headerV2Tests);
}
#endif
