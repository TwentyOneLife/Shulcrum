//
// Fulcrum - A fast & nimble SPV Server for Bitcoin & friends
//
// See BTC_HeaderV2.h.  The pipeline below is a transcription of
// CBlockHeader::GetHash() in Bitcoin Knots v29.4.1.knots20260508rc2
// (src/primitives/block.cpp) and is verified against real testnet4 blocks in
// the "headerv2" test at the bottom of this file.
//
#include "BTC_HeaderV2.h"

#include "BTC.h"

#include "bitcoin/crypto/blake2b.h"
#include "bitcoin/crypto/sha256.h"

#include "App.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace {

    using Bytes = std::vector<uint8_t>;

    inline uint32_t ReadLE32(const uint8_t *p) noexcept {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    }

    std::array<uint8_t, 32> Sha256(const uint8_t *data, size_t len) {
        std::array<uint8_t, 32> out;
        bitcoin::CSHA256().Write(data, len).Finalize(out.data());
        return out;
    }

    /// BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
    std::array<uint8_t, 32> TaggedHash(const char *tag, const Bytes &data) {
        const auto th = Sha256(reinterpret_cast<const uint8_t *>(tag), std::strlen(tag));
        bitcoin::CSHA256 h;
        h.Write(th.data(), th.size());
        h.Write(th.data(), th.size());
        h.Write(data.data(), data.size());
        std::array<uint8_t, 32> out;
        h.Finalize(out.data());
        return out;
    }

    void Append(Bytes &b, const uint8_t *p, size_t n) { b.insert(b.end(), p, p + n); }
    void Append(Bytes &b, const std::array<uint8_t, 32> &a) { Append(b, a.data(), a.size()); }
    void AppendLE32(Bytes &b, uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8*i))); }

    std::array<uint8_t, 32> Blake2b256(const Bytes &in) {
        std::array<uint8_t, 32> out;
        if (0 != blake2b_nokey(out.data(), out.size(), in.data(), in.size()))
            throw std::runtime_error("blake2b_nokey failed");
        return out;
    }

    /// Field offsets of the v2 serialization, in wire order.
    namespace Off {
        constexpr size_t version = 0, prev = 4, merkle = 36, time = 68, bits = 72, nonce = 76,
                         nonce2 = 80, nonce3 = 84, extranonce = 88, timeOffset = 104, txcount = 108,
                         flags = 110, clearBits = 111, xorKey = 112, height = 128, mmRhs = 132;
    }

} // namespace

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
        const auto *h = reinterpret_cast<const uint8_t *>(header.data());

        if (!IsHeaderV2(header)) {
            if (header.size() != size_t(HeaderSizeV1))
                throw std::invalid_argument("HeaderPoWHashRev: v1 header is not 80 bytes");
            return BTC::HashRev(header.toByteArray(false));
        }
        if (header.size() != size_t(HeaderSizeV2))
            throw std::invalid_argument("HeaderPoWHashRev: v2 header is not 164 bytes");

        // The pooling miner only learns m_xor_key when it finds a block, which is what
        // stops it from recognizing (and withholding) one.  We have the full header here,
        // so we can always reproduce the mask.
        Bytes xorKey(h + Off::xorKey, h + Off::xorKey + 16);
        const auto xorKeyHash = TaggedHash("Bitcoin block hash PoW XOR key", xorKey);

        std::array<uint8_t, 32> xorMask{}; // all zeroes when solo mining (null key)
        if (std::any_of(xorKey.begin(), xorKey.end(), [](uint8_t c) { return c != 0u; })) {
            xorMask = TaggedHash("Bitcoin block hash PoW XOR mask", xorKey);
            const unsigned clearBits = h[Off::clearBits];
            const unsigned clearBytes = clearBits / 8u;
            std::fill_n(xorMask.begin(), std::min<size_t>(clearBytes, xorMask.size()), uint8_t{0});
            if (clearBytes < xorMask.size())
                xorMask[clearBytes] &= uint8_t(0xffu >> (clearBits % 8u));
        }

        // hashPrevBlock reversed out of wire order, which is the order both tagged hashes below want.
        Bytes prevSane(h + Off::prev, h + Off::prev + 32);
        std::reverse(prevSane.begin(), prevSane.end());
        auto prevHidden = TaggedHash("Bitcoin prevblock header, hashed", prevSane);

        // h1 commits to everything the mining machine never sees, so the hasher cannot be
        // bricked by a future version, time or difficulty.
        Bytes b1;
        b1.reserve(119);
        Append(b1, h + Off::version, 4);         // complete version word, bit 31 included
        Append(b1, prevSane.data(), 32);
        Append(b1, h + Off::height, 4);
        Append(b1, h + Off::merkle, 32);
        Append(b1, h + Off::time, 4);            // time as it appears on the wire
        b1.push_back(0u);                        // reserved for extended 40-bit time
        Append(b1, h + Off::bits, 4);
        AppendLE32(b1, uint32_t(h[Off::txcount]) | (uint32_t(h[Off::txcount + 1]) << 8)); // u16 widened to u32
        b1.push_back(h[Off::flags]);
        b1.push_back(h[Off::clearBits]);
        Append(b1, xorKeyHash);
        if (b1.size() != 119) throw std::runtime_error("HeaderPoWHashRev: h1 preimage is not 119 bytes");
        const auto h1 = TaggedHash("Bitcoin block header 1", b1);

        Bytes b2;
        b2.reserve(96);
        Append(b2, h1);
        b2.insert(b2.end(), 32, 0u);             // two null uint128s
        Append(b2, h + Off::mmRhs, 32);
        if (b2.size() != 96) throw std::runtime_error("HeaderPoWHashRev: h2 preimage is not 96 bytes");
        const auto h2 = TaggedHash("Merge-mining hook", b2);

        // What a Stratum v1 miner receives as "coinb1" + extranonce.
        Bytes work;
        work.reserve(52);
        AppendLE32(work, 0u);
        Append(work, h2);
        Append(work, h + Off::extranonce, 16);
        if (work.size() != 52) throw std::runtime_error("HeaderPoWHashRev: Sv1 preimage is not 52 bytes");
        auto inner = Blake2b256(work);

        // What the ASIC itself hashes, laid out per the profile in the low 2 bits of m_flags.
        Bytes asic;
        asic.reserve(112);
        switch (h[Off::flags] & 3u) {
        case 3:
            asic.insert(asic.end(), 32, 0u);
            [[fallthrough]];
        case 2:
            asic.insert(asic.end(), 48, 0u);
            Append(asic, h2);
            Append(asic, h + Off::nonce, 4);
            Append(asic, h + Off::nonce2, 4);
            Append(asic, h + Off::timeOffset, 4);
            Append(asic, h + Off::nonce3, 4);
            Append(asic, inner);
            break;
        case 0:
            // Profile 0 is the Siacoin ASIC layout: the first 6 bytes of the prev commitment
            // are zeroed because in a Sia header those bytes mean something else.
            std::fill_n(prevHidden.begin(), 6, uint8_t{0});
            Append(asic, prevHidden);
            Append(asic, h + Off::nonce, 4);
            Append(asic, h + Off::nonce2, 4);
            Append(asic, h + Off::timeOffset, 4);
            Append(asic, h + Off::nonce3, 4);
            Append(asic, inner);
            break;
        case 1:
            Append(asic, h + Off::nonce, 4);
            Append(asic, h + Off::nonce2, 4);
            Append(asic, h + Off::nonce3, 4);
            Append(asic, h + Off::timeOffset, 4);
            Append(asic, inner);
            Append(asic, h2);
            break;
        }
        const auto outer = Blake2b256(asic);

        // GetHash() writes the XORed bytes back to front and the result is then printed
        // reversed again, so what a client sees is simply hash ^ mask in wire order.
        QByteArray ret(32, Qt::Uninitialized);
        auto *r = reinterpret_cast<uint8_t *>(ret.data());
        for (size_t i = 0; i < outer.size(); ++i)
            r[i] = uint8_t(outer[i] ^ xorMask[i]);
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
        Log() << "headerv2: height 149536 (v1) hashes to " << v1Hash << " with SHA256d OK";

        Log() << "headerv2: all vectors OK";
    }
    const auto t1 = App::registerTest("headerv2", headerV2Tests);
}
#endif
