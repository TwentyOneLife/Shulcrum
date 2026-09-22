//
// Shulcrum - A BLAKE2b-capable fork of Fulcrum
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
#include "ProtocolV2.h"

#include "BTC_HeaderV2.h"
#include "ServerMisc.h"

#ifdef ENABLE_TESTS
#include "App.h"
#include "Util.h"
#endif

namespace ProtocolV2 {

const char * const HeaderRefusal =
    "This chain uses 164-byte block headers with a BLAKE2b block hash, which a client below "
    "protocol 1.8 cannot read. Reconnect and negotiate 1.8. Refusing rather than serving headers "
    "it would misinterpret.";

Version maxNegotiable(bool chainHasV2)
{
    return chainHasV2 ? ServerMisc::MaxProtocolVersionV2 : ServerMisc::MaxProtocolVersion;
}

bool mayServeHeaders(bool chainHasV2, const Version &negotiated)
{
    return !chainHasV2 || negotiated >= ServerMisc::MaxProtocolVersionV2;
}

QVariantMap forkPointMap(BlockHeight activationHeight, const QByteArray &blockHashHex)
{
    return QVariantMap{
        { QByteArrayLiteral("height"), qlonglong(activationHeight) },
        { QByteArrayLiteral("hash"), QString::fromLatin1(blockHashHex) },
        // Stated rather than implied, so a client need not know our header sizes to read this.
        { QByteArrayLiteral("header_bytes"), int(BTC::HeaderSizeV2) },
        { QByteArrayLiteral("block_hash"), QByteArrayLiteral("blake2b") },
    };
}

} // namespace ProtocolV2

#ifdef ENABLE_TESTS
namespace {
    void protocolV2Tests()
    {
        using namespace ProtocolV2;
        const Version v14{1,4,0}, v16{1,6,0}, v17{1,7,0}, v18{1,8,0}, none{};

        // A chain with no v2 header behaves exactly as it did before any of this existed. Shulcrum
        // serves BTC, BCH and Litecoin too, and none of them may change.
        if (maxNegotiable(false) != ServerMisc::MaxProtocolVersion)
            throw Exception("a chain with no v2 header must offer the unchanged maximum");
        for (const auto &v : {none, v14, v16, v17, v18})
            if (!mayServeHeaders(false, v))
                throw Exception("a chain with no v2 header must serve headers to anyone");

        // A chain that has produced one offers 1.8 and serves headers only to a client that took it.
        if (maxNegotiable(true) != v18)
            throw Exception("a v2 chain must offer 1.8");
        for (const auto &v : {none, v14, v16, v17})
            if (mayServeHeaders(true, v))
                throw Exception("a v2 chain must not serve headers below 1.8");
        if (!mayServeHeaders(true, v18))
            throw Exception("a v2 chain must serve headers at 1.8");
        if (!mayServeHeaders(true, Version{1,9,0}))
            throw Exception("a version above 1.8 must be served, not refused");
        Log() << "protocolv2: negotiation and the serve rule OK";

        // The mainnet fork point, as the node reports it and as the specification's wallet checks
        // it. A wrong value here is worse than none: that wallet refuses a server that contradicts
        // what it expects.
        static constexpr auto mainnetHash = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb";
        const auto m = forkPointMap(961640, mainnetHash);
        if (m.value("height").toLongLong() != 961640)
            throw Exception("fork point height is wrong");
        if (m.value("hash").toString() != QString(mainnetHash))
            throw Exception("fork point hash is wrong");
        if (m.value("header_bytes").toInt() != BTC::HeaderSizeV2)
            throw Exception("fork point header_bytes is wrong");
        if (m.value("block_hash").toString() != QStringLiteral("blake2b"))
            throw Exception("fork point block_hash is wrong");
        if (m.size() != 4)
            throw Exception("fork point carries fields the specification does not define");
        Log() << "protocolv2: blake2b_fork at height 961640 hashes to " << mainnetHash << " OK";
    }
    const auto t1 = App::registerTest("protocolv2", protocolV2Tests);
}
#endif
