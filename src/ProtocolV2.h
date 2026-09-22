//
// Shulcrum - A BLAKE2b-capable fork of Fulcrum
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
#pragma once

#include "BlockProcTypes.h"
#include "Version.h"

#include <QByteArray>
#include <QVariantMap>

/// The Electrum protocol rules that depend on whether a chain serves v2 (164-byte) headers.
///
/// Kept apart from the call sites, and free of any server state, so the rules can be read and
/// tested on their own. See docs/electrum-header-v2.md in paulscode/electrs-pruned, the draft
/// specification this implements.
namespace ProtocolV2 {

    /// The highest version a client may negotiate on this chain.
    ///
    /// A chain that has produced a v2 header offers 1.8, which is the version that states a client
    /// reads a header's length from its version word rather than assuming 80 bytes. Every other
    /// chain is unchanged.
    Version maxNegotiable(bool chainHasV2);

    /// May a client that negotiated this version be served block headers?
    ///
    /// Refusing at `server.version` alone would not do: a chain crosses its activation height while
    /// clients are connected, so a client that negotiated below 1.8 beforehand would be served a v2
    /// header the moment the tip reaches it. That is what this exists to prevent, and it happens on
    /// every fresh sync of a chain that has already forked.
    ///
    /// A client that never sent `server.version` negotiated nothing and is treated as below 1.8: it
    /// has not said it can read this chain. Protocol 1.6 requires that message first in any case.
    ///
    /// Connecting is deliberately still allowed below 1.8, unlike the specification's server, which
    /// refuses at the handshake. Clients that never ask for a header work correctly on this chain,
    /// and the explorer this server exists to feed is one of them: it negotiates 1.4 and asks only
    /// about scripthashes. The safety property is unchanged, because it is a header reaching a
    /// client that cannot read it that does harm, and no header does.
    bool mayServeHeaders(bool chainHasV2, const Version &negotiated);

    /// What `server.features` reports as `blake2b_fork`, in the shape the specification's server
    /// emits and its wallet checks.
    ///
    /// `genesis_hash` cannot answer "which chain is this" for a fork that keeps its history: this
    /// chain shares its genesis with the chain it forked from, so two servers report the same one
    /// and serve chains that diverge at the activation height. A fork point needs no registry and a
    /// client can check it against the headers the server then serves.
    ///
    /// `activationHeight` is the first height whose header is v2, and `blockHashHex` is that
    /// block's id in display order.
    QVariantMap forkPointMap(BlockHeight activationHeight, const QByteArray &blockHashHex);

    /// Why a header was refused, for the client's log. It names the cause, because "unsupported
    /// protocol version" would send whoever reads it after the wrong fault.
    extern const char * const HeaderRefusal;

} // namespace ProtocolV2
