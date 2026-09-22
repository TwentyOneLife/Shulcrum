#!/usr/bin/env python3
"""Drives an Electrum session across a chain's BLAKE2b activation height.

Run by regtest-activation.sh, which owns the node and the server. Everything here is the protocol
behaviour that cannot be shown by a unit test: what a client is served, and when it is dropped,
while the chain crosses the height at which its headers change size.
"""
import json
import os
import socket
import subprocess
import sys
import time

HOST = "127.0.0.1"
PORT = int(os.environ["SHULCRUM_TCP_PORT"])
CLI = os.environ["BITCOIN_CLI"].split()
ACTIVATION = int(os.environ["ACTIVATION_HEIGHT"])
V2_HEX_LEN = 164 * 2
V1_HEX_LEN = 80 * 2

failures = []


def check(ok, what):
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        failures.append(what)


def cli(*args):
    return subprocess.run(CLI + list(args), capture_output=True, text=True, check=True).stdout.strip()


class Client:
    """A line-delimited JSON-RPC session, which is all the Electrum protocol is."""

    def __init__(self, timeout=30):
        self.sock = socket.create_connection((HOST, PORT), timeout=timeout)
        self.buf = b""
        self.n = 0

    def call(self, method, params=()):
        self.n += 1
        self.sock.sendall(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method,
                                      "params": list(params)}).encode() + b"\n")
        return self.read()

    def read(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                return None  # server closed the connection
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line)

    def closed_within(self, seconds):
        """True if the server closes the connection within the deadline, notifications aside."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            self.sock.settimeout(max(0.5, deadline - time.time()))
            try:
                msg = self.read()
            except socket.timeout:
                continue
            if msg is None:
                return True
            if msg.get("method") == "blockchain.headers.subscribe":
                hexstr = msg["params"][0]["hex"]
                check(len(hexstr) == V1_HEX_LEN,
                      f"a notification sent to this client carried a v1 header ({len(hexstr)//2} bytes)")
        return False

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def err_text(reply):
    return (reply or {}).get("error", {}).get("message", "")


print(f"chain is below its activation height ({ACTIVATION}), so nothing has changed yet")
old = Client()
check(old.call("server.version", ["probe", "1.4"])["result"][1] == "1.4", "a 1.4 client negotiates 1.4")
sub = old.call("blockchain.headers.subscribe")["result"]
check(len(sub["hex"]) == V1_HEX_LEN, "it is served the tip, which is still an 80-byte header")
feat = old.call("server.features")["result"]
check("blake2b_fork" not in feat, "server.features carries no fork point before the fork")
check(feat["protocol_max"] == "1.7", "the offered maximum is unchanged at 1.7")

print(f"mining past height {ACTIVATION}")
addr = cli("getnewaddress")
cli("generatetoaddress", str(ACTIVATION + 5), addr)
for _ in range(120):
    probe = Client()
    probe.call("server.version", ["probe", ["1.3", "1.8"]])
    tip = probe.call("blockchain.headers.get_tip")
    probe.close()
    if tip and tip.get("result", {}).get("height", 0) >= ACTIVATION:
        break
    time.sleep(1)

print("the chain has crossed it, with a client subscribed since before")
check(old.closed_within(60), "the subscriber that cannot read a v2 header is disconnected")
old.close()

print("a client below 1.8 may connect, and is refused every header")
low = Client()
check(low.call("server.version", ["probe", "1.4"])["result"][1] == "1.4",
      "connecting at 1.4 still works, so a client that never asks for a header is unaffected")
refusal = low.call("blockchain.block.header", [ACTIVATION])
check("1.8" in err_text(refusal), "a header request is refused, and the reason names protocol 1.8")
check(low.closed_within(10), "and the connection is closed, so it reconnects and renegotiates")
low.close()

print("a client at 1.8 is served the chain")
new = Client()
check(new.call("server.version", ["probe", ["1.3", "1.8"]])["result"][1] == "1.8",
      "a chain with v2 headers offers 1.8")
hdr = new.call("blockchain.block.header", [ACTIVATION])["result"]
check(len(hdr) == V2_HEX_LEN, f"the activation header is served whole ({V2_HEX_LEN} hex characters)")
feat = new.call("server.features")["result"]
fork = feat.get("blake2b_fork", {})
check(feat["protocol_max"] == "1.8", "server.features reports the raised maximum")
check(fork.get("height") == ACTIVATION, "blake2b_fork reports the activation height")
check(fork.get("hash") == cli("getblockhash", str(ACTIVATION)),
      "blake2b_fork's hash is the block hash the node reports for that height")
check(fork.get("header_bytes") == 164 and fork.get("block_hash") == "blake2b",
      "blake2b_fork states the header size and the hash function")
coinbase_of = lambda h: json.loads(cli("getblock", cli("getblockhash", str(h))))["tx"][0]
for height in (ACTIVATION - 10, ACTIVATION + 1):
    reply = new.call("blockchain.transaction.get_confirmed_blockhash", [coinbase_of(height)])
    layout = "v1" if height < ACTIVATION else "v2"
    check(reply["result"]["block_hash"] == cli("getblockhash", str(height)),
          f"the block hash reported for a transaction in a {layout} block is the node's own")

algos = new.call("blockchain.pow_algorithms")["result"]
check({"from_height": ACTIVATION, "algorithm": "blake2b-v2"} in algos,
      "pow_algorithms agrees about where the algorithm changes")
new.close()

print()
if failures:
    print(f"FAILED: {len(failures)}")
    sys.exit(1)
print("all checks passed")
