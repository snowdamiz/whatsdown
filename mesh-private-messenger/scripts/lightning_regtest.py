#!/usr/bin/env python3
"""Owned Bitcoin/LND regtest fixture for credit integration proofs, never live funds."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOOLS = ROOT / ".morse/lightning-tools"


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def await_value(action, predicate=lambda value: bool(value), timeout=45):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = action()
            if predicate(value):
                return value
        except (OSError, urllib.error.URLError, RuntimeError, ValueError) as error:
            last = type(error).__name__
        time.sleep(0.15)
    raise RuntimeError(f"regtest condition timed out ({last})")


class LightningRegtest:
    def __init__(self):
        self.stack = ExitStack()
        self.children = []
        self.counter = 0

    def spawn(self, binary, arguments, name):
        log = self.stack.enter_context((self.work / f"{name}.log").open("wb"))
        child = subprocess.Popen([str(binary), *arguments], stdout=log, stderr=subprocess.STDOUT)
        self.children.append(child)
        return child

    def bitcoin(self, method, *params):
        self.counter += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self.counter, "method": method, "params": list(params)}).encode()
        request = urllib.request.Request(self.bitcoin_origin, data=body, headers={
            "Authorization": "Basic " + base64.b64encode(f"fixture:{self.password}".encode()).decode(),
            "Content-Type": "application/json",
        })
        with urllib.request.urlopen(request, timeout=10) as response:
            value = json.load(response)
        if value.get("error"):
            raise RuntimeError("regtest RPC rejected " + method)
        return value["result"]

    def lnd(self, name, path, body=None, timeout=15):
        node = self.nodes[name]
        macaroon = (node["directory"] / "data/chain/bitcoin/regtest/admin.macaroon").read_bytes().hex()
        request = urllib.request.Request(node["origin"] + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Grpc-Metadata-macaroon": macaroon, "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)

    def mine(self, count):
        return self.bitcoin("generatetoaddress", count, self.miner)

    def pay(self, invoice):
        response = self.lnd("payer", "/v2/router/send", {
            "payment_request": invoice,
            "timeout_seconds": 90,
            "fee_limit_msat": "10000",
            "no_inflight_updates": True,
        }, timeout=110)
        value = response.get("result", response)
        if value.get("status") != "SUCCEEDED":
            raise AssertionError("regtest payment failed: " + str(value.get("failure_reason", "missing terminal status")))
        return value

    def __enter__(self):
        self.work = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="morse-ln-regtest-", dir="/tmp")))
        try:
            tools = Path(os.environ.get("LIGHTNING_TEST_TOOLS", DEFAULT_TOOLS))
            bitcoind = Path(os.environ.get("BITCOIND", tools / "bitcoin-31.1/bin/bitcoind"))
            lnd = Path(os.environ.get("LND", tools / "lnd-darwin-arm64-v0.21.4-beta/lnd"))
            if not bitcoind.is_file() or not lnd.is_file():
                raise RuntimeError("set BITCOIND and LND to verified local test binaries")
            self.password = secrets.token_hex(32)
            btc_dir = self.work / "bitcoin"
            btc_dir.mkdir(mode=0o700)
            btc_port = port()
            self.bitcoin_origin = f"http://127.0.0.1:{btc_port}"
            config = btc_dir / "bitcoin.conf"
            config.write_text(f"regtest=1\nserver=1\nlisten=0\ndnsseed=0\ndiscover=0\ntxindex=1\nfallbackfee=0.0002\nrpcuser=fixture\nrpcpassword={self.password}\n[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport={btc_port}\nport={port()}\n")
            config.chmod(0o600)
            self.spawn(bitcoind, [f"-datadir={btc_dir}"], "bitcoin")
            await_value(lambda: self.bitcoin("getblockchaininfo"), lambda value: value["chain"] == "regtest")
            self.bitcoin("createwallet", "fixture")
            self.miner = self.bitcoin("getnewaddress")
            self.mine(101)
            self.nodes = {}
            for name in ("issuer", "payer"):
                directory = self.work / name
                directory.mkdir(mode=0o700)
                rest_port, peer_port, rpc_port = port(), port(), port()
                self.nodes[name] = {"directory": directory, "origin": f"http://127.0.0.1:{rest_port}", "peer_port": peer_port}
                config = directory / "lnd.conf"
                config.write_text(f"[Application Options]\nnoseedbackup=1\nno-rest-tls=1\nrestlisten=127.0.0.1:{rest_port}\nrpclisten=127.0.0.1:{rpc_port}\nlisten=127.0.0.1:{peer_port}\nmaxpendingchannels=4\ndebuglevel=warn\n[Bitcoin]\nbitcoin.regtest=1\nbitcoin.node=bitcoind\n[Bitcoind]\nbitcoind.rpchost=127.0.0.1:{btc_port}\nbitcoind.rpcuser=fixture\nbitcoind.rpcpass={self.password}\nbitcoind.rpcpolling=1\nbitcoind.blockpollinginterval=100ms\nbitcoind.txpollinginterval=100ms\n")
                config.chmod(0o600)
                self.spawn(lnd, [f"--lnddir={directory}"], name)
            for name in self.nodes:
                info = await_value(lambda: self.lnd(name, "/v1/getinfo"), lambda value: value.get("synced_to_chain", False))
                if info.get("chains") != [{"chain": "bitcoin", "network": "regtest"}]:
                    raise RuntimeError("refusing non-regtest LND")
                self.nodes[name]["public_key"] = info["identity_pubkey"]
            address = self.lnd("payer", "/v1/newaddress?type=0")["address"]
            self.bitcoin("sendtoaddress", address, 1)
            self.mine(6)
            await_value(lambda: self.lnd("payer", "/v1/balance/blockchain"), lambda value: int(value.get("confirmed_balance", 0)) >= 100_000_000)
            target = self.nodes["issuer"]
            self.lnd("payer", "/v1/peers", {"addr": {"pubkey": target["public_key"], "host": f"127.0.0.1:{target['peer_port']}"}, "perm": False})
            self.lnd("payer", "/v1/channels", {"node_pubkey": base64.b64encode(bytes.fromhex(target["public_key"])).decode(), "local_funding_amount": "1000000", "private": True, "sat_per_vbyte": "2"})
            self.mine(6)
            await_value(lambda: self.lnd("payer", "/v1/channels"), lambda value: any(row.get("active") for row in value.get("channels", [])))
            await_value(lambda: self.lnd("issuer", "/v1/channels"), lambda value: any(row.get("active") for row in value.get("channels", [])))
            await_value(lambda: self.lnd("payer", "/v1/graph/routes/" + target["public_key"] + "/5000"), lambda value: bool(value.get("routes")))
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
        for child in reversed(self.children):
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        self.stack.close()


def smoke():
    with LightningRegtest() as fixture:
        preimage = secrets.token_bytes(32)
        digest = hashlib.sha256(preimage).hexdigest()
        invoice = fixture.lnd("issuer", "/v2/invoices/hodl", {"hash": base64.b64encode(bytes.fromhex(digest)).decode(), "value_msat": "5000000", "memo": "Morse credits", "expiry": "900", "private": True})
        with ThreadPoolExecutor(max_workers=1) as executor:
            payment = executor.submit(fixture.pay, invoice["payment_request"])
            def observe():
                if payment.done():
                    try:
                        payment.result()
                    except Exception as error:
                        raise AssertionError("regtest payment request failed") from error
                return fixture.lnd("issuer", "/v1/invoice/" + digest)
            accepted = await_value(observe, lambda value: value.get("state") == "ACCEPTED")
            if int(accepted["amt_paid_msat"]) != 5_000_000:
                raise RuntimeError("unexpected held amount")
            fixture.lnd("issuer", "/v2/invoices/settle", {"preimage": base64.b64encode(preimage).decode()})
            outcome = payment.result(timeout=45)
            if outcome.get("payment_error"):
                raise RuntimeError("regtest Lightning payment failed")
        settled = fixture.lnd("issuer", "/v1/invoice/" + digest)
        if settled["state"] != "SETTLED":
            raise RuntimeError("invoice is not settled")
        print(json.dumps({"proof": "owned_bitcoin_lnd_regtest", "hold": "ACCEPTED", "settle": "SETTLED", "amount_msat": settled["amt_paid_msat"], "live_funds": False}))


if __name__ == "__main__":
    smoke()
