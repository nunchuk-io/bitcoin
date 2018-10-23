#!/usr/bin/env python3
# Copyright (c) 2014-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the dumpprivkey RPC."""

from test_framework import script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    bytes_to_hex_str,
)


class DumpPrivKeyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

    def run_test (self):
        # P2PKH legacy address
        self.log.info("Should output the private key of a P2PKH address")
        address = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())
        privkey = self.nodes[0].dumpprivkey(address['address'])
        self.log.info("Should import the resulting private to obtain the same P2PKH address")
        result = self.nodes[1].importprivkey(privkey)
        assert_equal(result, address['address'])

if __name__ == '__main__':
    DumpPrivKeyTest ().main ()
