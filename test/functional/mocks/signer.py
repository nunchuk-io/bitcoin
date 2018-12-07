#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import sys
import argparse
import json

def enumerate(args):
  sys.stdout.write(json.dumps([{"fingerprint": "00000001"}, {"fingerprint": "00000002"}, {"fingerprint": "d95fc47e"}]))

def getkeys(args):
    if args.desc == "wpkh([00000001/84h/1h/0h]/0/*)":
        sys.stdout.write(json.dumps(["wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*)"]))
    elif args.desc == "wpkh([00000001/84h/1h/0h]/1/*)":
        sys.stdout.write(json.dumps(["wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/*)"]))
    elif args.desc == "sh(wpkh([00000001/49h/1h/0h]/0/*))":
        sys.stdout.write(json.dumps(["sh(wpkh([00000001/49h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*))"]))
    elif args.desc == "sh(wpkh([00000001/49h/1h/0h]/1/*))":
        sys.stdout.write(json.dumps(["sh(wpkh([00000001/49h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/*))"]))
    elif args.desc == "pkh([00000001/44h/1h/0h]/0/*)":
        sys.stdout.write(json.dumps(["pkh([00000001/44h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*)"]))
    elif args.desc == "pkh([00000001/44h/1h/0h]/1/*)":
        sys.stdout.write(json.dumps(["pkh([00000001/44h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/*)"]))
    else:
        print("Descriptor request not recognized: " + args.desc)
        exit(1)

def displayaddress(args):
    # Several descriptor formats are acceptable, so allowing for potential
    # changes to InferDescriptor:
    expected_desc = [
        "wpkh([00000001/84'/1'/0'/0/0]0297dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)",
        "wpkh([00000001/84'/1'/0']tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
    ]
    if args.desc not in expected_desc:
        return sys.stdout.write(json.dumps({"error": "Unexpected descriptor", "desc": args.desc}))

    return sys.stdout.write(json.dumps(None))

parser = argparse.ArgumentParser(prog='./signer.py', description='External signer mock')
parser.add_argument('--fingerprint')
parser.add_argument('--testnet', action='store_true')
subparsers = parser.add_subparsers()

parser_enumerate = subparsers.add_parser('enumerate', help='list available signers')
parser_enumerate.set_defaults(func=enumerate)

parser_getkeys = subparsers.add_parser('getkeys', help='get keys from signer')
parser_getkeys.add_argument('desc', metavar='desc')
parser_getkeys.set_defaults(func=getkeys)

parser_displayaddress = subparsers.add_parser('displayaddress', help='display address on signer')
parser_displayaddress.add_argument('--desc', metavar='desc')
parser_displayaddress.set_defaults(func=displayaddress)

if len(sys.argv) == 1:
  args = parser.parse_args(['-h'])
  exit()

args = parser.parse_args()

args.func(args)
