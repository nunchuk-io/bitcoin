#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import argparse
import json

def perform_pre_checks():
    mock_result_path = os.path.join(os.getcwd(), "mock_result")
    if(os.path.isfile(mock_result_path)):
        f = open(mock_result_path, "r", encoding="utf8")
        mock_result = f.read()
        f.close()
        if mock_result[0]:
            sys.exit(int(mock_result[0]))

def enumerate(args):
  sys.stdout.write(json.dumps([{"fingerprint": "00000001"}, {"fingerprint": "00000002"}]))

def getdescriptors(args):
    xpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"

    sys.stdout.write(json.dumps({
        "receive": [
            "pkh([00000001/44'/1'/" + args.account + "']" + xpub + "/0/*)#vt6w3l3j",
            "sh(wpkh([00000001/49'/1'/" + args.account + "']" + xpub + "/0/*))#r0grqw5x",
            "wpkh([00000001/84'/1'/" + args.account + "']" + xpub + "/0/*)#x30uthjs"
        ],
        "internal": [
            "pkh([00000001/44'/1'/" + args.account + "']" + xpub + "/1/*)#all0v2p2",
            "sh(wpkh([00000001/49'/1'/" + args.account + "']" + xpub + "/1/*))#kwx4c3pe",
            "wpkh([00000001/84'/1'/" + args.account + "']" + xpub + "/1/*)#h92akzzg"
        ]
    }))


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

def signtx(args):
    f = open(os.path.join(os.getcwd(), "mock_psbt"), "r")
    mock_psbt = f.read()
    f.close()

    if args.fingerprint == "00000001" :
        sys.stdout.write(json.dumps({
            "psbt": mock_psbt,
            "complete": True
        }))
    else:
        sys.stdout.write(json.dumps({"psbt": args.psbt}))

parser = argparse.ArgumentParser(prog='./signer.py', description='External signer mock')
parser.add_argument('--fingerprint')
parser.add_argument('--stdin', action='store_true')
parser.add_argument('--testnet', action='store_true')
subparsers = parser.add_subparsers()

parser_enumerate = subparsers.add_parser('enumerate', help='list available signers')
parser_enumerate.set_defaults(func=enumerate)

parser_getdescriptors = subparsers.add_parser('getdescriptors')
parser_getdescriptors.set_defaults(func=getdescriptors)
parser_getdescriptors.add_argument('--account', metavar='account')

parser_displayaddress = subparsers.add_parser('displayaddress', help='display address on signer')
parser_displayaddress.add_argument('--desc', metavar='desc')
parser_displayaddress.set_defaults(func=displayaddress)

parser_signtx = subparsers.add_parser('signtx')
parser_signtx.add_argument('psbt', metavar='psbt')

parser_signtx.set_defaults(func=signtx)

if len(sys.argv) == 1:
  args = parser.parse_args(['-h'])
  exit()

if not sys.stdin.isatty():
    buffer = sys.stdin.read()
    if buffer and buffer.rstrip() != "":
       sys.argv.extend(buffer.rstrip().split(" "))

args = parser.parse_args()

perform_pre_checks()

args.func(args)