// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <outputtype.h>

#include <pubkey.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <util/vector.h>

#include <assert.h>
#include <string>

static const std::string OUTPUT_TYPE_STRING_LEGACY = "legacy";
static const std::string OUTPUT_TYPE_STRING_P2SH_SEGWIT = "p2sh-segwit";
static const std::string OUTPUT_TYPE_STRING_BECH32 = "bech32";

bool ParseOutputType(const std::string& type, OutputType& output_type)
{
    if (type == OUTPUT_TYPE_STRING_LEGACY) {
        output_type = OutputType::LEGACY;
        return true;
    } else if (type == OUTPUT_TYPE_STRING_P2SH_SEGWIT) {
        output_type = OutputType::P2SH_SEGWIT;
        return true;
    } else if (type == OUTPUT_TYPE_STRING_BECH32) {
        output_type = OutputType::BECH32;
        return true;
    }
    return false;
}

const std::string& FormatOutputType(OutputType type)
{
    switch (type) {
    case OutputType::LEGACY: return OUTPUT_TYPE_STRING_LEGACY;
    case OutputType::P2SH_SEGWIT: return OUTPUT_TYPE_STRING_P2SH_SEGWIT;
    case OutputType::BECH32: return OUTPUT_TYPE_STRING_BECH32;
    default: assert(false);
    }
}

CTxDestination GetDestinationForKey(const CPubKey& key, OutputType type)
{
    switch (type) {
    case OutputType::LEGACY: return PKHash(key);
    case OutputType::P2SH_SEGWIT:
    case OutputType::BECH32: {
        if (!key.IsCompressed()) return PKHash(key);
        CTxDestination witdest = WitnessV0KeyHash(PKHash(key));
        CScript witprog = GetScriptForDestination(witdest);
        if (type == OutputType::P2SH_SEGWIT) {
            return ScriptHash(witprog);
        } else {
            return witdest;
        }
    }
    default: assert(false);
    }
}

std::vector<CTxDestination> GetAllDestinationsForKey(const CPubKey& key)
{
    PKHash keyid(key);
    CTxDestination p2pkh{keyid};
    if (key.IsCompressed()) {
        CTxDestination segwit = WitnessV0KeyHash(keyid);
        CTxDestination p2sh = ScriptHash(GetScriptForDestination(segwit));
        return Vector(std::move(p2pkh), std::move(p2sh), std::move(segwit));
    } else {
        return Vector(std::move(p2pkh));
    }
}

CTxDestination AddAndGetDestinationForScript(FillableSigningProvider& keystore, const CScript& script, OutputType type)
{
    // Add script to keystore
    keystore.AddCScript(script);
    ScriptHash sh(script);
    // Note that scripts over 520 bytes are not yet supported.
    switch (type) {
    case OutputType::LEGACY:
        keystore.AddCScript(GetScriptForDestination(sh));
        return sh;
    case OutputType::P2SH_SEGWIT:
    case OutputType::BECH32: {
        CTxDestination witdest = WitnessV0ScriptHash(script);
        CScript witprog = GetScriptForDestination(witdest);
        // Check if the resulting program is solvable (i.e. doesn't use an uncompressed key)
        if (!IsSolvable(keystore, witprog)) {
            // Since the wsh is invalid, add and return the sh instead.
            keystore.AddCScript(GetScriptForDestination(sh));
            return sh;
        }
        // Add the redeemscript, so that P2WSH and P2SH-P2WSH outputs are recognized as ours.
        keystore.AddCScript(witprog);
        if (type == OutputType::BECH32) {
            return witdest;
        } else {
            ScriptHash sh_w = ScriptHash(witprog);
            keystore.AddCScript(GetScriptForDestination(sh_w));
            return sh_w;
        }
    }
    default: assert(false);
    }
}

Optional<OutputType> DetermineOutputType(const CScript& script, const SigningProvider& provider)
{
    std::vector<std::vector<unsigned char>> solutions;
    txnouttype script_type = Solver(script, solutions);

    switch(script_type) {
    case TX_PUBKEYHASH:
        return OutputType::LEGACY;
    case TX_WITNESS_V0_SCRIPTHASH:
    case TX_WITNESS_V0_KEYHASH:
    case TX_WITNESS_UNKNOWN:
        return OutputType::BECH32;
    case TX_SCRIPTHASH: {
        CScriptID script_id = CScriptID(uint160(solutions[0]));
        CScript redeem_script;
        if (provider.GetCScript(script_id, redeem_script)) {
            script_type = Solver(redeem_script, solutions);
            switch(script_type) {
            case TX_WITNESS_V0_SCRIPTHASH:
            case TX_WITNESS_V0_KEYHASH:
            case TX_WITNESS_UNKNOWN:
                return OutputType::P2SH_SEGWIT;
            default:
                return OutputType::LEGACY;
            }
        }
        return nullopt;
    }
    default:
        return nullopt;
    }
}
