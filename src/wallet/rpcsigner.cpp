// Copyright (c) 2018-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>
#include <core_io.h>
#include <key_io.h>
#include <psbt.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/rpcdump.h>
#include <wallet/rpcsigner.h>
#include <wallet/rpcwallet.h>

#ifdef HAVE_BOOST_PROCESS

static UniValue enumeratesigners(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"enumeratesigners\n",
                "Returns a list of external signers from -signer and associates them\n"
                "with the wallet until you stop bitcoind.\n",
                {},
                RPCResult{
                    "{\n"
                    "  \"signers\" : [                              (json array of objects)\n"
                    "    {\n"
                    "      \"masterkeyfingerprint\" : \"fingerprint\" (string) Master key fingerprint\n"
                    "    }\n"
                    "    ,...\n"
                    "  ]\n"
                    "}\n"
                },
                RPCExamples{""}
            }.ToString()
        );
    }

    const std::string command = gArgs.GetArg("-signer", DEFAULT_EXTERNAL_SIGNER);
    if (command == "") throw JSONRPCError(RPC_WALLET_ERROR, "Error: restart bitcoind with -signer=<cmd>");
    std::string chain = gArgs.GetChainName();
    const bool mainnet = chain == CBaseChainParams::MAIN;
    UniValue signers;
    try {
        signers = ExternalSigner::Enumerate(command, pwallet->m_external_signers, mainnet);
    } catch (const ExternalSignerException& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }
    UniValue result(UniValue::VOBJ);
    result.pushKV("signers", signers);
    return result;
}

ExternalSigner *GetSignerForJSONRPCRequest(const JSONRPCRequest& request, int index, CWallet* pwallet) {
    if (pwallet->m_external_signers.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "First call enumeratesigners");
    }

    // If no fingerprint is specified, return the only available signer
    if (request.params.size() < size_t(index + 1) || request.params[index].isNull()) {
        if (pwallet->m_external_signers.size() > 1) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Multiple signers found, please specify which to use");
        }
        return &pwallet->m_external_signers.front();
    }

    const std::string fingerprint = request.params[index].get_str();
    for (ExternalSigner &candidate : pwallet->m_external_signers) {
        if (candidate.m_fingerprint == fingerprint) return &candidate;
    }
    throw JSONRPCError(RPC_WALLET_ERROR, "Signer fingerprint not found");
}

UniValue signerdissociate(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            RPCHelpMan{"signerdissociate",
                "Disossociates external signer from the wallet.\n",
                {
                    {"fingerprint", RPCArg::Type::STR, /* default_val */ "", "Master key fingerprint of signer"},
                },
                RPCResult{"null"},
                RPCExamples{""}
            }.ToString()
        );
    }

    ExternalSigner *signer = GetSignerForJSONRPCRequest(request, 0, pwallet);

    assert(signer != nullptr);
    std::vector<ExternalSigner>::iterator position = std::find(pwallet->m_external_signers.begin(), pwallet->m_external_signers.end(), *signer);
    if (position != pwallet->m_external_signers.end()) pwallet->m_external_signers.erase(position);

    return NullUniValue;
}

static UniValue signerdisplayaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.empty() || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"signerdisplayaddress",
            "Display address on an external signer for verification.\n",
                {
                    {"address",     RPCArg::Type::STR, RPCArg::Optional::NO, /* default_val */ "", "bitcoin address to display"},
                    {"fingerprint", RPCArg::Type::STR, /* default_val */ "", "master key fingerprint of signer"},
                },
                RPCResult{"null"},
                RPCExamples{""}
            }.ToString()
        );
    }

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ExternalSigner *signer = GetSignerForJSONRPCRequest(request, 1, pwallet);

    LOCK(pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());

    // Make sure the destination is valid
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    CScript scriptPubKey = GetScriptForDestination(dest);
    std::unique_ptr<SigningProvider> provider = pwallet->GetSigningProvider(scriptPubKey);
    auto descriptor = InferDescriptor(scriptPubKey, *provider);

    if (!descriptor->IsSolvable()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Key is not solvable");
    }

    // TODO: check that fingerprint and BIP32 path is present (new Descriptor method?)
    // TODO: check that fingerprint matches signer

    signer->displayAddress(descriptor->ToString());

    return UniValue(UniValue::VNULL);
}

std::unique_ptr<Descriptor> ParseDescriptor(const UniValue &descriptor_val, bool must_be_solveable = true, bool must_be_ranged = false) {
    if (!descriptor_val.isStr()) JSONRPCError(RPC_WALLET_ERROR, "Unexpect result");
    FlatSigningProvider provider;
    const std::string desc_str = descriptor_val.getValStr();
    std::unique_ptr<Descriptor> desc = Parse(desc_str, provider, true);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid descriptor: %s", desc_str));
    }
    if (!desc->IsRange()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor must be ranged");
    }
    if (!desc->IsSolvable()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor must be solvable");
    }
    return desc;
}

UniValue signerfetchkeys(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3) {
        throw std::runtime_error(
            RPCHelpMan{"signerfetchkeys",
                "Obtains keys from external signer and imports them into the wallet.\n"
                "Call enumeratesigners first.\n",
                {
                    {"account",     RPCArg::Type::NUM, /* default_val */ "0", "BIP32 account to use"},
                    {"fingerprint", RPCArg::Type::STR, /* default_val */ "", "Master key fingerprint of signer"},
                    // TODO: remove when #16528 can handle infinite range
                    {"range", RPCArg::Type::RANGE, /* default */ "set by -keypool", "The range of HD chain indexes to import (either end or [begin,end])"},
                },
                RPCResult{
                    "[{ \"success\": true }"
                },
                RPCExamples{""}
            }.ToString()
        );
    }

    ExternalSigner *signer = GetSignerForJSONRPCRequest(request, 1, pwallet);

    int account = 0;
    if (!request.params[0].isNull()) {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        account = request.params[0].get_int();
    }

    UniValue signer_res = signer->getDescriptors(account);
    if (!signer_res.isObject()) throw JSONRPCError(RPC_WALLET_ERROR, "Unexpect result");
    const UniValue& receive_descriptor_vals = find_value(signer_res, "receive");
    const UniValue& change_descriptor_vals = find_value(signer_res, "internal");
    if (!receive_descriptor_vals.isArray()) throw JSONRPCError(RPC_WALLET_ERROR, "Unexpect result");
    if (!change_descriptor_vals.isArray()) throw JSONRPCError(RPC_WALLET_ERROR, "Unexpect result");

    uint64_t keypool_target_size = 0;
    keypool_target_size = gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE);
    int64_t range_begin = 0;
    int64_t range_end = 0;
    if (request.params.size() >= 3 && !request.params[2].isNull()) {
        std::tie(range_begin, range_end) = ParseDescriptorRange(request.params[2]);
    } else {
        range_end = keypool_target_size - 1;
    }
    UniValue range(UniValue::VARR);
    range.push_back(range_begin);
    range.push_back(range_end);

    // Use importdescriptors to process the descriptors:
    // TODO: extract reusable non-RPC code from importmulti
    UniValue importdata(UniValue::VARR);

    if (keypool_target_size == 0) throw JSONRPCError(RPC_WALLET_ERROR, "-keypool must be > 0");

    for (const UniValue& desc : receive_descriptor_vals.get_array().getValues()) {
        UniValue receive_key_data(UniValue::VOBJ);
        receive_key_data.pushKV("desc", desc);
        receive_key_data.pushKV("range", range);
        receive_key_data.pushKV("active", true);
        receive_key_data.pushKV("internal", false);
        receive_key_data.pushKV("watchonly", true);
        importdata.push_back(receive_key_data);
    }

    for (const UniValue& desc : change_descriptor_vals.get_array().getValues()) {
        UniValue change_key_data(UniValue::VOBJ);
        change_key_data.pushKV("desc", desc);
        change_key_data.pushKV("range", range);
        change_key_data.pushKV("active", true);
        change_key_data.pushKV("internal", true);
        change_key_data.pushKV("watchonly", true);
        importdata.push_back(change_key_data);
    }

    UniValue result(UniValue::VARR);
    {
        auto locked_chain = pwallet->chain().lock();
        const Optional<int> tip_height = locked_chain->getHeight();
        int64_t now = tip_height ? locked_chain->getBlockMedianTimePast(*tip_height) : 0;
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(pwallet);
        for (const UniValue& data : importdata.getValues()) {
            result.push_back(ProcessDescriptorImport(pwallet, data, now));
        }
    }

    // TODO: after the import, fetch a random key from the wallet (part of the import)
    // and ask the signer to sign a message (may require user approval on device).
    // Check the returned signature.
    // This ensures that the device can actually sign with this key and no data
    // corruption occured en route.
    // Note that this doesn't guarantee the device can sign for any script involving this key.

    return result;
}

UniValue signerprocesspsbt(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            RPCHelpMan{"signerprocesspsbt",
                "\nSign PSBT inputs using external signer\n"
                "that we can sign for." +
                    HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, /* default_val */ "", "The transaction base64 string"},
                    {"fingerprint", RPCArg::Type::STR, /* default_val */ "", "master key fingerprint of signer"},
                },
                RPCResult{
                    "{\n"
                    "  \"hex\" : \"value\",           (string) The hex-encoded network transaction, if complete\n"
                    "  \"psbt\" : \"value\",          (string) The base64-encoded partially signed transaction\n"
                    "  \"complete\" : true|false,     (boolean) If the transaction has a complete set of signatures\n"
                    "  ]\n"
                    "}\n"
                },
                RPCExamples{
                    HelpExampleCli("signerprocesspsbt", "\"psbt\"")
                }
            }.ToString()
        );

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR});

    ExternalSigner *signer = GetSignerForJSONRPCRequest(request, 1, pwallet);

    // Unserialize the transaction
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("PSBT decode failed %s", error));
    }

    if( !signer->signTransaction(psbtx, error)) throw JSONRPCError(RPC_WALLET_ERROR, error);

    CMutableTransaction mtx;
    bool complete = FinalizeAndExtractPSBT(psbtx, mtx);
    CDataStream ssPsbtx(SER_NETWORK, PROTOCOL_VERSION);
    ssPsbtx << psbtx;

    UniValue result(UniValue::VOBJ);
    if (complete) {
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        std::string tx_hex;
        ssTx << mtx;
        tx_hex = HexStr(ssTx.str());
        result.pushKV("hex", tx_hex);
    }
    result.pushKV("psbt", EncodeBase64(ssPsbtx.str()));
    result.pushKV("complete", complete);
    return result;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                                actor (function)                argNames
    //  --------------------- ------------------------          -----------------------         ----------
    { "signer",             "enumeratesigners",                 &enumeratesigners,              {} },
    { "signer",             "signerdissociate",                 &signerdissociate,              {"fingerprint"} },
    { "signer",             "signerdisplayaddress",             &signerdisplayaddress,          {"address", "fingerprint"} },
    { "signer",             "signerfetchkeys",                  &signerfetchkeys,               {"account", "fingerprint"} },
    { "signer",             "signerprocesspsbt",                &signerprocesspsbt,             {"psbt", "fingerprint"} },
};
// clang-format on

void RegisterSignerRPCCommands(interfaces::Chain& chain, std::vector<std::unique_ptr<interfaces::Handler>>& handlers)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        handlers.emplace_back(chain.handleRpc(commands[vcidx]));
}
#endif // HAVE_BOOST_PROCESS
