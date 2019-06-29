// Copyright (c) 2010-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/error.h>

#include <util/system.h>

std::string TransactionErrorString(const TransactionError err)
{
    switch (err) {
        case TransactionError::OK:
            return "No error";
        case TransactionError::MISSING_INPUTS:
            return "Missing inputs";
        case TransactionError::ALREADY_IN_CHAIN:
            return "Transaction already in block chain";
        case TransactionError::P2P_DISABLED:
            return "Peer-to-peer functionality missing or disabled";
        case TransactionError::MEMPOOL_REJECTED:
            return "Transaction rejected by AcceptToMemoryPool";
        case TransactionError::MEMPOOL_ERROR:
            return "AcceptToMemoryPool failed";
        case TransactionError::INVALID_PSBT:
            return "PSBT is not sane";
        case TransactionError::PSBT_MISMATCH:
            return "PSBTs not compatible (different transactions)";
        case TransactionError::SIGHASH_MISMATCH:
            return "Specified sighash value does not match existing value";
        case TransactionError::MAX_FEE_EXCEEDED:
            return "Fee exceeds maximum configured by -maxtxfee";
        case TransactionError::NEGATIVE_AMOUNT:
            return "Transaction amounts must not be negative";
        case TransactionError::NO_OUTPUT:
            return "Transaction must have at least one recipient";
        case TransactionError::EMPTY_KEYPOOL:
            return "Keypool ran out, please call keypoolrefill first";
        case TransactionError::EMPTY_KEYPOOL_INTERNAL:
            return "Can't generate a change-address key. No keys in the internal keypool and can't generate any keys.";
        case TransactionError::AMOUNT_TOO_SMALL:
            return "Transaction amount too small";
        case TransactionError::AMOUNT_TOO_SMALL_FOR_FEE:
            return "The transaction amount is too small to pay the fee";
        case TransactionError::AMOUNT_TOO_SMALL_AFTER_FEE:
            return "The transaction amount is too small to send after the fee has been deducted";
        case TransactionError::INSUFFICIENT_FUNDS:
            return "Insufficient funds";
        case TransactionError::CHANGE_INDEX_OUT_OF_RANGE:
            return "Change index out of range";
        case TransactionError::SIGNING_FAILED:
            return "Signing transaction failed";
        case TransactionError::FEE_ESTIMATION_FAILED_NO_FALLBACK:
            return "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.";
        case TransactionError::FEE_TOO_LARGE_FOR_POLICY:
            return "Transaction too large for fee policy";
        case TransactionError::FEE_AND_CHANGE_CALCULATION_FAILED:
            return "Transaction fee and change calculation failed";
        case TransactionError::TOO_LARGE:
            return "Transaction too large";
        case TransactionError::TOO_LONG_MEMPOOL_CHAIN:
            return "Transaction has too long of a mempool chain";
        // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}

std::string AmountHighWarn(const std::string& optname)
{
    return strprintf(_("%s is set very high!"), optname);
}

std::string AmountErrMsg(const char* const optname, const std::string& strValue)
{
    return strprintf(_("Invalid amount for -%s=<amount>: '%s'"), optname, strValue);
}
