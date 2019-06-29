// Copyright (c) 2010-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_ERROR_H
#define BITCOIN_UTIL_ERROR_H

/**
 * util/error.h is a common place for definitions of simple error types and
 * string functions. Types and functions defined here should not require any
 * outside dependencies.
 *
 * Error types defined here can be used in different parts of the bitcoin
 * codebase, to avoid the need to write boilerplate code catching and
 * translating errors passed across wallet/node/rpc/gui code boundaries.
 */

#include <string>

enum class TransactionError {
    OK, //!< No error
    MISSING_INPUTS,
    ALREADY_IN_CHAIN,
    P2P_DISABLED,
    MEMPOOL_REJECTED,
    MEMPOOL_ERROR,
    INVALID_PSBT,
    PSBT_MISMATCH,
    SIGHASH_MISMATCH,
    MAX_FEE_EXCEEDED,
    NEGATIVE_AMOUNT,
    NO_OUTPUT,
    EMPTY_KEYPOOL,
    EMPTY_KEYPOOL_INTERNAL,
    AMOUNT_TOO_SMALL,
    AMOUNT_TOO_SMALL_FOR_FEE,
    AMOUNT_TOO_SMALL_AFTER_FEE,
    INSUFFICIENT_FUNDS,
    CHANGE_INDEX_OUT_OF_RANGE,
    SIGNING_FAILED,
    FEE_ESTIMATION_FAILED_NO_FALLBACK,
    FEE_TOO_LARGE_FOR_POLICY,
    FEE_AND_CHANGE_CALCULATION_FAILED,
    TOO_LARGE,
    TOO_LONG_MEMPOOL_CHAIN,
};

std::string TransactionErrorString(const TransactionError error);

std::string AmountHighWarn(const std::string& optname);

std::string AmountErrMsg(const char* const optname, const std::string& strValue);

#endif // BITCOIN_UTIL_ERROR_H
