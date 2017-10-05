// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTPRPC_H
#define BITCOIN_HTTPRPC_H

#include <functional>
#include <string>
#include <map>

class HTTPRequest;
class JSONRPCRequest;

/** Start HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been started.
 */
bool StartHTTPRPC();
/** Interrupt HTTP RPC subsystem.
 */
void InterruptHTTPRPC();
/** Stop HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been stopped.
 */
void StopHTTPRPC();

/** Start HTTP REST subsystem.
 * Precondition; HTTP and RPC has been started.
 */
bool StartREST();
/** Interrupt RPC REST subsystem.
 */
void InterruptREST();
/** Stop HTTP REST subsystem.
 * Precondition; HTTP and RPC has been stopped.
 */
void StopREST();

/** Callback to prepare a JSONRPCRequest */
typedef void (*JSONRPCRequestPreparer)(JSONRPCRequest& req, const HTTPRequest&);
/** Register callback for preparing JSONRPCRequests.
 * If multiple handlers match a prefix, all of them will be invoked.
 */
void RegisterJSONRPCRequestPreparer(const JSONRPCRequestPreparer&);
/** Unregister callback */
void UnregisterJSONRPCRequestPreparer(const JSONRPCRequestPreparer&);

#endif
