Low-level RPC changes
----------------------

The `bumpfee`, `fundrawtransaction`, `sendmany`, `sendtoaddress`, and `walletcreatefundedpsbt`
RPC commands have been updated to include two new fee estimation methods "BTC/KB" and "SAT/B".
The target is the fee expressed explicitly in the given form.

In addition, the estimate_mode parameter is now case insensitive for all of the above RPC commands.
