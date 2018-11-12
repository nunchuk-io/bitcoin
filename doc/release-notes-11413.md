Low-level RPC changes
----------------------

The `sendtoaddress` and `sendmany` RPC commands have been updated to include a
new "EXPLICIT" fee estimation method. The target is the fee expressed as BTC/kB.
