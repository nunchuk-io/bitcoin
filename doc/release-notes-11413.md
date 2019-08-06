Low-level RPC changes
----------------------

The `sendtoaddress` and `sendmany` RPC commands have been updated to include a
new "BTC/KB" and "SAT/B" fee estimation method. The target is the fee expressed as BTC per kB or Satoshi per byte.
