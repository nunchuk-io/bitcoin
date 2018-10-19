Miscellaneous RPC changes
------------

- `getaddressinfo` now reports `solvable`, a boolean indicating whether all information necessary for signing is present in the wallet (ignoring private keys).
- `getaddressinfo` and `listunspent` now report `descriptor`, a script descriptor that encapsulates all signing information and key paths for the address (only available when `solvable` is true).
