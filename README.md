Drivechain 1 GB sidechain branch
=====================================

[![Build Status](https://travis-ci.org/sjors/bitcoin.svg?branch=sidechain-1gb)](https://travis-ci.org/sjors/bitcoin)

Based on the Drivechain Project's [example sidechain](https://github.com/drivechain-project/bitcoin/tree/sidechainBMM), which is in turn based on [Bitcoin Core v0.14](https://github.com/bitcoin/bitcoin/tree/v0.14.2).

Learn more about Drivechain at http://drivechain.info. In particular, you'll need [their mainchainBMM branch](https://github.com/drivechain-project/bitcoin/tree/mainchainBMM) to run the mainchain side.

This project is not affiliated with the "official" Drivechain project. More importantly, _do not use this code with real bitcoin_. Then again, you only live once.

License
-------

Same as Bitcoin Core, namely the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The best place to see work in progress is this [pull request](https://github.com/Sjors/bitcoin/pull/1).

Pull requests should be made against the `sidechain-1gb` branch. This branch will be rebased as the upstream `sidechainBMM` branch is updated, which in turn is hopefully updated whenever Bitcoin Core releases a new version.

The `sidechain-1gb-experimental` branch will be used to try out various combinations of pull requests. It may be forced pushed over at any time.
