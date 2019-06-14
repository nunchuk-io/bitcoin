#!/usr/bin/env bash
#
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
  # update first to install required ruby dependency
  travis_retry brew update
  travis_retry brew install shellcheck
  travis_retry brew upgrade python
  export PATH="$(brew --prefix python)/bin:$PATH"
else
  SHELLCHECK_VERSION=v0.6.0
  curl -s "https://storage.googleapis.com/shellcheck/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" | tar --xz -xf - --directory /tmp/
  export PATH="/tmp/shellcheck-${SHELLCHECK_VERSION}:${PATH}"
fi

travis_retry pip install codespell==1.15.0
travis_retry pip install flake8==3.5.0
travis_retry pip install vulture==0.29
