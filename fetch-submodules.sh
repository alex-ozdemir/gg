#!/bin/sh -ex

git submodule update --recursive --init test_vectors
git submodule update --init toolchain
git submodule update --init third_party/cpptoml
./contrib/build-openssl.sh
./contrib/build-cryptopp.sh
git submodule update --init third_party/hiredis
./contrib/patch-hiredis.sh
