git submodule update --init third_party/cryptopp
(cd third_party/cryptopp && make libcryptopp.a -j $(nproc) && make install -j $(nproc) PREFIX=../install)
