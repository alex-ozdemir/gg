git submodule update --init third_party/openssl
(cd third_party/openssl && ./Configure --prefix=$(pwd)/../install &&  make -j $(nproc) && make install -j $(nproc))
