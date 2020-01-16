set -xe
cd third_party
wget https://github.com/protocolbuffers/protobuf/releases/download/v3.13.0/protobuf-cpp-3.13.0.tar.gz
tar xvf protobuf-cpp-3.13.0.tar.gz
cd protobuf-3.13.0
./autogen.sh
./configure --prefix=$(pwd)/../install
make
make install
