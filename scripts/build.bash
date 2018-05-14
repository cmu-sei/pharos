#!/bin/bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# sudo apt-get -y update
# sudo apt-get -y install build-essential wget flex ghostscript bzip2 git subversion automake libtool bison python libncurses5-dev vim-common libsqlite3-0 libsqlite3-dev zlib1g-dev

# CMake
cd $DIR

wget https://cmake.org/files/v3.8/cmake-3.8.2.tar.gz
test -d cmake-3.8.2 && rm -rf cmake-3.8.2
tar -xvzf cmake-3.8.2.tar.gz
cd cmake-3.8.2
./bootstrap
make -j 4
sudo make install

# BOOST
cd $DIR

test -d boost && sudo rm -rf boost
mkdir boost
cd boost
wget https://dl.bintray.com/boostorg/release/1.64.0/source/boost_1_64_0.tar.bz2
tar -xvjf boost_1_64_0.tar.bz2
cd boost_1_64_0
./bootstrap.sh --prefix=/usr/local --with-libraries=system,chrono,timer,iostreams
./b2 clean
sudo ./b2 -j4 --without-python toolset=gcc cxxflags="-std=c++11" install

# YAML-CPP
cd $DIR

test -d yaml && rm -rf yaml
git clone https://github.com/jbeder/yaml-cpp.git yaml
mkdir yaml/build
cd yaml/build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=true ..
make -j4
sudo make -j4 install

# Z3
cd $DIR
test -d z3 && rm -rf z3
git clone https://github.com/Z3Prover/z3.git z3
cd z3
git checkout b81165167304c20e28bc42549c94399d70c8ae65
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib ..
make -j4
sudo make -j4 install

# ROSE
cd $DIR

sudo ldconfig

test -d rose && rm -rf rose
git clone https://github.com/rose-compiler/rose-develop rose
cd rose
git checkout d3eaef2ad21687c294827d4471f2b0163af86978

./build
mkdir release
cd release
../configure --prefix=/usr/local --with-java=no --without-doxygen \
  --enable-languages=binaries --enable-projects-directory \
  --disable-tutorial-directory --disable-boost-version-check \
  --with-boost=/usr/local CXXFLAGS=-std=c++11 --with-yaml=/usr/local \
  --with-z3=/usr/local
make -j4
sudo make -j4 install

# SQLLite

# Installed via packages

# Pharos
cd $DIR

sudo ldconfig

# Work around make install bug
cp ../README.md ../README.txt
cp ../LICENSE.md ../LICENSE.txt
cp ../COPYRIGHT.md ../COPYRIGHT.txt
touch ../tools/apianalyzer/sig.json

test -d build && rm -rf build
mkdir build
cd build
cmake ../..
make -j4
sudo make install

# Reclaim space if argument specified.  Probably a good idea for
# Docker images, not such a good idea otherwise.
test "$1" = "-reclaim" && rm -rf $(cd $DIR/.. && pwd)

exit 0
