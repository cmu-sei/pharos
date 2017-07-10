#!/bin/bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# sudo apt-get -y update
# sudo apt-get -y install build-essential wget flex ghostscript bzip2 git subversion automake libtool bison python libncurses5-dev vim-common libsqlite3-0 libsqlite3-dev 

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
./bootstrap.sh --prefix=/usr/local
./b2 clean
sudo ./b2 -j4 --without-python toolset=gcc cxxflags="-std=c++11" install

# YAML-CPP
cd $DIR

test -d yaml && rm -rf yaml
git clone https://github.com/jbeder/yaml-cpp.git yaml
mkdir yaml/build
cd yaml/build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j4
sudo make -j4 install

# ROSE
cd $DIR

sudo ldconfig

test -d rose && rm -rf rose
git clone https://github.com/rose-compiler/rose-develop rose
cd rose
git checkout 8c8aebc30e9295f89ad4dfee8fe741c26e7e3353

./build
mkdir release
cd release
../configure --prefix=/usr/local --with-java=no --without-doxygen \
  --enable-languages=binaries --enable-projects-directory \
  --disable-tutorial-directory --disable-boost-version-check \
  --with-boost=/usr/local CXXFLAGS=-std=c++11 --with-yaml=/usr/local
make -j4
sudo make -j4 install

# XSB
cd $DIR

test -d XSB && sudo rm -rf XSB
svn checkout -r 9046 https://svn.code.sf.net/p/xsb/src/trunk XSB
cd XSB
patch -p1 < $DIR/../xsb.patch

cd XSB/build
sudo ./configure --prefix=/usr/local
sudo ./makexsb
sudo ./makexsb install

sudo touch /usr/local/xsb-3.7.0/syslib/sysinitrc.P

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
