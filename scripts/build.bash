#!/bin/bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

NCPU="${NCPU:-1}"

# sudo apt-get -y update
# sudo apt-get -y install build-essential wget flex ghostscript bzip2 git subversion automake libtool bison python libncurses5-dev vim-common libsqlite3-0 libsqlite3-dev zlib1g-dev

# CMake
cd $DIR

if [ "$DONT_COMPILE_CMAKE" = "" ]
then
    wget https://cmake.org/files/v3.8/cmake-3.8.2.tar.gz
    test -d cmake-3.8.2 && rm -rf cmake-3.8.2
    tar -xzf cmake-3.8.2.tar.gz
    cd cmake-3.8.2
    ./bootstrap
    make -j $NCPU
    sudo make install
    test "$1" = "-reclaim" && rm -rf $DIR/cmake-3.8.2
fi

# BOOST
cd $DIR

if [ "$DONT_COMPILE_BOOST" = "" ]
then
   test -d boost && sudo rm -rf boost
   mkdir boost
   cd boost
   wget https://dl.bintray.com/boostorg/release/1.64.0/source/boost_1_64_0.tar.bz2
   tar -xjf boost_1_64_0.tar.bz2
   cd boost_1_64_0
   ./bootstrap.sh --prefix=/usr/local --with-libraries=system,serialization,chrono,timer,iostreams,thread,date_time,random,regex,program_options,filesystem,wave
   sudo ./b2 -j $NCPU toolset=gcc cxxflags="-std=c++11" install
   test "$1" = "-reclaim" && sudo rm -rf $DIR/boost
fi

# YAML-CPP
cd $DIR

test -d yaml && rm -rf yaml
git clone https://github.com/jbeder/yaml-cpp.git yaml
mkdir yaml/build
cd yaml/build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=true -DCMAKE_RULE_MESSAGES=OFF ..
make -j $NCPU
sudo make -j $NCPU install
test "$1" = "-reclaim" && rm -rf $DIR/yaml


# Z3
cd $DIR
test -d z3 && rm -rf z3
git clone https://github.com/Z3Prover/z3.git z3
cd z3
git checkout b81165167304c20e28bc42549c94399d70c8ae65
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_RULE_MESSAGES=off ..
make -j $NCPU
sudo make -j $NCPU install
test "$1" = "-reclaim" && rm -rf $DIR/z3

# ROSE
cd $DIR

sudo ldconfig

test -d rose && rm -rf rose
git clone https://github.com/rose-compiler/rose-develop rose
cd rose
git checkout d3eaef2ad21687c294827d4471f2b0163af86978

#  CXXFLAGS='-std=c++11 --param ggc-min-expand=1 --param ggc-min-heapsize=32768' \
./build
mkdir release
cd release
../configure --prefix=/usr/local --with-java=no --without-doxygen \
  --enable-languages=binaries --enable-projects-directory \
  --disable-tutorial-directory --disable-boost-version-check \
  --with-boost=/usr/local \
  CXXFLAGS='-std=c++11 --param ggc-min-expand=5 --param ggc-min-heapsize=32768' \
  --with-yaml=/usr/local \
  --with-z3=/usr/local
make -k -j $NCPU
make
sudo make -j $NCPU install
test "$1" = "-reclaim" && rm -rf $DIR/rose

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
make -j $NCPU
sudo make install

# If we're reclaiming space, run tests now since we won't be able to
# later
test "$1" = "-reclaim" && (ctest3 || ctest)

# Reclaim space if argument specified.  Probably a good idea for
# Docker images, not such a good idea otherwise.
test "$1" = "-reclaim" && rm -rf $(cd $DIR/.. && pwd)

exit 0
