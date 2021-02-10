#!/bin/bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

NCPU="${NCPU:-1}"
PREFIX="${PREFIX:-/usr/local}"

# BOOST
if [ "$COMPILE_BOOST" != "" ]
then
   test -d boost && sudo rm -rf boost
   mkdir boost
   cd boost
   wget https://dl.bintray.com/boostorg/release/1.64.0/source/boost_1_64_0.tar.bz2
   tar -xjf boost_1_64_0.tar.bz2
   cd boost_1_64_0
   ./bootstrap.sh --prefix=$PREFIX --with-libraries=system,serialization,chrono,timer,iostreams,thread,date_time,random,regex,program_options,filesystem,wave
   sudo ./b2 cxxflags="$CXXFLAGS" -j $NCPU toolset=gcc install
   test "$1" = "-reclaim" && sudo rm -rf $DIR/boost
fi

# SWI
cd $DIR
test -d swipl-devel && rm -rf swipl-devel
git clone --recursive -b V8.3.19 --depth 1 https://github.com/swi-prolog/swipl-devel
cd swipl-devel
mkdir build
cd build
cmake -G Ninja -DCMAKE_INSTALL_PREFIX=$PREFIX -DINSTALL_DOCUMENTATION=off ..
ninja -j $NCPU
sudo ninja -j $NCPU install
test "$1" = "-reclaim" && rm -rf $DIR/swipl-devel

# Z3
cd $DIR
test -d z3 && rm -rf z3

git clone --depth 1 -b z3-4.8.7 https://github.com/Z3Prover/z3.git z3
cd z3
mkdir build
cd build
cmake -G Ninja -DCMAKE_INSTALL_PREFIX=$PREFIX -DCMAKE_RULE_MESSAGES=off ..
ninja -j $NCPU
sudo ninja -j $NCPU install
test "$1" = "-reclaim" && rm -rf $DIR/z3

# ROSE
cd $DIR
test -d rose && rm -rf rose

git clone --depth 1 -b v0.11.11.2 https://github.com/rose-compiler/rose rose
cd rose

# See rose issue #52
mkdir ../rose-build
cd ../rose-build

sudo ldconfig
cmake -GNinja -DCMAKE_INSTALL_PREFIX=$PREFIX -DBOOST_ROOT=$PREFIX -DZ3_ROOT=$PREFIX \
        -Denable-binary-analysis=yes -Denable-c=no -Denable-opencl=no -Denable-java=no -Denable-php=no \
        -Denable-fortran=no -Ddisable-tutorial-directory=yes -Denable-projects-directory=no \
        -Ddisable-tests-directory=yes ../rose

# Try once in parallel and then if things fail due to memory
# shortages, try again one thread at a time.  This is a reasonable
# compromise between waiting for a single threaded build, and the
# reliability problems introduced by parallel builds.
ninja -k $NCPU -j $NCPU || true
ninja -j1
sudo ninja -j $NCPU install
test "$1" = "-reclaim" && rm -rf $DIR/rose $DIR/rose-build

exit 0
