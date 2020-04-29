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

# XSB
cd $DIR
test -d XSB && sudo rm -rf XSB

# XSB frequently fails to clone, so try very hard to clone with reasonable timeouts in between
svn checkout https://svn.code.sf.net/p/xsb/src/trunk/XSB XSB || true

RETRY=100
while (cd XSB && svn cleanup && svn update); status=$?; [ $status -ne 0 -a $RETRY -gt 0 ]
do
    RETRY=$(($RETRY-1))
    echo SVN update failed.
    sleep 5
done

# Pre-create the XSB install target and give the user write access.
# Because the XSB build requires write access for configuration,
# compile and install, the alternatives are to install someplace else
# or to run each step with sudo.
sudo mkdir -p $PREFIX/xsb-3.8.0 $PREFIX/site
sudo chown $(whoami) $PREFIX/xsb-3.8.0 $PREFIX/site

cd XSB/build
./configure --prefix=$PREFIX
# makexsb -j does not appear to be reliable
./makexsb
./makexsb install
test "$1" = "-reclaim" && rm -rf $DIR/XSB


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

git clone --depth 1 -b v0.10.0.27 https://github.com/rose-compiler/rose rose
cd rose

# See rose issue #52
mkdir ../rose-build
cd ../rose-build

sudo ldconfig
# The CXXFLAGS are to reduce the memory requirements.
CXXFLAGS="$CXXFLAGS --param ggc-min-expand=5 --param ggc-min-heapsize=32768" \
cmake -GNinja -DCMAKE_INSTALL_PREFIX=$PREFIX -DBOOST_ROOT=$PREFIX -DZ3_ROOT=$PREFIX \
        -Denable-binary-analysis=yes -Denable-c=no -Denable-opencl=no -Denable-java=no -Denable-php=no \
        -Denable-fortran=no -Ddisable-tutorial-directory=yes \
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
