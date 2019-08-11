#!/bin/bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

NCPU="${NCPU:-1}"

# XSB
cd $DIR
test -d XSB && sudo rm -rf XSB

# XSB frequently fails to clone, so try very hard to clone with reasonable timeouts in between
RETRY=100
while svn checkout https://svn.code.sf.net/p/xsb/src/trunk/XSB XSB; test $? -eq 1 -a $RETRY -gt 0
do
    RETRY=$(($RETRY-1))
    echo SVN checkout failed.  Sleeping and trying again.
    sleep 60
    rm -rf XSB
done

# Pre-create the XSB install target and give the user write access.
# Because the XSB build requires write access for configuration,
# compile and install, the alternatives are to install someplace else
# or to run each step with sudo.
sudo mkdir -p /usr/local/xsb-3.8.0 /usr/local/site
sudo chown $(whoami) /usr/local/xsb-3.8.0 /usr/local/site

cd XSB/build
./configure --prefix=/usr/local
# makexsb -j does not appear to be reliable
./makexsb
./makexsb install
test "$1" = "-reclaim" && rm -rf $DIR/XSB


# Z3
cd $DIR
test -d z3 && rm -rf z3

git clone -b Z3-4.8.5 https://github.com/Z3Prover/z3.git z3
cd z3
mkdir build
cd build
cmake -G Ninja -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_RULE_MESSAGES=off ..
ninja -j $NCPU
sudo ninja -j $NCPU install
test "$1" = "-reclaim" && rm -rf $DIR/z3

# ROSE
cd $DIR
test -d rose && rm -rf rose

git clone https://github.com/rose-compiler/rose rose
cd rose
git checkout fc6bb3504961cd8cbe7d758eaa4a86069ad81589

mkdir release
cd release

sudo ldconfig
# The CXXFLAGS are to reduce the memory requirements.
CXXFLAGS='--param ggc-min-expand=5 --param ggc-min-heapsize=32768' \
cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
        -Denable-binary-analysis=yes -Denable-c=no -Denable-opencl=no -Denable-java=no -Denable-php=no \
        -Denable-fortran=no -Ddisable-tutorial-directory=yes \
        -Ddisable-tests-directory=yes ..

# Try once in parallel and then if things fail due to memory
# shortages, try again one thread at a time.  This is a reasonable
# compromise between waiting for a single threaded build, and the
# reliability problems introduced by parallel builds.
make -k -j $NCPU || true
make
sudo make -j $NCPU install
test "$1" = "-reclaim" && rm -rf $DIR/rose

# Pharos
cd $DIR

sudo ldconfig

test -d build && rm -rf build
mkdir build
cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DROSE_ROOT=/usr/local \
      -DXSB_ROOT=/usr/local/xsb-3.8.0 \
      -DZ3_ROOT=/usr/local -DYAML_CPP_ROOT=/usr ../..
ninja -k $NCPU -j $NCPU || true
ninja -j1
sudo ninja install

if [ "$1" = "-reclaim" ]
then
    # If we're reclaiming space, run tests now since we won't be able to
    # later
    ctest3 -j $NCPU || ctest -j $NCPU

    # Reclaim space
    rm -rf $DIR/build
fi

exit 0
