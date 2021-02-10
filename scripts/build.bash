#!/bin/bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

NCPU="${NCPU:-1}"
PREFIX="${PREFIX:-/usr/local}"

# Pharos
cd $DIR

sudo ldconfig

test -d build && rm -rf build
mkdir build
cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=$PREFIX -DROSE_ROOT=$PREFIX \
      -DBOOST_ROOT=$PREFIX -DZ3_ROOT=$PREFIX -DSWIPL_ROOT=$PREFIX \
      -DYamlCpp_ROOT=/usr ../..

ninja -k $NCPU -j $NCPU || true
ninja -j 1
sudo ninja install

if [ "$1" = "-reclaim" ]
then
    # If we're reclaiming space, run tests now since we won't be able to
    # later
    ctest -j $NCPU

    # Reclaim space
    rm -rf $DIR/build
fi

exit 0
