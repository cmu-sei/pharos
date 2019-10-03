#!/bin/bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

NCPU="${NCPU:-1}"

# Pharos
cd $DIR

sudo ldconfig

test -d build && rm -rf build
mkdir build
cd build
CXXFLAGS='-O3 -flto -march=haswell' \
LDFLAGS='-O3 -flto -march=haswell' \
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DROSE_ROOT=/usr/local \
      -DXSB_ROOT=/usr/local/xsb-3.8.0 -DBOOST_ROOT=/usr \
      -DZ3_ROOT=/usr/local -DYAML_CPP_ROOT=/usr ../..

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
