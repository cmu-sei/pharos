This file describes several ways to install (and optionally build) the
Pharos static binary analysis framework tools.

# Pre-built Docker Images (Easiest)

The easiest way to get started with Pharos is to use our pre-built
Docker images.

The first step is to download the image:
```
$ docker pull seipharos/pharos
```

To start an interactive session in which the host directory `/dir` is
mapped to `/dir` inside your container, run the following
command:
```
$ docker run --rm -it -v /dir:/dir seipharos/pharos
```

The pharos tools will be installed in `/usr/local/bin`.

# Building the Docker Image (Easy)

You can also build your own Docker image with:
```
$ docker build --build-arg NCPU=4 -t seipharos/pharos .
```

where 4 is the number of cores you wish to use for building.  Using
more than one processor consumes more RAM.  For small numbers of CPUs
(1-4) you should probably have 4GiB of RAM per CPU.  For larger
numbers of CPUs (>16) about 1Gib of RAM per CPU should be sufficient.

You can then run the container using the same `docker run` command as above.

# Build Script (Medium)

You can also use our Docker build script to build Pharos outside of
Docker.  This is only supported on the latest version of Ubuntu.

First, install prerequisite packages:
```
$ sudo apt update
$ sudo apt install build-essential wget flex ghostscript bzip2 \
  git subversion automake libtool bison python libncurses-dev \
  vim-common sqlite3 libsqlite3-0 libsqlite3-dev zlib1g-dev cmake \
  libyaml-cpp-dev libboost-all-dev libboost-dev libxml2-dev
```

Then install all dependencies by running:
```
./scripts/build_prereqs.bash
```

And finally run the script:
```
NCPU=4 ./scripts/build.bash
```

Set `NCPU` to the number of cores you wish to use for building.  You
should probably use 1 unless you have a lot of RAM.

Note that the build script must be able to run `sudo` without being
prompted for a password.

# Manually Building from Source (Hard)

We have tested several configurations, but have not extensively tested
different build configurations.

  * RedHat Enterprise Linux 7, GCC 8.3.1, Boost 1.61
  * RedHat Enterprise Linux 7, GCC 6.3.1, Boost 1.61
  * Ubuntu 19.04, GCC 8.3.0, Boost 1.67
  * Ubuntu 19.04, GCC 9.1.0, Boost 1.67
  * OpenSUSE Leap 15.1/Tumbleweed, GCC 8.3.1, Boost 1.69

Pharos requires C++14 support, so you'll need a compiler that's new
enough.  If you have an older compiler that doesn't support C++14 by
default, you may be able to add "--std=c++14" options in some places.

If you attempt to build Pharos (successfully or not) we'd like to hear
about your experiences, and may be able to help with various build
issues.

## Dependencies

In addition to the general build dependencies listed earlier, several
other important dependencies must be built or installed, including:

  * Boost
  * yaml-cpp
  * SQLite
  * Z3
  * ROSE
  * SWI Prolog

### Boost

We build with Boost version 1.61 currently, but we do not believe that
either ROSE or Pharos is particularly sensitive which version of Boost
is used.  It is important to ensure that this Boost distribution is
the same Boost distribution used to build ROSE.

You should be able to use the standard operating system packages under
most circumstances.

```
$ sudo yum install boost boost-devel
-- or --
$ sudo apt install libboost-dev libboost-all-dev
-- or --
$ sudo zypper install boost-devel
```

We typically build with the following Boost components: system,
thread, program_options, iostreams, filesystem, regex, wave, chrono,
date_time, atomic, and serialization.  It may be easier to just build
and install all components.

It is also important for Boost to be built with zlib support for
boost::iostreams to function properly, so ensure that zlib is
installed properly, including development headers.

You can build Boost using these commands:

```
$ mkdir boost
$ cd boost
$ wget https://dl.bintray.com/boostorg/release/1.64.0/source/boost_1_64_0.tar.bz2
$ tar -xjvf boost_1_64_0.tar.bz2
$ cd boost_1_64_0
$ ./bootstrap.sh --prefix=/usr/local
$ ./b2 clean
$ ./b2 -j4 toolset=gcc install
```

The latest versions of Boost can interact poorly the FindBoost.cmake
module because the cmake module has specific versions hard-coded into
it, but this is not a difficult fix (remove the upper version bound).
We require CMake version 3.5, so if your distribution is really old
you might update CMake first.  CMake version 3.5 supports Boost
version 1.61, and if your Boost version is newer, you'll need to
update CMake or patch patch it by hand.

An alternative is to use an older distribution of boost.  Much of our
testing has been done using version 1.61.

### yaml-cpp

You can try installing the standard operating system distribution:

```
$ sudo yum install yaml-cpp yaml-cpp-devel
--or--
$ sudo apt install libyaml-cpp0.6 libyaml-cpp-dev
--or--
$ sudo zypper install yaml-cpp-devel
```

We're usually building off a fairly current git checkout of the
yaml-cpp repository.  We build yaml-cpp using commands like these:

```
$ git clone https://github.com/jbeder/yaml-cpp.git yaml
$ mkdir yaml/build
$ cd yaml/build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=true ..
$ make -j4
$ make -j4 install
```

### SQLite

We recommend fulfilling the SQLite requirement by installing your
standard operating system distribution of SQLite. Note that on
most distributions, you must the executable is package separately
from the library; both must be installed, as the examples below.

```
$ sudo yum install sqlite sqlite-devel
-- or --
$ sudo apt install sqlite3 libsqlite3-dev
-- or --
$ sudo zypper install sqlite3 sqlite3-devel
```

### Z3

The Z3 package is an SMT solver that can be optionally compiled into
ROSE.  Z3 is used primarily in the binary analysis component to answer
questions about symbolic expression equivalence.  Some of the pharos
tools require Z3 to work.  Z3 is under active development, and some
commits have broken compatibility with our code from time to time.
The latest release version of Z3 (4.8.7) has passed our testing.

We build Z3 using commands like these:
```
$ git clone -b Z3-4.8.7 https://github.com/Z3Prover/z3.git
$ cd z3
$ mkdir build
$ cd build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
$ make -j4
$ sudo make -j4 install
```

### ROSE

ROSE is probably the most difficult package to build.  We track the
current commit on the development version of ROSE on GitHub more or
less daily, but our own updates to GitHub are less frequent.  At the
time of this release, ROSE master is a couple of months behind
rose-develop, so be sure to fetch the "development" version of ROSE.

You can obtain the latest version of ROSE from:

```
$ git clone -b develop https://github.com/rose-compiler/rose rose
$ cd rose
```

This version has a reasonable chance of working or only having minor
issues.  If you want to be conservative and use the version of ROSE
that was known to compile with the latest major commit to the Pharos
repository, you can checkout this commit (ROSE version v0.11.11.2):

```
$ git checkout v0.11.11.2
```

ROSE can be configured in a multitude of ways, and some attention to
the configuration parameters in your environment is recommended. We
build ROSE like this:

```
$ mkdir release
$ cd release
$ cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
  -Denable-binary-analysis=yes -Denable-c=no \
  -Denable-java=no -Denable-fortran=no \
  -Ddisable-tutorial-directory=yes -Ddisable-tests-directory=yes ..
```

Enabling binary analysis is very important.  Disabling C, Java and
Fortran eliminate a dependency on a binary EDG file that must be
downloaded from the Internet, but these options can be removed without
impacting the Pharos build.  Disabling the tutorials and tests are
optional, and suggested simply to reduce the build time.

To actually begin the build use:

```
$ make -j4
```

ROSE can consume a fair amount of RAM and CPU power during the build,
and we recommend that you NOT use a virtual machine with limited RAM
or old hardware.  Be patient and go have lunch. :-)

To install ROSE, run:

```
$ sudo make -j4 install
```

### SWI Prolog

SWI Prolog is the backbone of OOAnalyzer's reasoning system.  The Pharos
build system currently depends on version 8.2.0 or greater.

These commands will build and install this version to $SWIPL_LOCATION:

```
$ git clone --recursive -b V8.2.0 --depth 1 https://github.com/swi-prolog/swipl-devel
$ cd swipl-devel
$ mkdir build
$ cd build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DINSTALL_DOCUMENTATION=off ..
$ make
$ sudo make install
```

## Building Pharos

If all of the dependencies have been built and properly installed,
building Pharos should be pretty easy.  We use the standard CMake
build approach listed below.

Similar to NCPU above, change `make -j4` to `make -j1` unless you
have a lot of RAM.

```
$ cd pharos
$ mkdir build
$ cd build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
$ make -j4
```

If you want to run tests to ensure that your configuration has been
properly and is producing results identical to ours, you can run
tests with the following command from the build directory:

```
$ make tests
$ ctest -j4
```

## Installing Pharos

Installing should also be easy.  Simply type:

```
$ sudo make install
```

The software installs into /usr/local by default, but can be
configured with CMake in the usual way.
