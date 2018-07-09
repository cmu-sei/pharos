# Building and Installing

This file describes how to build and install the Pharos static
binary analysis framework tools.

The primary difficulty involved in building the Pharos framework is an
unfortunate C++11 application binary interface (ABI) compatibility
issue where all C++ components linked into the final executable need
to use the same ABI in order to link correctly.  Since the C++ ABI has
been undergoing changes from GCC 4.8 through GCC 6.3, it's important
to know which compiler was used to build all of your library
dependencies.  Additionaly, there are build constraints on various
packages for some of the very latest compilers.  Our solution has been
to build all of our dependencies using GCC 4.8 in C++11 mode since the
Pharos code uses C++11 features.  These instructions are therefore
part instruction, part advice, and part a report of how we build
Pharos.

If your linux system/distribution was built using GCC 6 or later, the
ABI should match, and you should be able to use your system's
libraries without recompiling them.

We have tested several configurations, but have not extensively tested
different build configurations.

  * RedHat Enterprise Linux 7, GCC 6.3.1, Boost 1.61
  * RedHat Enterprise Linux 7, GCC 4.8.5, Boost 1.61
  * Ubuntu 17.04, GCC 6.3, Boost 1.64
  * Ubuntu 17.10, GCC 7.2, Boost 1.62

Building Pharos requires a C++11 compliant compiler.  If you attempt
to build Pharos (successfully or not) we'd like to hear about you
experiences, and may be able to help with various build issues.

# Build Script and Docker Container

A script that will attempt to download, build, and install the Pharos
dependencies is located in scripts/build.bash.  There is also a
Dockerfile in the root directory that can be used to build a Docker
image with:
```
$ docker build -t pharos .
```

# Dependencies

First several important dependencies must be built or installed,
including:

  * ROSE
  * Boost
  * yaml-cpp
  * SQLLite
  * Z3

## Boost

We build with Boost version 1.61 currently, but we do not belive that
either ROSE or Pharos is particularly senstive which version of Boost
is used.  It does need to be compiled with a consistent ABI however,
and it is important to ensure that this Boost distribution is the same
Boost distribution used to build ROSE.

We typically build with the folllowing Boost components: system,
thread, program_options, iostreams, filesystem, regex, wave, chrono,
date_time, atomic, and serialization.  It may be easier to just build
and install all components.

It is also important for Boost to be built with zlib support for
boost::iostreams to function propertly, so ensure that zlib is
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
$ ./b2 -j4 --without-python toolset=gcc cxxflags="-std=c++11" install
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

You may be able to muddle through with the standard operating system
packages under certain (unknown) circumstances.

```
$ sudo yum install boost boost-devel
-- or --
$ sudo apt install libboost-dev libboost-all-dev
-- or --
$ sudo zypper install boost-devel
```

## yaml-cpp

YAML-cpp is also a C++ library, and has the same C++11 ABI compability
concerns.  You can try installing the standard operating system
distribution:

```
$ sudo yum install yaml-cpp yaml-cpp-devel
--or--
$ sudo apt install libyaml-cpp0.5v5 libyaml-cpp-dev
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


## Z3

The Z3 package is an SMT solver that can be optionally compiled into
ROSE.  Z3 is used primarily in the binary analysis component to answer
questions about symbolic expression equivalence.  Some of the pharos
tools require Z3 to work.  A fairly recent version of Z3 is necessary,
but an even more recent commit broke the Z3 ABI with respect to ROSE.
Therefore, we currently use a very specific revision of Z3.
Specifically, revision b81165167304c20e28bc42549c94399d70c8ae65.

We build Z3 using commands like these:
```
$ git clone https://github.com/Z3Prover/z3.git
$ cd z3
$ git reset --hard b81165167304c20e28bc42549c94399d70c8ae65
$ mkdir build
$ cd build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib ..
$ make -j4
$ make -j4 install
```

## ROSE

ROSE is probably the most difficult package to build.  We track the
current commit on the development version of ROSE on GitHub more or
less daily, but our own updates to GitHub are less frequent.  At the
time of this release, ROSE master is a couple of months behind
rose-develop, so be sure to fetch the "development" version of ROSE.

You can obtain the latest version of ROSE from:

```
$ git clone https://github.com/rose-compiler/rose-develop rose
```

Which has a reasonable chance of working or only having minor issues.
If you want to be conservative, and use the version of ROSE that was
known to compile with the latest major commit to the Pharos
repository, you can checkout this commit (ROSE version 0.9.10.9):

```
$ git reset --hard d3eaef2ad21687c294827d4471f2b0163af86978
```

You may also be able to distribution packages from the ROSE website,
although our code was updated to include a major renaming of the ROSE
namespace shortly before our latest commit.

ROSE can be configured in a multitude of ways, and some attention to
the configuration parameters in your environment is recommended.  The
flags option to specify C++11 is required for ABI compatibility with
Pharos and other libraries.  We use a configure command very similar
to this one:

```
$ cd rose
$ ./build
$ mkdir release
$ cd release
$ ../configure --prefix=/usr/local --with-java=no \
  --with-z3=/usr/local --enable-languages=binaries \
  --without-doxygen --enable-projects-directory \
  --disable-tutorial-directory --disable-boost-version-check \
  --with-boost=/usr/local CXXFLAGS=-std=c++11 --with-yaml=/usr/local
```

Disabling Java, doxygen, and the tutorials, but enabling binaries and
projects is related to generating a minimal and therefore faster
build, so those confuration options should be optional.  To build use:

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

## XSB

XSB is downloaded during the pharos cmake invocation, and is built as
part of building pharos.  If you do not have network access or
subversion, the configure process will fail.

## SQLLite

We recommend fulfilling the SQLLite requirement by installing your
standard operating system distribution of SQLLite.  Because the
SQLLite interface is not C++11 depdendent the ABI concerns do not
apply to this package.

```
$ sudo yum install sqlite sqlite-devel
-- or --
$ sudo apt-get install libsqlite3-0 libsqlite3-dev 
-- or --
$ sudo zypper install sqlite3-devel
```
# Building Pharos

If all of the dependencies have been built and properly installed,
building Pharos should be pretty easy.  We use the standard CMake
approach which boils down to:

```
$ cd pharos
$ mkdir build
$ cd build
$ cmake ..
$ make -j4
```

If you want to run tests to ensure that your configuration has been
properly and is producing results identical to ours, you can run
tests with the following command from the build directory:

```
$ ctest -j4
```

# Installing Pharos

Installing should also be easy.  Simply type:

```
$ make install
```

The software installs into /usr/local by default, but can be
configured with CMake in the usual way 
