# Building and Installing

This file describes how to build and install the Pharos static
analysis framework tools.

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

We have tested several configurations, but have not extensively tested
different build configurations.  We typically build with GCC 4.8.5 abd
boost 1.60 on a RedHat Enterprise Linux 7 system.  We have also
successfully built on Ubuntu 17.04 system with Boost 1.64 and GCC 6.3.
Building Pharos requires a C++11 compliant compiler.  If you attempt
to build Pharos (successfully or not) we'd like to hear about you
experiences, and may be able to help with various build issues.

# Dependencies

First several important dependencies must be built or installed,
including:

  * ROSE
  * XSB
  * Boost
  * yaml-cpp
  * SQLLite
  * YICES

## Boost

We build with Boost version 1.60 currently, but we do not belive that
either ROSE or Pharos is particularly senstive which version of Boost
is used.  It does need to be compiled with a consistent ABI however,
and it is important to ensure that this Boost distribution is the same
Boost distribution used to build ROSE.

We typically build with the folllowing Boost components: system,
thread, program_options, iostreams, filesystem, regex, wave, chrono,
date_time, atomic, and serialization.  It may be easier to just build
and install all components.

You can build Boost using these commands:

```
$ mkdir boost
$ cd boost
$ wget https://dl.bintray.com/boostorg/release/1.64.0/source/boost_1_64_0.tar.bz2
$ tar -xzvf boost_1_64_0.tar.bz2
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

You may be able to muddle through with the standard operating system
packages under certain (unknown) circumstances.

```
$ sudo yum install boost boost-devel
$ sudo apt install libboost-dev libboost-all-dev
```

## yaml-cpp

YAML-cpp is also a C++ library, and has the same C++11 ABI compability
concerns.  We're usually building off a fairly current git checkout of
the yaml-cpp repository.  We build yaml-cpp using commands like these:

```
$ git clone https://github.com/jbeder/yaml-cpp.git yaml
$ mkdir yaml/build
$ cd yaml/build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
$ make -j4
$ make -j4 install
```

Or you can try installing the standard opeating system distribution:

```
$ sudo yum install yaml-cpp yaml-cpp-devel
$ sudo apt install libyaml-cpp0.5v5 libyaml-cpp-dev
```

## YICES

The YICES package is an SMT solver that can be optionally compiled
into ROSE.  YICES is used primarily in the binary analysis component
to answer questions about symbolic expression equivalence.  We
generally build with YICES, but it's not required to pass tests, and
it's probably easier to build without it.

After going to the Yices website (https://yices.csl.rsi.com/) and
obtaining version ONE of the Linux 64-bit executable dsitribution, you
can install YICES using the following commands:

```
$ cd /usr/local
$ sudo tar -xzvf yices-1.0.40-x86_64-unknown-linux-gnu-static-gmp.tar.gz
```

Recent GCC versions enable -fPIE by default but the Yices 1.0.40
static library was compiled long ago without -fPIE, which makes the
library incompatible with the default compilation options of recent
GCC versions.  If you build with YICES on newer compilers, you may
need to disbale -fPIE.

There are no standard YICES operating system packages, so if they are
desired, they must be built.

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
repository, you can checkout this commit:

```
$ git checkout 8c8aebc30e9295f89ad4dfee8fe741c26e7e3353
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
$ ./build
$ mkdir release
$ cd release
$ ../configure --prefix=/usr/local --with-java=no --without-doxygen \
  --enable-languages=binaries --enable-projects-directory \
  --disable-tutorial-directory --disable-boost-version-check \
  --with-boost=/usr/local CXXFLAGS=-std=c++11 --with-yaml=/usr/local
```

You will want to add --enable-static if you want to build Pharos tools
statically later.  Boost and YAML are not optional.  If you've chosen
to build with YICES, add "--with-yices=/usr/local/yices-1.0.40".
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

XSB must be built from source code on most platforms.  It is written
in C, and not C++, so the the ABI concerns do not apply to this
package.  As with ROSE, we're working with the XSB developers to keep
our XSB distribution in sync with theirs, and while they've accepted a
number of our contributions, they're currently only on the development
branch.


Additionally, there are some minor patches that are still outstanding
with the XSB develoeprs that need to be applied to the XSB
distribution to function properly with the Pharos tools.  Apply those
patches with the following command:

```
$ svn checkout https://sourceforge.net/p/xsb/src/HEAD/tree/ XSB
$ svn checkout -r 9046
$ patch -p1 /path/to/pharos/xsb.patch
```

The build procedure for XSB is documented in their distribution, but
the produce is roughly:

```
$ cd XSB/build
$ ./configure --prefix=/usr/local
$ ./makexsb
$ sudo ./makexsb install
```

There's an unexplained installation error in XSB that we've had to
hack around with the following command:

```
$ sudo touch /usr/local/xsb-3.7.0/syslib/sysinitrc
```

## SQLLite

We recommend fulfilling the SQLLite requirement by installing your
standard operating system distribution of SQLLite.  Because the
SQLLite interface is not C++11 depdendent the ABI concerns do not
apply to this package.

```
$ sudo yum install sqlite sqlite-devel
$ sudo apt-get install libsqlite3-0 libsqlite3-dev 
```
# Building Pharos

If all of the dependencies have been built and properly installed,
building Pharos should be pretty easy.  We use the standard CMake
approach which boils down to:

```
$ mkdir build
$ cd build
$ cmake ..
$ make -j4
```

We've shipped a site.cmake file to assist in documenting a number of
options and veraibles that need to be set, but you should also be able
to just move the file aside, and let CMake decide what to do.

If you want to run tests to ensure that your configuration has been
properly and is producing results identical to ours, you can run
tests with the following command:

```
$ ctest -j4
```

# Installing Pharos

Installing should also be easy.  Simply type:

```
$ make intall
```

The software installs into /usr/local by default, but can be
configured with CMake in the usual way 
