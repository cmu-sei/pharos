#
# spec file for package pharos
#
# Copyright (c) 2019 Carnegie Mellon University.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# this spec was developed for OpenSUSE however may be useful
# for other rpm-based distributions.


Name:           pharos
Version:        20190807
Release:        0
Summary:        Static binary analysis framework from CMU SEI
License:        BSD-3-Clause
Group:          "Development/Libraries/C and C++"
URL:            https://github.com/cmu-sei/pharos
Source0:        %{name}-%{version}.tar.gz
Patch0:         001-use-lib64-paths-and-share-path.diff
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  cmake
BuildRequires:  gcc8-c++
BuildRequires:  git
BuildRequires:  wget
BuildRequires:  boost-devel >= 1.68.0
BuildRequires:  libboost_headers-devel >= 1.68.0
BuildRequires:  libboost_atomic-devel >= 1.68.0
BuildRequires:  libboost_chrono-devel >= 1.68.0
BuildRequires:  libboost_date_time-devel >= 1.68.0
BuildRequires:  libboost_filesystem-devel >= 1.68.0
BuildRequires:  libboost_graph-devel >= 1.68.0
BuildRequires:  libboost_iostreams-devel >= 1.68.0
BuildRequires:  libboost_program_options-devel >= 1.68.0
BuildRequires:  libboost_random-devel >= 1.68.0
BuildRequires:  libboost_regex-devel >= 1.68.0
BuildRequires:  libboost_serialization-devel >= 1.68.0
BuildRequires:  libboost_system-devel >= 1.68.0
BuildRequires:  libboost_thread-devel >= 1.68.0
BuildRequires:  libboost_timer-devel >= 1.68.0
BuildRequires:  libboost_wave-devel >= 1.68.0
BuildRequires:  rose-devel
BuildRequires:  ncurses-devel
# vim package contains the xxd tool we actually need
BuildRequires:  vim
# NOTE: we may need to require a specific version of z3?
BuildRequires:  z3 >= 4.8
BuildRequires:  z3-devel >= 4.8
BuildRequires:  pl-devel >= 8.2.0
BuildRequires:  zlib-devel
BuildRequires:  libxml2-devel
BuildRequires:  libpng-devel
BuildRequires:  yaml-cpp-devel
BuildRequires:  ghostscript
BuildRequires:  libdwarf-devel
BuildRequires:  libelf-devel
# following is for libmagic
BuildRequires:  file-devel
# note that: sqlite3 is executable, packaged separate from library
BuildRequires:  sqlite3
BuildRequires:  sqlite3-devel
BuildRequires:  pkgconfig
Requires:       libncurses6
Requires:       rose
Requires:       z3 >= 4.8
Requires:       pl

%description
The Pharos static binary analysis framework is a project of the Software Engineering Institute at Carnegie Mellon University. The framework is designed to facilitate the automated analysis of binary programs. It uses the ROSE compiler infrastructure developed by Lawrence Livermore National Laboratory for disassembly, control flow analysis, instruction semantics, and more.

%package -n libpharos
Summary:        Library for the Pharos Static Binary Analysis Framework
Group:          "Development/Libraries/C and C++"
Requires:       %{name} = %{version}

%description -n libpharos
The Pharos static binary analysis framework is a project of the Software Engineering Institute at Carnegie Mellon University. The framework is designed to facilitate the automated analysis of binary programs. It uses the ROSE compiler infrastructure developed by Lawrence Livermore National Laboratory for disassembly, control flow analysis, instruction semantics, and more.

This subpackage contains the Pharos runtime library needed for Pharos tools and
other projects.

%package -n libpharos-devel
Summary:        Development files for libpharos
Group:          "Development/Libraries/C and C++"
Requires:       lib%{name} = %{version}

%description -n libpharos-devel
Development files, headers, and cmake configuration for libpharos.

%package apianalyzer
Summary:        A tool for finding sequences of API calls in an executable
Group:          "Development/Libraries/C and C++"
Requires:       lib%{name} = %{version}

%description apianalyzer
ApiAnalyzer is a tool for finding sequences of API calls with the specified data and control relationships. This capability is intended to be used to detect common operating system interaction paradigms like opening a file, writing to it, and the closing it.

This tool utilizes libpharos, the Pharos Static Binary Analysis Framework.

%package dumpmasm
Summary:        A tool for dumping disassembly listings from an executable
Group:          "Development/Libraries/C and C++"
Requires:       lib%{name} = %{version}

%description dumpmasm
DumpMASM is a tool for dumping disassembly listings from an executable using the Pharos framework in the same style as the other tools. It has not been actively maintained, and you should consider using ROSE's standard recursiveDisassemble instead.

This tool utilizes libpharos, the Pharos Static Binary Analysis Framework.

%package fn2hash
Summary:        A tool for generating hashes of functions in executables
Group:          "Development/Libraries/C and C++"
Requires:       lib%{name} = %{version}

%description fn2hash
FN2Hash is tool for generating a variety of hashes and other descriptive properties for functions in an executable program. Like FN2Yara it can be used to support binary similarity analysis, or provide features for machine learning algorithms.

This tool utilizes libpharos, the Pharos Static Binary Analysis Framework.

%package fn2yara
Summary:        A tool for generating YARA signatures of functions in executables
Group:          "Development/Libraries/C and C++"
Requires:       lib%{name} = %{version}

%description fn2yara
FN2Yara is a tool to generate YARA signatures for matching functions in an executable program. Programs that share significant numbers of functions are are likely to have behavior in common.

This tool utilizes libpharos, the Pharos Static Binary Analysis Framework.

%package callanalyzer
Summary:        A tool for reporting static parameters to API calls in executables
Group:          "Development/Libraries/C and C++"
Requires:       lib%{name} = %{version}

%description callanalyzer
CallAnalyzer is a tool for reporting the static parameters to API calls in a binary program. It is largely a demonstration of our current calling convention, parameter analysis, and type detection capabilities, although it also provides useful analysis of the code in a program.

This tool utilizes libpharos, the Pharos Static Binary Analysis Framework.

%package ooanalyzer
Summary:        A tool for the analysis and recovery of object oriented constructs
Group:          "Development/Libraries/C and C++"
Requires:       lib%{name} = %{version}

%description ooanalyzer
OOAnalyzer is a tool for the analysis and recovery of object oriented constructs. This tool was the subject of a paper titled "Using Logic Programming to Recover C++ Classes and Methods from Compiled Executables" which was published at the ACM Conference on Computer and Communications Security in 2018. The tool identifies object members and methods by tracking object pointers between functions in the program. A previous implementation of this tool was named "Objdigger", but it was renamed to reflect a substantial redesign using Prolog rules to recover the object attributes.

This tool utilizes libpharos, the Pharos Static Binary Analysis Framework.

%package pathanalyzer
Summary:        A tool for finding conditions necessary for paths in an executable
Group:          "Development/Libraries/C and C++"
Requires:       lib%{name} = %{version}

%description pathanalyzer
PathAnalyzer is a tool for finding conditions necessary for paths in an executable.

NOTE: This tool is still very experimental!

This tool utilizes libpharos, the Pharos Static Binary Analysis Framework.

%prep
%setup -q -c pharos
# use -c to create a dir
%patch0 -p1

%build
# we get failures with gcc9 link-time optimization (LTO) so disable for now
# see: https://en.opensuse.org/openSUSE:LTO
%define _lto_cflags %{nil}
#have to define different folder since pharos includes a file named "build"
%define __builddir pharos-build
%cmake \
  -DCMAKE_CXX_COMPILER=g++-8 \
  -DCMAKE_C_COMPILER=gcc-8 \
  -DPATHTEST_CXX_FLAGS="-O1"
#-DFIND_LIBRARY_USE_LIB64_PATHS=true

# to run tests with debugging output:
#../tools/ooanalyzer/tests/ooanalyzer-test.py -i -v -d ooex_vs2008/Debug/oo

%cmake_build

%install
%cmake_install

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files -n libpharos
%doc INSTALL.md
%dir %{_datadir}/doc/pharos
%{_datadir}/doc/pharos/CONTRIBUTING.md
%{_datadir}/doc/pharos/LICENSE.md
%{_datadir}/doc/pharos/README.md
%{_libdir}/libpharos.so
%dir %{_datadir}/pharos
%{_datadir}/pharos/pharos.yaml
%dir %{_datadir}/pharos/apidb
%{_datadir}/pharos/apidb/pharos-api-additions.json
%{_datadir}/pharos/apidb/pharos-apidb.sqlite
%dir %{_datadir}/pharos/typedb
%{_datadir}/pharos/typedb/types.json
%dir %{_datadir}/pharos/prolog
%dir %{_datadir}/pharos/prolog/oorules
%{_datadir}/pharos/prolog/oorules/*.xwam

%files -n libpharos-devel
%dir %{_includedir}/libpharos
%{_includedir}/libpharos/*.hpp
%dir %{_includedir}/libpharos/CMakeFiles
%{_includedir}/libpharos/CMakeFiles/generate_pharos_revision.dir
%{_includedir}/libpharos/CMakeFiles/pharos.dir
%dir %{_libdir}/cmake/libpharos
%{_libdir}/cmake/libpharos/*.cmake
%dir %{_includedir}/libpharos/CMakeFiles/Export
%dir %{_includedir}/libpharos/CMakeFiles/Export/lib64
%dir %{_includedir}/libpharos/CMakeFiles/Export/lib64/cmake
%dir %{_includedir}/libpharos/CMakeFiles/Export/lib64/cmake/libpharos

%files apianalyzer
%{_bindir}/apianalyzer
%{_mandir}/man1/apianalyzer.1.gz
%dir %{_datadir}/pharos/apianalyzer
%{_datadir}/pharos/apianalyzer/sig.json

%files dumpmasm
%{_bindir}/dumpmasm
%{_mandir}/man1/dumpmasm.1.gz

%files fn2hash
%{_bindir}/fn2hash
%{_bindir}/fse.py
%{_mandir}/man1/fn2hash.1.gz
%{_mandir}/man1/fse.1.gz

%files fn2yara
%{_bindir}/fn2yara
%{_mandir}/man1/fn2yara.1.gz

%files callanalyzer
%{_bindir}/callanalyzer
%{_mandir}/man1/callanalyzer.1.gz

%files ooanalyzer
%{_bindir}/ooanalyzer
%{_bindir}/OOAnalyzer.py
%{_mandir}/man1/ooanalyzer.1.gz
%{_mandir}/man1/ooanalyzer-plugin.1.gz

%files pathanalyzer
%{_bindir}/pathanalyzer
%{_bindir}/pathfinder
%{_mandir}/man1/pathanalyzer.1.gz


%changelog
