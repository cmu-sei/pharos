#=========================================================================================
# Set the paths to various libraries if needed.
#=========================================================================================
#ROSE_ROOT = /usr/local
#YICES_ROOT = /usr/local
#BOOST_ROOT = /usr/local
#CRYPTO_ROOT = /usr/local
#Z3_ROOT = /usr/local

BASIC_OPT = -g -O3 -std=c++11 -pthread
PEDANTRY = -Wall -Wextra -Wshadow -Wstrict-aliasing
OPT = $(BASIC_OPT) $(PEDANTRY)

EXTRA_CXXFLAGS =
EXTRA_INCLUDES =
EXTRA_LDFLAGS =

BOOST_MT_SUFFIX =

# include your personal overrides of the above vars in here
# (doesn't matter if the file doesn't exist):
-include Makefile.inc

########################################
ROSE_LIBS = -lrose -lyaml-cpp
ROSE_CONFIG = $(ROSE_ROOT)/bin/rose-config

# ROSE requires libhpdf (libharu), a PDF generation library that ships and builds with ROSE
# ROSE requires libgcrypt which in turn requires libgpg-error
# ROSE requires dladdr(), a function from libdl
# ROSE requires all of the boost libraries (or close)
ROSE_SLIBS = -lhpdf -lgcrypt -lgpg-error -ldl
ROSE_INCLUDES = -isystem $(ROSE_ROOT)/include/rose
ROSE_LIB_DIR = $(ROSE_ROOT)/lib
ROSE_LDFLAGS = -L$(ROSE_LIB_DIR) -Wl,-rpath $(ROSE_LIB_DIR) $(ROSE_LIBS) $(BOOST_LDFLAGS)
ROSE_SLDFLAGS = -L$(ROSE_LIB_DIR) $(ROSE_LIBS) $(ROSE_SLIBS) $(BOOST_SLDFLAGS)
#ROSE_LDFLAGS = -Wl,-rpath $(ROSE_LIB_DIR) $(shell $(ROSE_CONFIG) ldflags)
#ROSE_SLDFLAGS = $(shell $(ROSE_CONFIG) ldflags)

########################################
BOOST_LIBS = -lboost_system$(BOOST_MT_SUFFIX) -lboost_thread$(BOOST_MT_SUFFIX) -lboost_program_options$(BOOST_MT_SUFFIX) -lboost_iostreams$(BOOST_MT_SUFFIX) -lboost_filesystem$(BOOST_MT_SUFFIX)
BOOST_SLIBS = $(BOOST_LIBS) -lboost_wave$(BOOST_MT_SUFFIX) -lboost_regex$(BOOST_MT_SUFFIX) -lpthread -licui18n -licuuc -licudata
ifneq ($(wildcard $(BOOST_ROOT)), )
BOOST_INCLUDES = -isystem $(BOOST_ROOT)/include
BOOST_LIB_DIR = $(BOOST_ROOT)/lib
BOOST_LDEXTRA = -L$(BOOST_LIB_DIR) -Wl,-rpath $(BOOST_LIB_DIR) $(BOOST_LIBS)
BOOST_SLDEXTRA = -L$(BOOST_LIB_DIR) $(BOOST_SLIBS)
endif
BOOST_LDFLAGS = $(BOOST_LDEXTRA) $(BOOST_LIBS)
BOOST_SLDFLAGS = $(BOOST_LDEXTRA) $(BOOST_SLIBS)

########################################
YICES_LIBS = -lyices -lm
YICES_SLIBS = $(YICES_LIBS)
ifneq ($(wildcard $(YICES_ROOT)), )
YICES_INCLUDES = -isystem $(YICES_ROOT)/include
YICES_LIB_DIR = $(YICES_ROOT)/lib
YICES_LDEXTRA = -L$(YICES_LIB_DIR) -Wl,-rpath $(YICES_LIB_DIR)
YICES_SLDEXTRA = -L$(YICES_LIB_DIR)
endif
YICES_LDFLAGS = $(YICES_LDEXTRA) $(YICES_LIBS)
YICES_SLDFLAGS = $(YICES_SLDEXTRA) $(YICES_SLIBS)

########################################
CRYPTO_LIBS = -lcryptopp
CRYPTO_SLIBS = $(CRYPTO_LIBS)
ifneq ($(wildcard $(CRYPTO_ROOT)), )
CRYPTO_INCLUDES = -isystem $(CRYPTO_ROOT)/include
CRYPTO_LIB_DIR = $(CRYPTO_ROOT)/lib
CRYPTO_LDEXTRA = -L$(CRYPTO_LIB_DIR) -Wl,-rpath $(CRYPTO_LIB_DIR) $(CRYPTO_LIBS)
CRYPTO_SLDEXTRA = -L$(CRYPTO_LIB_DIR) $(CRYPTO_LIBS)
endif
CRYPTO_LDFLAGS = $(CRYPTO_LDEXTRA) $(CRYPTO_LIBS)
CRYPTO_SLDFLAGS = $(CRYPTO_SLDEXTRA) $(CRYPTO_SLIBS)

########################################

INCLUDES = -Ilibpharos $(ROSE_INCLUDES) $(YICES_INCLUDES) $(CRYPTO_INCLUDES) $(BOOST_INCLUDES) $(EXTRA_INCLUDES)
CXXFLAGS = $(OPT) $(INCLUDES) $(EXTRA_CXXFLAGS)
CXXFLAGSNP = $(BASIC_OPT) $(INCLUDES) $(EXTRA_CXXFLAGS)
LDFLAGS = -lncurses $(ROSE_LDFLAGS) $(YICES_LDFLAGS) $(CRYPTO_LDFLAGS) $(EXTRA_LDFLAGS)
# librt is for clock_gettime
SLDFLAGS = --static -Xlinker -zmuldefs -lncurses $(ROSE_SLDFLAGS) $(YICES_SLDFLAGS) $(CRYPTO_SLDFLAGS) $(EXTRA_LDFLAGS) -lrt -ltinfo

########################################

BINARIES = objdigger/objdigger fn2yara/fn2yara
STATIC_BINARIES = objdigger/objdigger-static fn2yara/fn2yara-static
YAML_INCLUDES = libpharos/config.yaml.i

all: $(BINARIES)

static: $(STATIC_BINARIES)

LIB_OBJS = libpharos/options.o libpharos/masm.o libpharos/misc.o \
	libpharos/util.o libpharos/semantics.o libpharos/partitioner.o \
	libpharos/limit.o libpharos/config.o libpharos/dllapi.o \
	libpharos/descriptors.o libpharos/funcs.o libpharos/calls.o \
	libpharos/imports.o libpharos/globals.o libpharos/vcall.o \
	libpharos/convention.o libpharos/riscops.o libpharos/state.o \
	libpharos/defuse.o libpharos/sptrack.o libpharos/pdg.o \
	libpharos/cdg.o libpharos/vftable.o libpharos/class.o \
	libpharos/member.o libpharos/method.o libpharos/usage.o \
	libpharos/jsonoo.o libpharos/ooanalyzer.o libpharos/stkvar.o

libpharos/libpharos.a: $(LIB_OBJS)
	$(AR) rcs $@ $+

objdigger/objdigger: objdigger/objdigger.o libpharos/libpharos.a
	$(CXX) $+ $(LDFLAGS) -o $@
	strip $@

objdigger/objdigger-static: objdigger/objdigger.o libpharos/libpharos.a
	$(CXX) $+ $(SLDFLAGS) -o $@
	strip $@

fn2yara/fn2yara: fn2yara/fn2yara.o libpharos/libpharos.a
	$(CXX) $+ $(LDFLAGS) -o $@
	strip $@

fn2yara/fn2yara-static: fn2yara/fn2yara.o libpharos/libpharos.a
	$(CXX) $+ $(SLDFLAGS) -o $@
	strip $@

%.yaml.i : %.yaml
	xxd -i $< > $@

clean:
	$(RM) $(BINARIES) $(STATIC_BINARIES) libpharos/libpharos.a */*.o libpharos/*.yaml.i

depends: $(YAML_INCLUDES)
	g++ -MM $(INCLUDES) objdigger/objdigger.cpp fn2yara/fn2yara.cpp > Makefile.depends
	for f in libpharos/*.cpp; do \
	   b=`basename $$f .cpp`; \
	   g++ -MM $(INCUDES) -MT libpharos/$$b.o $$f >> Makefile.depends ; \
	done

# Cut and paste the results from "make depends" below here.
-include Makefile.depends
