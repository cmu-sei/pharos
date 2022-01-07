# Pharos Static Binary Analysis Framework

The Pharos static binary analysis framework is a project of the
Software Engineering Institute at Carnegie Mellon University.  The
framework is designed to facilitate the automated analysis of binary
programs.  It uses the ROSE compiler infrastructure developed by
Lawrence Livermore National Laboratory for disassembly, control flow
analysis, instruction semantics, and more. This software is released
under a BSD [license](LICENSE.md).

The current distribution is a substantial update to the previous
version, and adds a variety of features including improvements to the
OOAnalyzer tool, experimental path analysis code, partitioner
improvements, multi-threading, and many other smaller features.

The Pharos framework is a research project, and the code is undergoing
active development.  No warranties of fitness for any purpose are
provided. While this release provides build instructions, unit tests,
and some documentation, much work remains to be done.  We've tested a
few select build configurations, but we have not actively tested the
portability of the source code. See the [installation
instructions](INSTALL.md) for more details.

Since the primary objective for releasing this code is to provide
transparency into our research and stimulate conversation with other
binary static analysis researchers, please feel free to contact Cory
Cohen <cfc@cert.org> with questions you may have about this work.  I
may be unable to respond in a timely manner, but I will do my best.

# Pharos Static Binary Analysis Tools

## [APIAnalyzer](tools/apianalyzer/apianalyzer.pod)

ApiAnalyzer is a tool for finding sequences of API calls with the
specified data and control relationships.  This capability is intended
to be used to detect common operating system interaction paradigms
like opening a file, writing to it, and the closing it.

## [OOAnalyzer](tools/ooanalyzer/ooanalyzer.pod)

OOAnalyzer is a tool for the analysis and recovery of object oriented constructs. This tool was
the subject of a paper titled ["Using Logic Programming to Recover C++ Classes and Methods from
Compiled Executables"](https://edmcman.github.io/papers/ccs18.pdf) which was published at the
ACM Conference on Computer and Communications Security in 2018. The tool identifies object
members and methods by tracking object pointers between functions in the program.  A previous
implementation of this tool was named "Objdigger", but it was renamed to reflect a substantial
redesign using Prolog rules to recover the object attributes.  The current version of the tool
only supports analysis of 32-bit x86 executables compiled by Microsoft Visual C++.  For more
detailed instructons on how to run OOAnalyzer on very large executables, see these
[notes](share/prolog/oorules/README.md).

The Pharos distribution used to include a plugin that imported OO
information exported by OOAnalayzer into the
[Ghidra](https://ghidra-sre.org/) reverse engineering tool set.  To get
that functionality now and in the future, install the
[Kaiju](https://github.com/CERTCC/kaiju) Ghidra plugin, which includes
the functionality that was provided by the OOAnalayzer plugin.

## [CallAnalyzer](tools/callanalyzer/callanalyzer.pod)

CallAnalyzer is a tool for reporting the static parameters to API
calls in a binary program.  It is largely a demonstration of our
current calling convention, parameter analysis, and type detection
capabilities, although it also provides useful analysis of the code in
a program.

## [FN2Yara](tools/fn2yara/fn2yara.pod)

FN2Yara is a tool to generate YARA signatures for matching functions
in an executable program.  Programs that share significant numbers of
functions are are likely to have behavior in common.

## [FN2Hash](tools/fn2hash/fn2hash.pod)

FN2Hash is tool for generating a variety of hashes and other
descriptive properties for functions in an executable program.  Like
FN2Yara it can be used to support binary similarity analysis, or
provide features for machine learning algorithms.

## [DumpMASM](tools/dumpmasm/dumpmasm.pod)

DumpMASM is a tool for dumping disassembly listings from an executable
using the Pharos framework in the same style as the other tools.  It
has not been actively maintained, and you should consider using ROSE's
standard recursiveDisassemble instead
<http://rosecompiler.org/ROSE_HTML_Reference/rosetools.html>.


