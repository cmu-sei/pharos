# Pharos Static Binary Analysis Framework

The Pharos static binary analysis framework is a project of the
Software Engineering Institute at Carnegie Mellon University.  The
framework is designed to facilitate the automated analysis of binary
programs.  It uses the ROSE compiler infrastructure developed by
Lawrence Livermore National Laboratory for disassembly, control flow
analysis, instruction semantics, and more.

The current distribution is a substantial update to the previous
version, and is part of an ongoing process to release more of the
framework and tools publicly.  This software is released under a BSD
[license](LICENSE.md).  Carnegie Mellon University retains the
[copyright](COPYRIGHT.md).

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

## APIAnalyzer

ApiAnalyzer is a tool for finding sequences of API calls with the
specified data and control relationships.  This capability is intended
to be used to detect common operating system interaction paradigms
like opening a file, writing to it, and the closing it.

## OOAnalyzer

OOAnalyzer is a tool for the analysis and recovery of object oriented
constructs.  This tool was the subject of a paper titled "Recovering
C++ Objects From Binaries Using Inter-Procedural Data-Flow Analysis"
which was published at the ACM SIGPLAN on Program Protection and
Reverse Engineering Workshop in 2014.  The tool identifies object
members and methods by tracking object pointers between functions in
the program.  This tool was previously named "Objdigger" and is in the
process of being renamed OOAnalyzer as part of a substantial redesign
using Prolog rules to recover the object attributes.

## CallAnalyzer

CallAnalyzer is a tool for reporting the static parameters to API
calls in a binary program.  It is largely a demonstration of our
current calling convention, parameter analysis, and type detection
capabilities, although it also provides useful analysis of the code in
a program.

## FN2Yara

FN2Yara is a tool to generate YARA signatures for matching functions
in an executable program.  Programs that share significant numbers of
functions are are likely to have behavior in common.

## FN2Hash

FN2Hash is tool for generating a variety of hashes and other
descriptive properties for functions in an executable program.  Like
FN2Yara it can be used to support binary similarity analysis, or
provide features for machine learning algorithms.

## DumpMASM

DumpMASM is a tool for dumping disassembly listings from an executable
using the Pharos framework in the same style as the other tools.  It
has not been actively maintained, and you should consider using ROSE's
standard recursiveDisassemble instead
<http://rosecompiler.org/ROSE_HTML_Reference/rosetools.html>.


