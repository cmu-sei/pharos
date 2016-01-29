The Pharos static analysis framework is a project of the Software
Engineering Institute at Carnegie Mellon University.  The framework is
designed to facilitate the automated analysis of binary programs.  It
uses the ROSE compiler infrastructure developed by Lawrence Livermore
National Laboratory for disassembly, control flow analysis,
instruction semantics, and more.

Objdigger is a tool built using the Pharos framework for the analysis
and recovery of object oriented constructs.  This tool was the subject
of a paper titled "Recovering C++ Objects From Binaries Using
Inter-Procedural Data-Flow Analysis" which was published at the ACM
SIGPLAN on Program Protection and Reverse Engineering Workshop in
2014.  The tool identifies object members and methods by tracking
object pointers between functions in the program.

FN2YARA is a tool built using the Pharos framework to generate YARA
signatures for matching functions in an executable program.  Programs
that share significant numbers of functions are are likely to have
behavior in common.

The Pharos framework is a research project, and the code is undergoing
active development.  No warranties of fitness for any purpose are
provided.  The current distribution in particular is part of an
ongoing process of releasing more of the framework and tools publicly.
Several libraries are required to build the tools, including
ROSE.  There is currently no documentation in the distribution.

This distribution includes the code required to build Objdigger and
FN2YARA, but it has not been extensively tested for build portability
or reliability.  This distribution has been successfully built with
the following development version of ROSE from 

  https://github.com/rose-compiler/rose-develop/commit/76ca4b8db9570b517f73e544f4b85de8469ad19d

You are likely to have difficuly building against other versions of
ROSE since their binary API is also evolving steadily.  We plan to
release updates to this distribution to support a more recent version
of ROSE soon.  In the meantime, you may find it more convenient to
download a binary distribution of the tools from:

  https://portal.cert.org/web/mc-portal/pharos-static-analysis-tools

Since the primary objective for releasing this code is to provide
transparency into our research and stimulate conversation with other
binary static analysis researchers, please feel free to contact Cory
Cohen <cfc@cert.org> with questions you may have about this work.  I
may be unable to respond in a timely manner, but I will do my best.

