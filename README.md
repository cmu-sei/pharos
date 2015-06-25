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

This repo does not currently contain a complete system that compiles
into an executable.  It instead contains portions of the framework
that has been reviewed, and is intended to be integrated back into the
ROSE compiler infrastructure.  We plan for the code available in this
repo to grow quickly so that objdigger can be built from source.

In the meantime, a binary distribution of objdigger is available from:

  https://portal.cert.org/web/mc-portal/pharos-static-analysis-tools
