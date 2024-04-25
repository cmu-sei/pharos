# Pharos OOAnalyzer Prolog Rules

## Background

The Pharos OOAnalyzer tool uses the Prolog files in this directory to
reason about the facts extracted from the executable.  Because the Prolog
step is executed automatically, there is no reason for a typical user to
concern themselves much with the contents of this directory and these files
have been considered to be mostly for developers of OOAnalyzer.  Recently
however, several users of OOAnalyzer have tried analyzing rather large
object-oriented programs, and there are known deficiencies in the
completely-automated one-step approach represented by simply running
OOAnalyzer with default settings.

The OOAnalyzer developers often use a multi-step process that separates
various stages of analysis. This provides for easier recovery from
failures, slightly reduced resource requirements, and most importantly,
dramatically better performance in some cases.  One of the key
differences is based on the recent development that SWI Prolog's tabling
support is now sufficient to run the OOAnalyzer Prolog analysis stage,
and that it performs much better in general than the XSB implementation
that was previously used.  Users facing problems associated with the
analysis of large object-oriented executables are encouraged to use the
following procedure because it breaks the entire process up into smaller
steps, so that if one fails, you don't have to restart from the
beginning.


## Installation Requirements

If you are building Pharos from source, make sure that you [install
SWI Prolog and configure Pharos to use
it](../../../INSTALL.md#swi-prolog-optional).  If you use our Docker
image or build scripts, SWI should be available.

## Analyzing Large Executables

### Step One: Partitioning

The first step is to complete the partitioning phase of analysis, where
the Pharos system disassembles the executable, identifies function
boundaries, and prepares to begin more detailed function analysis to
determine object-oriented properties.  There are several reasons why it
is important to separate the partitioning step from later steps.

For large files, this stage requires a lot of memory because the entire
executable is disassembled in RAM at once, and each instruction becomes
several memory objects representing instructions, operands, basic,
blocks, and functions.  RAM requirements can be 1000 times the size of
the input executable, which is typically not a problem for files that
are kilobytes in size, but can be a serious difficulty for files that
are multiple megabytes.  This memory consumption is largely driven by
design decisions in ROSE and are not easily correctable in Pharos, but
we are discussing the issue with the ROSE developers (where it is also a
non-trivial change).  One bit of good news here is that due to the
memory access patterns, some users have obtained good results by simply
increasing their system swap space significantly.

Another problem is that depending on the partitioner options that you
use, there can be long execution times for some large input files, where
it is unclear how beneficial the additional analysis really is.  This
aspect of the problem is caused by differences in the partitioning
algorithm that is used.  By default, OOAnalyzer is configured to produce
the most accurate and complete disassembly that it is capable of.  For
large files, many users many find the less accurate partitioning
algorithm produces better results because the partitioning step actually
completes.

Most importantly, because this step takes a non-trivial amount of time,
and should not need to be repeated if other problems are encountered
later, it is important to utilize a Pharos feature for saving the
results of this step before proceeding to later stages.

In order to avoid starting later analysis steps automatically, we often
use a different Pharos tool to complete the partitioning step, and then
save those results to a serialization file.

```
partition --serialize=ooprog.ser --maximum-memory=128000 --no-semantics ooprog.exe
```

The primary goal of this command is to create the `ooprog.ser` file,
which is a Boost serialization of the partitioning results, and is
enabled with the option `--serialize=<filename>`.  This file allows us
to perform later analysis without repeating the partitioning step.  For
example, a first invocation of this command reported:

```
OPTI[INFO ]: Function partitioning took 27.7931 seconds.
OPTI[INFO ]: Writing serialized data to "ooprog.ser".
OPTI[INFO ]: Writing serialized data took 38.2657 seconds.
OPTI[INFO ]: Partitioned 654308 bytes, 222289 instructions, 56639 basic blocks, 150 data blocks and 3908 functions.
```

While running the same command ran a second time reported:

```
OPTI[INFO ]: Reading serialized data from "ooprog.ser".
OPTI[INFO ]: Reading serialized data took 21.6498 seconds.
```

While there was no improvement on this relatively small file, using this
option with large files can save hours when performing later analysis
stages.

The `--maximum-memory` option sets the maximum amount of memory before
exiting (in megabytes).  This option should be set to as large a value
as possible to prevent premature exits during partitioning.  We
recommend choosing a large value like 128000 (128GB).  Of course,
specifying a larger value does not give your computer additional
RAM. ;-)

There are two options that can reduce the runtime of the partitioner.
The `--no-semantics` option disables the semantic analysis of
instructions during partitioning.  This semantic analysis is very
expensive, but may be required to detect certain malicious obfuscations
and non-standard control flow.  Assuming that your input program is not
malicious and only has normal control flow, using this option can reduce
partitioning times dramatically. The second option is
`--partitioner=rose`, which disables some of the custom behaviors in the
Pharos partitioner, such as more aggressively searching for disconnected
code.  As can be seen in the test example below, partitioning without
either of these options took approximately 430 seconds instead of 27
seconds:

```
OPTI[INFO ]: ROSE stock partitioning took 400.103 seconds.
OPTI[INFO ]: Partitioned 652519 bytes, 221785 instructions, 57164 basic blocks, 149 data blocks and 3915 functions.
OPTI[INFO ]: Function partitioning took 430.479 seconds.
OPTI[INFO ]: Writing serialized data to "ooprog.ser".
OPTI[INFO ]: Writing serialized data took 38.8095 seconds.
OPTI[INFO ]: Partitioned 718962 bytes, 231603 instructions, 60524 basic blocks, 3389 data blocks and 4492 functions.
```

As you can see, only a small number of differences in the data blocks
and functions occurred during partitioning, despite taking 15 times as
long!  For this reason, we often run large executables with
`--no-semantics`.

On our original sample, which uses `--no-semantics`, the contribution of
the Pharos partitioning extensions can be seen because `--partitioner=rose`
was not specified.  These lines first show when the stock ROSE
partitioner completes, and then after the Pharos partitioner has
completed:

```
OPTI[INFO ]: ROSE stock partitioning took 27.0066 seconds.
OPTI[INFO ]: Partitioned 652504 bytes, 221780 instructions, 56534 basic blocks, 148 data blocks and 3909 functions.
OPTI[INFO ]: Function partitioning took 39.2653 seconds.
```

... and after Pharos partitioning refinement ...

```
OPTI[INFO ]: Partitioned 718960 bytes, 231603 instructions, 59893 basic blocks, 3388 data blocks and 4485 functions.
```

Whether the 3240 additional data blocks and the 576 additional functions
found by the Pharos partitioner are important is not well understood.
The additional functions are often exception handlers, and other
functions that do not appear to greatly affect object detection.  The
additional data blocks are unlikely to affect object detection unless
they are global static objects.  For large files in particular, the
additional 12 seconds required in this example can grow to hours of
analysis due to complexity problems in the partitioning.

In general these times are representative of the increases in runtime
that you might experience, but different input executables can result in
dramatically different execution times.  In this sample,
omitting`--no-semantics` was more expensive, but for other input
executables, the relative cost of omitting the two options may be
reversed.  We recommend that you start the process with 
`--no-semantics` since it can reduce partitioning time for large files,
but not `--partitioner=rose` since it can lead to less accurate results,
although that's an oversimplification of the tradeoffs.

### Step Two: Object-Oriented Analysis of Functions

In this step, our goal is to produce object-oriented facts about the
executable program by performing the "lightweight" binary analysis we
described in our
[paper](https://dl.acm.org/doi/abs/10.1145/3243734.3243793).  During
this phase, we will resolve problems with imports, analyze the functions
in the program, and produce a data file containing Prolog facts
describing the object-oriented features of the program.

We recommend that you run a command like this:

```
ooanalyzer --serialize=ooprog.ser --maximum-memory 128000 --no-semantics --prolog-facts=ooprog-facts.pl --threads=16 --per-function-timeout=60 ooprog.exe
```

The `--serialize` option causes OOAnalyzer to read the previously
serialized partitioning results.  The `--maximum-memory` option is
required because the deserialized partitioning results takes
approximately the same amount of RAM as doing the partitioning.

The `--prolog-facts` option instructs OOAnalyzer to only run the fact
generation step, and to write the results out to `ooprog-facts.pl`.

This step is one of the few steps in the Pharos system that takes
advantage of multi-threading, so if you have multiple processors, you
should specify `--threads=N`, where N is the number of processors.  The
functions are analyzed in a bottom-up dependency order, so it is normal
for the parallelization (and overall progress) to slow near the end.  On
our sample program, this analysis phase took approximately 122 seconds.

The `--per-function-timeout=60` option shows how to control the analysis
time limit per function, and sixty seconds is the default.  If you
receive a significant number of errors that look like this:

```
FSEM[ERROR]: Analysis of function 0x00492DA0 failed: relative CPU time exceeded; adjust with --per-function-timeout
```

you may need to increase the timeout.

If desired, you may specify `--verbose`, which will report more messages
about each function.  We do not recommend this in general, because it
produces a lot of spew, but you may find this option informative during
this step.

You may also encounter a few warnings like this:

```
APID[WARN ]: API database has no data for DLL: DLLNAME
OOAN[WARN ]: No stack delta information for: DLLNAME.dll:FunctionName
```

These warnings indicate that that the API database does not have the
required information for `<DLLNAME>` in general and for `<FunctionName>`
in particular.  While a few such errors are not usually a serious
problem, if you see many of these errors, you should probably correct
them by extending the API database with `--apidb dllname.json`, and the
appropriate contents of the JSON file.  For non-OO functions, it is most
important to list the "stack delta", which is the number of bytes popped
off the stack in the Windows syscall calling convention (equivalent to
the number of parameters times four).

If near the end of your output you receive these messages:

```
OOAN[ERROR]: No new() methods were found.  Heap objects may not be detected.
OOAN[ERROR]: No delete() methods were found.  Object analysis may be impaired.
```

You may want to manually identify `new()` and `delete()` methods with
some reverse engineering, and add the options `--new-method=0x<ADDR>`
and `--delete-method=0x<ADDR>`, which can be specified multiple times.
Obviously the correct identification of `new()` and `delete()` can be
fairly important to correct object detection, so you may need to repeat
this step with those options.

Our experience is that manually identifying `new()` and `delete()`
through reverse engineering is fairly easy after the Prolog step
completes because many constructors and destructors have been
identified, which makes the task easier.

These messages:

```
OOAN[WARN ]: Unable to find parameter for new() call at 0x004D8F49
```

Mostly indicate problems in object-oriented analysis that are poorly
understood.  They can be ignored, although large numbers of them may not
bode well for your ultimate results.

It is normal for this phase to complete with the following messages.

```
OOAN[INFO ]: Exported <xxxx> Prolog facts to 'ooprog-facts.pl'.
OPTI[WARN ]: OOAnalyzer did not perform C++ class analysis.
OPTI[INFO ]: OOAnalyzer analysis complete.
```

These simply indicate that that OOAnalyzer did not perform the next
step, which is...

### Step Three: Prolog Analysis

When step two has completed successfully, you should have a file
containing many Prolog facts about the input program.  You can manually
inspect this file to get a sense of whether the previous step completed
successfully.  Obviously a file containing no facts, or a small number
of facts means that either your program is not in fact object-oriented
or that something went substantially wrong.

For large files we recommend a command like:

```
awk -F\( '{print $1}' ooprog-facts.pl | sort | uniq -c
```

This command will show the distribution of facts recovered from the
executable, and should contain RTTI facts if your file has RTTI.  Other
facts strongly indicating successful object-oriented fact detection
include `thisPtrOffset`, `thisPtrAllocation`, `thisPtrUsage`,
`possibleVFTableWrite`, and `possibleVirtualFunctionCall`.

If your fact generation failed, you may need to revisit the previous
step, or OOAnalyzer may have failed on your input program.  If you
have a reasonable set of facts, you can proceed with the Prolog phase
of object-oriented analysis by running the following command:

```
ooprolog --facts ooprog-facts.pl --results ooprog-results.pl --log-level=6 >ooprog.log
```

This command runs the Prolog analysis phase in SWI Prolog.  Additionally,
because the previous function analysis step has exited, we no longer have
the partitioning results in RAM when starting a rather expensive new
analysis step.  (It is difficult to free all the RAM required from
partitioning, because we need some of it for later steps in the normal
OOAnalyzer execution model.)

This step can be expensive and time consuming as well, and sometimes
fails for a variety of reasons that may require restarting. In the
traditional OOAnalyzer execution model, a failure during this step would
mean going all the way back to partitioning and fact generation again!

The spew written to the log file will let you know how analysis is
progressing.  It is primarily designed for developer debugging, and a
detailed explanation of all of the messages here would be difficult.  As
a first approximation of how to interpret the results, it is beneficial
to be generating lots of new facts.  It is also normal for facts to be
retracted and asserted, usually because two classes have been merged.
It is also normal for "trigger" facts to be processed.

As the analysis progresses, the Prolog analysis code will begin making
"guesses".  This transition is marked by the message:

```
Making new hypothetical guesses ...
```

While this should typically result in new conclusions, it is not
uncommon for guesses to occasionally result in failures and retractions
due to making incorrect guesses.  These two possible outcomes from a
guess are marked by one of these two messages:

```
Constraint checks succeeded, guess accepted!
Constraint checks failed, retracting guess!
```

In general, if this step is continuing to spew messages, it is still
making progress.

When this step completes, hopefully your log contains the message:

```
No plausible guesses remain, finalizing answer.
```

This indicates that the Prolog analysis found a consistent solution to
the set of input facts. But it may instead contain:

```
No complete solution was found!
```

This indicates that the final answer was contradictory in some way, and
that the result was in some way incorrect.  In is normal for some
classes to be discarded as "worthless" near the end of the Prolog phase.
These are classes that have only a single method in them (and may not in
fact be classes at all).  

The final results should be found in the ooprog-results.pl file that was
created. These results should be be nearly identical to the those produced
by the `--prolog-results` option on the
OOAnalyzer command.  You can inspect this file manually to get a sense
for how well OOAnalyzer did or run the `awk` command from earlier to get
a distribution of results.  For a successful execution, there should be
a reasonable number of `finalClass` results.

### Step Four: Prolog JSON generation

Before June 2, 2020, there was no convenient way to convert the Prolog
results into the JSON format without invoking the JSON exporting code
that was compiled into the OOAnalyzer executable.  This was inconvenient
for large files because the recommended procedure described above
generated Prolog results without generating the JSON file, and there was
no way to convert those results into the JSON format which is consumed
by the plugins.  As the developers of OOAnalyzer, we are often content
to review the Prolog results directly, but end-users of OOAnalyzer of
course want to reverse-engineer the actual object-oriented executable in
IDA Pro or Ghidra.

The new `ooprolog` command is also capable of generating JSON results.
This step could have been executed previously by simply adding `--json`
to the previous `ooprolog` command, but we've chosen to show how it can
also be run as a separate step.

```
ooprolog --results ooprog-results.pl --json ooprog.json
```

In just a few seconds, this command should produce a JSON file that is
identical to the one that would have been produced using the `--json`
option of the OOAnalyzer command.

### Step Five: Load the JSON into IDA Pro and/or Ghidra

This step is identical to the normal procedure for importing JSON files, so we
will not go into more detail here.  See the README for [IDA
Pro](https://github.com/cmu-sei/pharos/blob/master/tools/ooanalyzer/ida/README.md)
or
[Ghidra](https://github.com/CERTCC/kaiju/blob/main/docs/OOAnalyzerImporter.md)
for more information.

### Conclusion

This multi-step manual procedure is recommended for large
object-oriented programs because it increases your ability to diagnose
problems, restart failed steps, and generally control the OOAnalyzer
process more carefully.  We recognize that it is less convenient than
simply running the OOAnalyzer command and waiting, but given the number
of recent requests to analyze large object-oriented programs, we
concluded that we should better document this more complex process.  We
hope to integrate SWI Prolog directly into the OOAnalyzer tool.  In the
mean time, we strongly recommend this process for object oriented
programs with more than 100 classes or a megabyte in file size.

## About the Prolog Rules

Since this directory is really about the Prolog rules (and not
explicitly about the manual OOAnalyzer process documented above), we
should say a few words about the rules themselves.

The `facts.pl` file documents the facts generated during step two.  The
`results.pl` file documents the results generated in step three.  The
`oojson.pl` file implements the JSON generation that occurs in step four.
The remaining files implement the Prolog reasoning in step three.

The `rules.pl` file implements the "forward" reasoning rules that reach
direct conclusions from existing facts about the input program.  This
file is likely to be the most interesting to people wanting to learn
more about step three.  The `guess.pl` file implements the "guesses" that
drive learning in the latter part of step three.  The `insanity.pl` file
implements consistency checks that determine whether a guess was
consistent with the other facts.  The `forward.pl` and `trigger.pl` files
implement logic related to improving performance of the Prolog phase by
deferring the re-computation of certain conclusions.  The `final.pl` file
handles final reporting, and the remaining files will mostly make sense
in context once those parts of the system are better understood.

[comment]: # ( Local Variables: )
[comment]: # ( fill-column: 73  )
[comment]: # ( End:             )
