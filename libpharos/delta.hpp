// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Delta_H
#define Pharos_Delta_H

#include "enums.hpp"

// Our confidence in the correctness of the stack delta.  This is a strict ordering from least
// confident to most confident.  Comparisons of the form (confidence <= DeltaConfident) are
// explicitly allowed so take caution.
enum GenericConfidence {
  ConfidenceNone,
  ConfidenceWrong,
  ConfidenceGuess,
  ConfidenceConfident,
  ConfidenceUser,  
  ConfidenceCertain,
  ConfidenceUnspecified
};

// A helper function to print negative hexadecimal values.
std::string neghex(int x);

// StackDelta is basically a glorified struct, but we might want to put some accessors and
// convience methods on the confidence and delta members.
class StackDelta {
public:

  // The stack delta before the instruction executes.  Stack deltas are measured from the value
  // zero occuring before the first instruction at the entry point of the function.  e.g. after
  // any call has pushed the return address onto the stack, but before any code in this
  // function has executed.

  // Because the stack pointer usually has a negative value relative to the start of the
  // function, and because lots of negative numbers are unpleasant to look at (especially in
  // hexadecimal), we're going to adopt the same convention that IDA Pro has, which is to
  // reverse the sign of the delta.  Thus a push instruction subtracts 4 from ESP, buts adds 4
  // to the delta.  Care needs to be taken to correct sign when interacting with parts of the
  // system that use the real semantics of the architecture.
  int delta;

  // This is our confidence in the current stack delta value.  It allows us to decide the
  // confidence derivative values for things like stack memory access, to decide whether we
  // should try harder to determine a correct answer, and whether we need to repeat previous
  // analysis in the presence of improved data.
  GenericConfidence confidence;

  StackDelta(int d, GenericConfidence c) { delta = d; confidence = c; }
  StackDelta() { delta = 0; confidence = ConfidenceNone; }

  void print(std::ostream &o) const { o << neghex(delta) << "(" << Enum2Str(confidence) << ")"; }
  friend std::ostream& operator<<(std::ostream &o, const StackDelta &sd) {
    sd.print(o);
    return o;
  }
};

typedef std::map<rose_addr_t, StackDelta> StackDeltaMap;

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
