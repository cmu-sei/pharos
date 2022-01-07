// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/algorithm/string.hpp>

#include <string>
#include <vector>

#include "sptrack.hpp"
#include "cdg.hpp"

namespace pharos {

// A hackish helper function for negative hex stack deltas. (Unused)
std::string neghex(int x) {
  std::string result;
  if (x >= 0) {
    result = str(boost::format("+%04X") % x);
  }
  else {
    result = str(boost::format("-%04X") % -x);
  }
  return result;
}

void spTracker::update_delta(rose_addr_t addr, StackDelta const & sd, size_t & failures) {
  StackDelta current = get_delta(addr);

  write_guard<decltype(mutex)> guard{mutex};

  // This status reporting is substantially more verbose than we will need after we've
  // debugged this throughly.  In the mean time, I'd like to log every questionable update.
  if (sd.confidence < current.confidence) {
    SDEBUG << "Improving stack delta confidence: addr=" << addr_str(addr)
           << " new=" << sd << " old=" << current << LEND;
  }
  else if (sd.confidence == current.confidence) {
    // No change is one case we certainly don't care about.
    if (sd.delta == current.delta) return;
    // We also don't want to report replacing "none" values.
    if (current.confidence == ConfidenceNone) return;

    // If we are merging a missing stack delta with a better-than-missing stack delta, use the
    // better value.  This is because the missing stack delta is represented by a variable,
    // which we can say takes on the value of the better delta.  If we had done stack call
    // analysis in a separate pass, we could have already resolved this.  We should probably do
    // that in the near future.
    if (sd.confidence == ConfidenceMissing && current.confidence >= ConfidenceMissing) {
      return;
    }
    if (current.confidence == ConfidenceMissing && sd.confidence >= ConfidenceMissing) {
      current.confidence = sd.confidence;
      current.delta = sd.delta;
      deltas[addr] = current;
      return;
    }

    // If we reached here, something is definitely wrong.  This message should be be "error"
    // level, but it's still spewing frequently enough that for the time being Cory reduced it
    // back to debug so as not to annoy general users of the tool.  Instead, we ticking
    // failures each time, and that allows us to test for stack delta analysis failures in
    // general at the end of the function.
    SDEBUG << "Attempt to alter stack delta value: addr=" << addr_str(addr)
           << " new=" << sd << " old=" << current << LEND;
    failures++;
    // Force the confidence down to Wrong.
    current.confidence = ConfidenceWrong;
    deltas[addr] = current;
    return;
  }
  else {
    if (current.confidence != ConfidenceNone) {
      SDEBUG << "Lowering stack delta confidence: addr=" << addr_str(addr)
             << " new=" << sd << " old=" << current << LEND;
    }
  }
  deltas[addr] = sd;
}

const StackDelta spTracker::get_delta(rose_addr_t addr) const {
  write_guard<decltype(mutex)> guard{mutex};
  auto finder = deltas.find(addr);
  if (finder == deltas.end()) return StackDelta(0, ConfidenceNone);
  else return finder->second;
}

const StackDelta spTracker::get_call_delta(rose_addr_t addr, size_t & failures) {

  const CallDescriptor* cd = descriptor_set.get_call(addr);
  SDEBUG << "Getting stack delta for call " << addr_str(addr) << LEND;

  write_guard<decltype(mutex)> guard{mutex};

  if (cd == NULL) {
    failures++;
    SERROR << "Unable to find call descriptor for address: " << addr_str(addr) << LEND;
    return StackDelta(0, ConfidenceWrong);
  }
  else {

    StackDelta delta = cd->get_stack_delta();
    // If our call descriptor returned no delta, upgrade the answer to a guess on account of
    // how guessing zero isn't all that horrible, and we want to reserve some space for other
    // kinds of failures.  In a proper bottom up configuration, this is probably where we
    // invoke the solver, or at least issue an error.
    if (delta.confidence == ConfidenceNone)
      delta.confidence = ConfidenceMissing;
    SDEBUG << "Call descriptor for address: " << addr_str(addr)
           << " returned stack delta: " << delta << LEND;
    return delta;
  }
}

void spTracker::dump_deltas(std::string filename) const {
  FILE *csv = fopen(filename.c_str(), "w");

  write_guard<decltype(mutex)> guard{mutex};

  for (const FunctionDescriptorMap::value_type& pair : descriptor_set.get_func_map()) {
    rose_addr_t faddr = pair.first;
    const FunctionDescriptor& fd = pair.second;
    for (SgAsmInstruction* insn : fd.get_insns_addr_order()) {
      rose_addr_t iaddr = insn->get_address();
      StackDelta current = get_delta(iaddr);
      fprintf(csv, "%08x,%08x,%d\n", (unsigned int)faddr, (unsigned int)iaddr, -current.delta);
    }
  }
  fclose(csv);
}

// There was a lot of very old code here, that's probably better replaced with a descriptive
// comment since the code wasn't actually compiled for a long time.  Much of the code was from
// a flawed approach where we tried to guess stack deltas based on how many pushes we found.
//
// My current understanding of the correct formulation of the constraint problem is:
//
// * Each vertex has two stack deltas (input_X and output_X).
//
// * The input stack delta for the entry point is the architecture size (for the return
//   address).
//
// * For each vertex there's a constraint that:
//   output_X = input_X + known_instruction_delta_X + unknown_call_delta_X
//
//   The known instruction delta is obtained from the semantics of the block.
//   The unknown call delta is zero if the block does not end in a call, a value loaded from
//   the API database if we known about the call, and a free variable otherwise.
//
// * For each out edge, the output stack delta on the predecessor vertex must equal the input
//   stack delta on the successor.
//
// * The output stack delta for each return instruction must equal zero (including the callee
//   cleaup amount on the RET instruction).
//
// * There may be a constraint that the starting and ending deltas are never negative (aka no
//   leaking into the neighboring stack frame).
//
// There should be a function to simply answer the question of whether there are any calls for
// which we don't know the call deltas.  If we know them all, just go straight to the usual
// "rigorous" analysis.  If we don't know one of the call deltas (or we tried the usual
// analysis and failed with a contradiction) then we should analyze each block independently to
// gather known instruction delta.  Ideally we'd use the standard ROSE stack delta analysis for
// this step.  Then we'd instantiate the solver, inject all the constraints, and solve for the
// unknown call deltas.
//
// We might need to solve repeatedly to minimize the unknown call deltas.
//
// There's also a Prolog solution to this problem in sdrules, but I supect that using Z3 is the
// better approach now.

// Some prototypes:
//
// size_t get_known_instruction_delta(block);
// size_t get_known_return_delta(block);
// void export_cfg_constraints();
// void export_vertex_constraints();
// void export_return_constraints();

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
