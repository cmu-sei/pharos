// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_SPTrack_Header
#define Pharos_SPTrack_Header

#include <mutex>
#include "descriptors.hpp"
#include "delta.hpp"

namespace pharos {

class spTracker {

 protected:
  // This is our map of address to stack delta (and confidence) for each instruction.  This is
  // the stack delta before the instruction is executed.  See the declaration of StackDelta in
  // delta.hpp for more details.
  std::map<rose_addr_t, StackDelta> deltas;

  // Keep a handle to our descriptor set so that it doesn't have to be global.  Maybe we can
  // eliminate this entirely with a little more effort.
  DescriptorSet const & descriptor_set;

  // Multi-threaded protection
  mutable std_mutex mutex;

 public:

  // Construct a stack delta oracle.
  spTracker(DescriptorSet const & ds) : descriptor_set(ds) {}

  // Update stack deltas during analysis.
  void update_delta(rose_addr_t addr, StackDelta const & sd, size_t & failures);

  // Retrieve stack per instruction stack deltas.
  const StackDelta get_delta(rose_addr_t addr) const;
  // Retrieve the call delta for a call instruction, which might increment recent failures.
  const StackDelta get_call_delta(rose_addr_t addr, size_t & failures);

  // Old and for debugging, but not worthless.
  void dump_deltas(std::string filename) const;

};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
