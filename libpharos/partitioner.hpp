// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Partitioner_H
#define Pharos_Partitioner_H

#include "rose.hpp"
#include <Rose/BinaryAnalysis/Partitioner2/Engine.h>
#include <Rose/BinaryAnalysis/Partitioner2/Partitioner.h>
#include <Rose/BinaryAnalysis/Partitioner2/Modules.h>
#include <Rose/BinaryAnalysis/Partitioner2/ModulesX86.h>
#include <Rose/BinaryAnalysis/Partitioner2/Utility.h>

#include "limit.hpp"
#include "misc.hpp"

namespace pharos {

#define CODE_THRESHOLD 0.7

// This basic block call back refuses to make code out of too many zero bytes.  Technically,
// two zero bytes (four zero nybbles) decoded into the X86 instruction "add byte ds:[eax], al".
// This instruction occurs rarely enough that IDA refuses to create it _ever_.  We'll try a
// little harder, creating the instruction only in contexts that don't exceed some threshold.
class RefuseZeroCode: public P2::BasicBlockCallback {
 protected:
  size_t threshold = 3;
  RefuseZeroCode(size_t t = 3) {
    threshold = t;
  }
 public:
  using Ptr = Sawyer::SharedPointer<RefuseZeroCode>;

  static Ptr instance() {
    return Ptr(new RefuseZeroCode);
  }

  // The official interface that allows us to function as a basic block callback.
  bool operator()(bool chain, const Args &args) override;


  // Returns true if the code referenced meets the threshold for being bad code.  If the
  // address does NOT point to a "zero instruction" (or other invalid instructions) this
  // routine returns false, and must be called again for additional instructions.  If it does
  // match a zero instruction, it will contune to look at subsequent instructions to predict
  // whether the threshold will be met using normal fall through flow control.  If the address
  // points to one or more zero instructions, any instructions in the provided basic block will
  // also count against the threshold (for situations with large numbers of zero instructions
  // mixed in with other bad code).  This interface is intended for other users of the same
  // logic as the basic block call back interface (specifically gap analysis).
  bool check_zeros(const P2::Partitioner& partitioner,
                   rose_addr_t address, const P2::BasicBlock::Ptr& bblock);

};

class RefuseOverlappingCode: public P2::BasicBlockCallback {
 protected:
  bool refusing = true;
 public:
  using Ptr = Sawyer::SharedPointer<RefuseOverlappingCode>;

  static Ptr instance() {
    return Ptr(new RefuseOverlappingCode);
  }

  // The official interface that allows us to function as a basic block callback.
  bool operator()(bool chain, const Args &args) override;

  void set_refusing(bool r) { refusing = r; }
  bool get_refusing() { return refusing; }
};

// Returns true if and only if the instruction is a zero instruction (two bytes of zeros).
bool check_zero_insn(SgAsmInstruction* insn);

// Look for unconditional jumps to code that match a prologue pattern, and then make the jump a
// thunk, and the target a separate function.  This is required to work-around an issue where
// ROSE doesn't look at the target of the jump, resulting in inconsistent thunk-splitting
// behavior.  This might be corrected in a future version of ROSE, and if it is we should use
// the standard implementation.
class MatchJmpToPrologue: public P2::BasicBlockCallback {
 protected:
  // I wanted to use these, but they insist on inspecting bytes that have not been made into
  // instructions, and that's not what we wanted in this case.  Instead, we'll have to copy big
  // parts of the implementations. :-(
  //P2::ModulesX86::MatchStandardPrologue::Ptr std_matcher;
  //P2::ModulesX86::MatchStandardPrologue::Ptr hot_matcher;
  MatchJmpToPrologue() {
    //std_matcher = P2::ModulesX86::MatchStandardPrologue::instance();
    //assert(std_matcher);
    //hot_matcher = P2::ModulesX86::MatchHotPatchPrologue::instance();
    //assert(hot_matcher);
  }

  // Further we can't just request that the function be created while we're in the operator()
  // callback because the partitioner cam ein through the const args parameter. :-( That makes
  // it unclear whether the basic block callback was even the right architecture in the first
  // place, but the easiest fix at this point is to accumulate the addresses, and process them
  // later.
  std::set<rose_addr_t> prologues;

 public:
  using Ptr = Sawyer::SharedPointer<MatchJmpToPrologue>;

  static Ptr instance() {
    return Ptr(new MatchJmpToPrologue);
  }

  bool operator()(bool chain, const Args &args) override;
  void make_functions(P2::Partitioner& partitioner);
};

// A CFG adjustment callback that might be useful for debugging.
class Monitor: public P2::CfgAdjustmentCallback {
 private:
  ResourceLimit partitioner_limit;
 public:
  class ResourceException: public std::runtime_error {
    using std::runtime_error::runtime_error;
  };
  Monitor();
  static Ptr instance() { return Ptr(new Monitor); }
  virtual bool operator()(bool chain, const AttachedBasicBlock &args);
  virtual bool operator()(bool chain, const DetachedBasicBlock &args);
};


class MatchThunkPrologue: public P2::ModulesX86::MatchStandardPrologue {
 public:
  static Ptr instance() { return Ptr(new MatchThunkPrologue); }
  virtual std::vector<P2::Function::Ptr> functions() const override {
    return std::vector<P2::Function::Ptr>(1, function_);
  }
  virtual bool match(const P2::Partitioner &partitioner, rose_addr_t anchor) override;
};

class NamePredicate :
    public Sawyer::Container::SegmentPredicate<MemoryMap::Address, MemoryMap::Value>
{
  const std::string name;
 public:
  NamePredicate(std::string const & n) : name(n) {}

  bool operator()(bool, const Args & args) override {
    return args.segment.name() == name;
  }
};

class SupersetEngine: public P2::Engine {
 private:

 public:

  // We're going to override this so that it hardly uses the real partitioner at all...
  virtual void runPartitioner(P2::Partitioner& partitioner) override;
};

// We want our own engine because we want to override some steps. Specifically, we want to make
// sure our functions get defined after basic blocks are discovered but before they're assigned
// to functions.  Another way would be to run the base engine like normal, then throw away the
// BB-to-function assignments, then make our new functions, then recompute the BB-to-function
// assignments (this part isn't expensive).
class CERTEngine: public P2::Engine {
 private:

  MatchJmpToPrologue::Ptr jump_to_prologue_matcher;
  RefuseOverlappingCode::Ptr overlapping_code_detector;
  Rose::BinaryAnalysis::AddressSet not_pad_gaps;
  Rose::BinaryAnalysis::AddressSet not_thunk_gaps;
  Rose::BinaryAnalysis::AddressSet not_code_gaps;

  // A helper for consume thunks.
  bool try_making_thunk(P2::Partitioner& partitioner, rose_addr_t address);

  // Something a bit prettier to read a byte from the program image.
  uint8_t read_byte(rose_addr_t addr);

  // Create a padding data block if the appropriate bytes are found.
  P2::DataBlock::Ptr try_making_padding_block(
    P2::Partitioner& partitioner, rose_addr_t addr, bool backwards = false);

  bool bad_code(const P2::Partitioner& partitioner, const P2::BasicBlock::Ptr bb) const;
  bool consume_thunks(P2::Partitioner& partitioner, bool top, bool bottom);
  bool consume_padding(P2::Partitioner& partitioner, bool top, bool bottom);
  bool create_arbitrary_code(P2::Partitioner& partitioner);

 public:

  // Add our extensions to the partitioner.
  virtual P2::Partitioner createTunedPartitioner() override;

  // These are the methods that primarily alter the behavior of the partitioner.
  virtual void runPartitioner(P2::Partitioner &partitioner) override;
  virtual void runPartitionerRecursive(P2::Partitioner& partitioner) override;
};

// This is primary mechanism by which the partitioning occurs.  It's called from the global
// descriptor set, and needs some additional cleanup longer term.
P2::Partitioner create_partitioner(const ProgOptVarMap& vm, P2::Engine *engine,
                                   std::vector<std::string> const & specimen_names);


void report_partitioner_statistics(const P2::Partitioner& partitioner);

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
