// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Partitioner_H
#define Pharos_Partitioner_H

#include <rose.h>
#include <Partitioner2/Engine.h>
#include <Partitioner2/Partitioner.h>
#include <Partitioner2/Modules.h>
#include <Partitioner2/Utility.h>

#include "limit.hpp"

typedef rose::BinaryAnalysis::Disassembler RoseDisassembler;

#define CODE_THRESHOLD 0.7

// A custom partitioner extended by Wes.
class CERTPartitioner: public rose::BinaryAnalysis::Partitioner {

  ResourceLimit partitioner_limit;

  // Look for the save-restore pattern (push-pop-ret) in range of unassigned instructions.
  bool find_save_restore_pattern(Partitioner::InstructionMap range);

public:

  CERTPartitioner();

  // Return basic block reason code as a printable string.  For debugging.  Added by Wes and
  // heavily modified by Cory.
  std::string reason_string(unsigned r);

#if 1
  // Override parent just to add logging
  void append(BasicBlock *bb, DataBlock *db, unsigned reason);

  // Override parent just to add logging
  void append(Function *func, DataBlock *block, unsigned reason, bool force);

  // This one's really overriden with something...
  void append(Function* f, BasicBlock *bb, unsigned reason, bool keep/*=false*/);
#endif

  // Look for the save-restore pattern and create functions in all unassigned ranges?
  // Wes says: Copied from scan_unassigned_insn().  He thinks there might be a bug in
  // scan_unassigned_insns(), because it's not calling scan_interfunc_insns(), like the comment
  // claims...
  size_t add_save_restore_funcs();

  // Iterate through the list of basic blocks that have not been assigned to functions in
  // address order.  Determine if the successors of a block can reach any of the other
  // unassigned blocks.  If it can, mark the first block as a function start and reanalyze the
  // CFG.  Repeat this process until the list of unassigned data blocks stops changing.
  void findFuncsInDataBlocks();

  // This is where where we hook in to call add_save_restore_functions() and
  // findFuncsInDataBblocks().  Cory is interested in finding an earlier place to hook as well.
  void post_cfg(SgAsmInterpretation *interp);

  // Unknown?
  RoseDisassembler::AddressSet successors(BasicBlock *bb, bool *complete);

};

namespace P2 = rose::BinaryAnalysis::Partitioner2;

// Looks for JMP instructions at the beginning of a basic block and prevents the basic block
// from having any additional instructions.  Saves the addresses of the JMP and their targets.
class ThunkDetacher: public P2::BasicBlockCallback {
protected:
  ThunkDetacher() {}
public:
  typedef Sawyer::SharedPointer<ThunkDetacher> Ptr;

  std::set<rose_addr_t> jmpVas, targetVas;

  static Ptr instance() {
    return Ptr(new ThunkDetacher);
  }

  bool operator()(bool chain, const Args &args) ROSE_OVERRIDE;
  void makeFunctions(P2::Partitioner &partitioner);
};

// A CFG adjustment callback that might be useful for debugging.
class Monitor: public P2::CfgAdjustmentCallback {
public:
  static Ptr instance() { return Ptr(new Monitor); }
  virtual bool operator()(bool chain, const AttachedBasicBlock &args);
  virtual bool operator()(bool chain, const DetachedBasicBlock &args);
};

// We want our own engine because we want to override some steps. Specifically, we want to make
// sure our functions get defined after basic blocks are discovered but before they're assigned
// to functions.  Another way would be to run the base engine like normal, then throw away the
// BB-to-function assignments, then make our new functions, then recompute the BB-to-function
// assignments (this part isn't expensive).
class CERTEngine: public P2::Engine {
    ThunkDetacher::Ptr thunkDetacher_;
public:

    // Augment the method that creates a partitioner so our thunk detacher gets attached to all
    // partitioners created by the engine.  This won't take care of the case when the user
    // creates their own partitioner.
    virtual P2::Partitioner createBarePartitioner() ROSE_OVERRIDE {
        P2::Partitioner partitioner = P2::Engine::createBarePartitioner();
        thunkDetacher_ = ThunkDetacher::instance();
        partitioner.basicBlockCallbacks().append(thunkDetacher_);
        return partitioner;
    }

    // Augment the engine functon that attaches basic blocks to functions so we have a chance
    // to create functions that we detected as thunks.
    virtual void
    attachBlocksToFunctions(P2::Partitioner &partitioner) ROSE_OVERRIDE {
        if (thunkDetacher_)
            thunkDetacher_->makeFunctions(partitioner);
        P2::Engine::attachBlocksToFunctions(partitioner);
    }
};


#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
