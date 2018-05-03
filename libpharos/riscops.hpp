// Copyright 2015-2018 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_RiscOps_H
#define Pharos_RiscOps_H

#include "semantics.hpp"
#include "state.hpp"

namespace pharos {

typedef Rose::BinaryAnalysis::SmtSolverPtr SmtSolverPtr;

typedef Semantics2::SymbolicSemantics::RiscOperators SymRiscOperators;
typedef Semantics2::SymbolicSemantics::RiscOperatorsPtr SymRiscOperatorsPtr;

using Rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_ALL_DEFINERS;
using Rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_NO_DEFINERS;
using Rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_LATEST_DEFINER;

using Rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_ALL_WRITERS;
using Rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_NO_WRITERS;
using Rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_LATEST_WRITER;

//==============================================================================================
// Symbolic RISC Operators
//==============================================================================================

// Custom class required because we need to overide most operators for modifiers, and because
// we temporarily store reads and writes on a per instruction basis here.
class SymbolicRiscOperators: public SymRiscOperators {

private:
  // Cache a handle to the EIP register descriptor so that we can easily remove reads and
  // writes of the instruction pointer.
  RegisterDescriptor EIP;

public:
  // These maps are used to track the reads and writes of each instruction.  This is one of the
  // primary pieces of new functionality in this override of RiscOperators.  Perhaps we should
  // make these private as well.
  AbstractAccessVector reads;
  AbstractAccessVector writes;

  // This map represents memory accesses
  std::map<TreeNode*, TreeNodePtr> memory_accesses;

  // Map for every treenode we every find
  std::map<TreeNode*, TreeNodePtr> unique_treenodes;

protected:
  // Constructors must remain private so that all instances are constructed through calls to
  // instance().

  // Standard ROSE constructor must take custom types to ensure promotion.
  explicit SymbolicRiscOperators(const SymbolicValuePtr& aprotoval_,
                                 const SmtSolverPtr & asolver);

  // Standard ROSE constructor must take custom types to ensure promotion.
  explicit SymbolicRiscOperators(const SymbolicStatePtr& state_,
                                 const SmtSolverPtr & asolver);

public:

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicRiscOperatorsPtr instance(const SymbolicValuePtr& protoval_,
                                           const SmtSolverPtr & solver_ = SmtSolverPtr())
  {
    SymbolicRiscOperatorsPtr ptr = SymbolicRiscOperatorsPtr(
      new SymbolicRiscOperators(protoval_, solver_));
    return ptr;
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicRiscOperatorsPtr instance(const SymbolicStatePtr& state_,
                                           const SmtSolverPtr & solver_ = SmtSolverPtr())
  {
    SymbolicRiscOperatorsPtr ptr = SymbolicRiscOperatorsPtr(
      new SymbolicRiscOperators(state_, solver_));
    return ptr;
  }

  // Instance() methods must take custom types to ensure promotion.  Yet Robb seems to think
  // it's ok to pass a BaseStatePtr in the TestSemantics jig... I guess we'll promote, and
  // assert if we didn't get the right kind of state?  Long term we should really support other
  // arbitrary states.
  static SymbolicRiscOperatorsPtr instance(const BaseStatePtr& state_,
                                           const SmtSolverPtr & solver_ = SmtSolverPtr())
  {
    SymbolicStatePtr sstate = SymbolicState::promote(state_);
    SymbolicRiscOperatorsPtr ptr = SymbolicRiscOperatorsPtr(new SymbolicRiscOperators(sstate, solver_));
    return ptr;
  }

  // Default constructors are a CERT addition.
  static SymbolicRiscOperatorsPtr instance(const SmtSolverPtr & solver_ = SmtSolverPtr()) {
    SymbolicMemoryMapStatePtr mstate = SymbolicMemoryMapState::instance();
    SymbolicRegisterStatePtr rstate = SymbolicRegisterState::instance();
    SymbolicStatePtr state = SymbolicState::instance(rstate, mstate);
    SymbolicRiscOperatorsPtr ptr = SymbolicRiscOperatorsPtr(new SymbolicRiscOperators(state, solver_));
    return ptr;
  }

  // Each custom class must implement promote.
  static SymbolicRiscOperatorsPtr promote(const BaseRiscOperatorsPtr &v) {
    SymbolicRiscOperatorsPtr retval = boost::dynamic_pointer_cast<SymbolicRiscOperators>(v);
    assert(retval!=NULL);
    return retval;
  }

  virtual BaseRiscOperatorsPtr create(const BaseSValuePtr &aprotoval_,
                                      const SmtSolverPtr &asolver_ = SmtSolverPtr())
    const ROSE_OVERRIDE
  {
    STRACE << "RiscOps::create(protoval, solver)" << LEND;
    return instance(SymbolicValue::promote(aprotoval_), asolver_);
  }

  virtual BaseRiscOperatorsPtr create(const BaseStatePtr &state_,
                                      const SmtSolverPtr &asolver_= SmtSolverPtr())
    const ROSE_OVERRIDE
  {
    STRACE << "RiscOps::create(state, solver)" << LEND;
    return instance(SymbolicState::promote(state_), asolver_);
  }

  // Overridden to clear our abstract access vectors.
  virtual void startInstruction(SgAsmInstruction *insn) ROSE_OVERRIDE;

  virtual BaseSValuePtr readRegister(RegisterDescriptor reg) ROSE_OVERRIDE;

  virtual void writeRegister(RegisterDescriptor reg, const BaseSValuePtr &a) ROSE_OVERRIDE;

  virtual BaseSValuePtr readMemory(RegisterDescriptor segreg, const BaseSValuePtr &addr,
                                   const BaseSValuePtr &dflt, const BaseSValuePtr &cond) ROSE_OVERRIDE;

  virtual void writeMemory(RegisterDescriptor segreg, const BaseSValuePtr &addr,
                           const BaseSValuePtr &data, const BaseSValuePtr &cond) ROSE_OVERRIDE;

  // -----------------------------------------------------------------------------------------
  // These are the primary RISC operator functions (all virtual overrides)
  // -----------------------------------------------------------------------------------------

  // Don't clear the state when we encounter an int3 instruction?
  virtual void interrupt(int majr, int minr) ROSE_OVERRIDE;

  // The standard overridden operators...
  virtual BaseSValuePtr or_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;

  // The standard overridden operators that are NOT actually overriden...
  // This code was kept to make it easier to re-enable one of these if needded.
#if 0
  virtual BaseSValuePtr boolean_(bool b) ROSE_OVERRIDE;
  virtual BaseSValuePtr number_(size_t nbits, uint64_t value) ROSE_OVERRIDE;
  virtual BaseSValuePtr and_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr xor_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr invert(const BaseSValuePtr &a_) ROSE_OVERRIDE;
  virtual BaseSValuePtr concat(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
#endif
  virtual BaseSValuePtr extract(const BaseSValuePtr &a_, size_t begin_bit,
                                size_t end_bit) ROSE_OVERRIDE;
#if 0
  virtual BaseSValuePtr leastSignificantSetBit(const BaseSValuePtr &a_) ROSE_OVERRIDE;
  virtual BaseSValuePtr mostSignificantSetBit(const BaseSValuePtr &a_) ROSE_OVERRIDE;
  virtual BaseSValuePtr rotateLeft(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) ROSE_OVERRIDE;
  virtual BaseSValuePtr rotateRight(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) ROSE_OVERRIDE;
  virtual BaseSValuePtr shiftLeft(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) ROSE_OVERRIDE;
  virtual BaseSValuePtr shiftRight(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) ROSE_OVERRIDE;
  virtual BaseSValuePtr shiftRightArithmetic(const BaseSValuePtr &a_,
                                             const BaseSValuePtr &sa_) ROSE_OVERRIDE;
  virtual BaseSValuePtr equalToZero(const BaseSValuePtr &a_) ROSE_OVERRIDE;
  virtual BaseSValuePtr ite(const BaseSValuePtr &sel_, const BaseSValuePtr &a_,
                            const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr unsignedExtend(const BaseSValuePtr &a_, size_t new_width) ROSE_OVERRIDE;
  virtual BaseSValuePtr signExtend(const BaseSValuePtr &a_, size_t new_width) ROSE_OVERRIDE;
  virtual BaseSValuePtr add(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr addWithCarries(const BaseSValuePtr &a_, const BaseSValuePtr &b_,
                                       const BaseSValuePtr &c_, BaseSValuePtr &carry_out) ROSE_OVERRIDE;
  virtual BaseSValuePtr negate(const BaseSValuePtr &a_) ROSE_OVERRIDE;
  virtual BaseSValuePtr signedDivide(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr signedModulo(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr signedMultiply(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr unsignedDivide(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr unsignedModulo(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr unsignedMultiply(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
#endif

  // -----------------------------------------------------------------------------------------
  // Custom interface
  // -----------------------------------------------------------------------------------------

  // CERT addition so we don't have to promote return value.
  SymbolicStatePtr get_sstate() {
    STRACE << "RiscOps::get_sstate()" << LEND;
    return boost::dynamic_pointer_cast<SymbolicState>(currentState());
  }

  // This is Cory's interface, and it's probably half-baked.
  SymbolicValuePtr read_register(RegisterDescriptor reg);

  // CERT needs a rational interface read memory. :-)
  SymbolicValuePtr read_memory(const SymbolicMemoryMapState* state,
                               const SymbolicValuePtr& addr, const size_t nbits);

  // New API by Cory to initialize memory.
  void initialize_memory(const SymbolicValuePtr &addr,
                         const SymbolicValuePtr &data);
};

// This class was renamed just for consistency with the overriden classes, even though it was
// not.  It is used for catching exceptions when emulating instructions, and is needed roughly
// whereever RISC operators and the instruction dispatcher are.
typedef Rose::BinaryAnalysis::InstructionSemantics2::BaseSemantics::Exception SemanticsException;

// Extern declaration of the global_rops object.  This object is used so that we don't have to
// carry arround a SymbolicRiscOperatorsPtr everywhere that we want to be able to read from or
// write to a state.
extern SymbolicRiscOperatorsPtr global_rops;

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
