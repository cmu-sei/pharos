// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_RiscOps_H
#define Pharos_RiscOps_H

#include "semantics.hpp"
#include "state.hpp"

namespace pharos {

using SmtSolverPtr = Rose::BinaryAnalysis::SmtSolverPtr;

using SymRiscOperators = Semantics2::SymbolicSemantics::RiscOperators;
using SymRiscOperatorsPtr = Semantics2::SymbolicSemantics::RiscOperatorsPtr;

using Rose::BinaryAnalysis::InstructionSemantics::SymbolicSemantics::TRACK_ALL_DEFINERS;
using Rose::BinaryAnalysis::InstructionSemantics::SymbolicSemantics::TRACK_NO_DEFINERS;
using Rose::BinaryAnalysis::InstructionSemantics::SymbolicSemantics::TRACK_LATEST_DEFINER;

using Rose::BinaryAnalysis::InstructionSemantics::SymbolicSemantics::TRACK_ALL_WRITERS;
using Rose::BinaryAnalysis::InstructionSemantics::SymbolicSemantics::TRACK_NO_WRITERS;
using Rose::BinaryAnalysis::InstructionSemantics::SymbolicSemantics::TRACK_LATEST_WRITER;

//==============================================================================================
// Symbolic RISC Operators
//==============================================================================================

// Custom class required because we need to overide most operators for modifiers, and because
// we temporarily store reads and writes on a per instruction basis here.
class SymbolicRiscOperators: public SymRiscOperators {

 public:
  struct Callbacks {
    virtual ~Callbacks() = default;
    virtual void readMemory(SymbolicRiscOperators &, SymbolicValuePtr /* saddr */) {}
  };

 private:
  // Cache a handle to the EIP register descriptor so that we can easily remove reads and
  // writes of the instruction pointer.
  RegisterDescriptor EIP;

  // It's a read/write descriptor set because we update imports...  should we?
  DescriptorSet const & ds;

  Callbacks * callbacks = nullptr;

 public:
  // These maps are used to track the reads and writes of each instruction.  This is one of the
  // primary pieces of new functionality in this override of RiscOperators.  Perhaps we should
  // make these private as well.
  AbstractAccessVector insn_accesses;

  // This map represents memory accesses
  std::map<TreeNode*, TreeNodePtr> memory_accesses;

  // Map for every treenode we every find
  std::map<TreeNode*, TreeNodePtr> unique_treenodes;

 protected:

  // Constructors must remain private so that all instances are constructed through calls to
  // instance().

  // Standard ROSE constructor must take custom types to ensure promotion.
  explicit SymbolicRiscOperators(DescriptorSet const & ds_,
                                 const SymbolicValuePtr& protoval_,
                                 const SmtSolverPtr & solver_,
                                 Callbacks * callbacks_);

  // Standard ROSE constructor must take custom types to ensure promotion.
  explicit SymbolicRiscOperators(DescriptorSet const & ds_,
                                 const SymbolicStatePtr& state_,
                                 const SmtSolverPtr & solver_,
                                 Callbacks * callbacks_);

 public:

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicRiscOperatorsPtr instance(
    DescriptorSet const & ds_,
    const SymbolicValuePtr& protoval_,
    Callbacks * callbacks_ = nullptr,
    const SmtSolverPtr & solver_ = SmtSolverPtr())
  {
    SymbolicRiscOperatorsPtr ptr = SymbolicRiscOperatorsPtr(
      new SymbolicRiscOperators(ds_, protoval_, solver_, callbacks_));
    return ptr;
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicRiscOperatorsPtr instance(
    DescriptorSet const & ds_,
    const SymbolicStatePtr& state_,
    Callbacks * callbacks_ = nullptr,
    const SmtSolverPtr & solver_ = SmtSolverPtr())
  {
    SymbolicRiscOperatorsPtr ptr = SymbolicRiscOperatorsPtr(
      new SymbolicRiscOperators(ds_, state_, solver_, callbacks_));
    return ptr;
  }

  // Instance() methods must take custom types to ensure promotion.  Yet Robb seems to think
  // it's ok to pass a BaseStatePtr in the TestSemantics jig... I guess we'll promote, and
  // assert if we didn't get the right kind of state?  Long term we should really support other
  // arbitrary states.
  static SymbolicRiscOperatorsPtr instance(
    DescriptorSet const & ds_,
    const BaseStatePtr& state_,
    Callbacks * callbacks_ = nullptr,
    const SmtSolverPtr & solver_ = SmtSolverPtr())
  {
    SymbolicStatePtr sstate = SymbolicState::promote(state_);
    return instance(ds_, sstate, callbacks_, solver_);
  }

  // Default constructors are a CERT addition.
  static SymbolicRiscOperatorsPtr instance(
    DescriptorSet const & ds_,
    Callbacks * callbacks_ = nullptr,
    const SmtSolverPtr & solver_ = SmtSolverPtr());

  // Each custom class must implement promote.
  static SymbolicRiscOperatorsPtr promote(const BaseRiscOperatorsPtr &v) {
    SymbolicRiscOperatorsPtr retval = boost::dynamic_pointer_cast<SymbolicRiscOperators>(v);
    assert(retval!=NULL);
    return retval;
  }

  virtual BaseRiscOperatorsPtr create(const BaseSValuePtr &aprotoval_,
                                      const SmtSolverPtr &asolver_ = SmtSolverPtr())
    const override
  {
    STRACE << "RiscOps::create(protoval, solver)" << LEND;
    return instance(ds, SymbolicValue::promote(aprotoval_), callbacks, asolver_);
  }

  virtual BaseRiscOperatorsPtr create(const BaseStatePtr &state_,
                                      const SmtSolverPtr &asolver_= SmtSolverPtr())
    const override
  {
    STRACE << "RiscOps::create(state, solver)" << LEND;
    return instance(ds, SymbolicState::promote(state_), callbacks, asolver_);
  }

  // Overridden to clear our abstract access vectors.
  virtual void startInstruction(SgAsmInstruction *insn) override;

  virtual BaseSValuePtr readRegister(
    RegisterDescriptor reg, const BaseSValuePtr & dflt) override;
  virtual BaseSValuePtr readRegister(RegisterDescriptor reg) override {
    return readRegister(reg, undefined_(reg.get_nbits()));
  }

  virtual void writeRegister(RegisterDescriptor reg, const BaseSValuePtr &a) override;

  virtual BaseSValuePtr readMemory(RegisterDescriptor segreg, const BaseSValuePtr &addr,
                                   const BaseSValuePtr &dflt, const BaseSValuePtr &cond) override;

  virtual void writeMemory(RegisterDescriptor segreg, const BaseSValuePtr &addr,
                           const BaseSValuePtr &data, const BaseSValuePtr &cond) override;

  // -----------------------------------------------------------------------------------------
  // These are the primary RISC operator functions (all virtual overrides)
  // -----------------------------------------------------------------------------------------

  // Don't clear the state when we encounter an int3 instruction?
  virtual void interrupt(int majr, int minr) override;

  // The standard overridden operators...
  virtual BaseSValuePtr or_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;

  // The standard overridden operators that are NOT actually overridden...
  // This code was kept to make it easier to re-enable one of these if needded.
#if 0
  virtual BaseSValuePtr boolean_(bool b) override;
  virtual BaseSValuePtr number_(size_t nbits, uint64_t value) override;
  virtual BaseSValuePtr and_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;
  virtual BaseSValuePtr xor_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;
  virtual BaseSValuePtr invert(const BaseSValuePtr &a_) override;
  virtual BaseSValuePtr concat(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;
#endif
  virtual BaseSValuePtr extract(const BaseSValuePtr &a_, size_t begin_bit,
                                size_t end_bit) override;
#if 0
  virtual BaseSValuePtr leastSignificantSetBit(const BaseSValuePtr &a_) override;
  virtual BaseSValuePtr mostSignificantSetBit(const BaseSValuePtr &a_) override;
  virtual BaseSValuePtr rotateLeft(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) override;
  virtual BaseSValuePtr rotateRight(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) override;
  virtual BaseSValuePtr shiftLeft(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) override;
  virtual BaseSValuePtr shiftRight(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) override;
  virtual BaseSValuePtr shiftRightArithmetic(const BaseSValuePtr &a_,
                                             const BaseSValuePtr &sa_) override;
  virtual BaseSValuePtr equalToZero(const BaseSValuePtr &a_) override;
  virtual BaseSValuePtr ite(const BaseSValuePtr &sel_, const BaseSValuePtr &a_,
                            const BaseSValuePtr &b_) override;
  virtual BaseSValuePtr add(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;
  virtual BaseSValuePtr addWithCarries(const BaseSValuePtr &a_, const BaseSValuePtr &b_,
                                       const BaseSValuePtr &c_, BaseSValuePtr &carry_out) override;
  virtual BaseSValuePtr negate(const BaseSValuePtr &a_) override;
  virtual BaseSValuePtr signedDivide(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;
  virtual BaseSValuePtr signedModulo(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;
  virtual BaseSValuePtr signedMultiply(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;
  virtual BaseSValuePtr unsignedDivide(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;
  virtual BaseSValuePtr unsignedModulo(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;
  virtual BaseSValuePtr unsignedMultiply(const BaseSValuePtr &a_, const BaseSValuePtr &b_) override;
#endif

#if PHAROS_ROSE_NUMERIC_EXTENSION_HACK
  virtual BaseSValuePtr unsignedExtend(const BaseSValuePtr &a_, size_t new_width) override;
  virtual BaseSValuePtr signExtend(const BaseSValuePtr &a_, size_t new_width) override;
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

// Callback used for single threaded analysis passes
struct SingleThreadedAnalysisCallbacks : public SymbolicRiscOperators::Callbacks
{
  DescriptorSet & ds;

  SingleThreadedAnalysisCallbacks(DescriptorSet & ds_) : ds(ds_) {}

  void readMemory(SymbolicRiscOperators &, SymbolicValuePtr saddr) override;
};

// This class was renamed just for consistency with the overriden classes, even though it was
// not.  It is used for catching exceptions when emulating instructions, and is needed roughly
// whereever RISC operators and the instruction dispatcher are.
using SemanticsException = Rose::BinaryAnalysis::InstructionSemantics::BaseSemantics::Exception;

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
