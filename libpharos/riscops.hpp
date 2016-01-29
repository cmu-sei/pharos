// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_RiscOps_H
#define Pharos_RiscOps_H

#include "semantics.hpp"
#include "state.hpp"

typedef rose::BinaryAnalysis::SMTSolver SMTSolver;

typedef Semantics2::SymbolicSemantics::RiscOperators SymRiscOperators;
typedef Semantics2::SymbolicSemantics::RiscOperatorsPtr SymRiscOperatorsPtr;

typedef boost::shared_ptr<class CustomDispatcher> CustomDispatcherPtr;

using rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_ALL_DEFINERS;
using rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_NO_DEFINERS;
using rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_LATEST_DEFINER;

using rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_ALL_WRITERS;
using rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_NO_WRITERS;
using rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::TRACK_LATEST_WRITER;

//==============================================================================================
// Symbolic RISC Operators
//==============================================================================================

// Custom class required because we need to overide most operators for modifiers, and because
// we temporarily store reads and writes on a per instruction basis here.
class SymbolicRiscOperators: public SymRiscOperators {

protected:
  // Cache a handle to the EIP register descriptor so that we can easily remove reads and
  // writes of the instruction pointer.
  const RegisterDescriptor *EIP;

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicRiscOperators(const SymbolicValuePtr& protoval_, SMTSolver* solver_ = NULL):
    SymRiscOperators(protoval_, solver_) {
    set_name("CERT");
    computingDefiners(TRACK_LATEST_DEFINER);
    computingRegisterWriters(TRACK_LATEST_WRITER);
    computingMemoryWriters(TRACK_LATEST_WRITER);
    const RegisterDictionary* regdict = RegisterDictionary::dictionary_pentium4();
    EIP = regdict->lookup("eip");
  }

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicRiscOperators(const SymbolicStatePtr& state_, SMTSolver* solver_ = NULL):
    SymRiscOperators(state_, solver_) {
    set_name("CERT");
    computingDefiners(TRACK_LATEST_DEFINER);
    computingRegisterWriters(TRACK_LATEST_WRITER);
    computingMemoryWriters(TRACK_LATEST_WRITER);
    const RegisterDictionary* regdict = RegisterDictionary::dictionary_pentium4();
    EIP = regdict->lookup("eip");
  }

public:

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicRiscOperatorsPtr instance(const SymbolicValuePtr& protoval_,
                                           SMTSolver* solver_ = NULL) {
    SymbolicRiscOperatorsPtr ptr = SymbolicRiscOperatorsPtr(new SymbolicRiscOperators(protoval_, solver_));
    return ptr;
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicRiscOperatorsPtr instance(const SymbolicStatePtr& state_, SMTSolver* solver_ = NULL) {
    SymbolicRiscOperatorsPtr ptr = SymbolicRiscOperatorsPtr(new SymbolicRiscOperators(state_, solver_));
    return ptr;
  }

  // Instance() methods must take custom types to ensure promotion.  Yet Robb seems to think
  // it's ok to pass a BaseStatePtr in the TestSemantics jig... I guess we'll promote, and
  // assert if we didn't get the right kind of state?  Long term we should really support other
  // arbitrary states.
  static SymbolicRiscOperatorsPtr instance(const BaseStatePtr& state_, SMTSolver* solver_ = NULL) {
    SymbolicStatePtr sstate = SymbolicState::promote(state_);
    SymbolicRiscOperatorsPtr ptr = SymbolicRiscOperatorsPtr(new SymbolicRiscOperators(sstate, solver_));
    return ptr;
  }

  // Each custom class must implement promote.
  static SymbolicRiscOperatorsPtr promote(const BaseRiscOperatorsPtr &v) {
    SymbolicRiscOperatorsPtr retval = boost::dynamic_pointer_cast<SymbolicRiscOperators>(v);
    assert(retval!=NULL);
    return retval;
  }

  virtual BaseRiscOperatorsPtr create(const BaseSValuePtr &protoval_,
                                      SMTSolver *solver_ = NULL) const ROSE_OVERRIDE {
    STRACE << "RiscOps::create(protoval, solver)" << LEND;
    return instance(SymbolicValue::promote(protoval_), solver_);
  }

  virtual BaseRiscOperatorsPtr create(const BaseStatePtr &state_,
                                      SMTSolver *solver_= NULL) const ROSE_OVERRIDE {
    STRACE << "RiscOps::create(state, solver)" << LEND;
    return instance(SymbolicState::promote(state_), solver_);
  }

  virtual BaseSValuePtr get_protoval() const ROSE_OVERRIDE {
    STRACE << "RiscOps::get_protoval()" << LEND;
    return protoval;
  }

  // Overridden to force IP to correct value, and clear assorted vectors...
  // And this isn't even remotely in this class anymore.  It's in Disassembly!
  virtual void startInstruction(SgAsmInstruction *insn) ROSE_OVERRIDE;

  virtual BaseSValuePtr readRegister(const RegisterDescriptor &reg) ROSE_OVERRIDE;

  virtual void writeRegister(const RegisterDescriptor &reg, const BaseSValuePtr &a) ROSE_OVERRIDE;

  virtual BaseSValuePtr readMemory(const RegisterDescriptor &segreg, const BaseSValuePtr &addr,
                                   const BaseSValuePtr &dflt, const BaseSValuePtr &cond) ROSE_OVERRIDE;

  virtual void writeMemory(const RegisterDescriptor &segreg, const BaseSValuePtr &addr,
                           const BaseSValuePtr &data, const BaseSValuePtr &cond) ROSE_OVERRIDE;

  // -----------------------------------------------------------------------------------------
  // These are the primary RISC operator functions (all virtual overrides)
  // -----------------------------------------------------------------------------------------

  // Don't clear the state when we encounter an int3 instruction?
  virtual void interrupt(int majr, int minr) ROSE_OVERRIDE;

  // The standard overridden operators...
  virtual BaseSValuePtr or_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr concat(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;

  // The standard overridden operators that are NOT actually overriden...
  // This code was kept to make it easier to re-enable one of these if needded.
#if 1
  virtual BaseSValuePtr boolean_(bool b) ROSE_OVERRIDE;
  virtual BaseSValuePtr number_(size_t nbits, uint64_t value) ROSE_OVERRIDE;
  virtual BaseSValuePtr and_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr xor_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) ROSE_OVERRIDE;
  virtual BaseSValuePtr invert(const BaseSValuePtr &a_) ROSE_OVERRIDE;
  virtual BaseSValuePtr extract(const BaseSValuePtr &a_, size_t begin_bit,
                                size_t end_bit) ROSE_OVERRIDE;
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

  // These maps are used to track the reads and writes of each instruction.  This is one of the
  // primary pieces of new functionality in this override of RiscOperators.
  AbstractAccessVector reads;
  AbstractAccessVector writes;

  // Default constructors are a CERT addition, but we didn't implement one?
  // Is it standard in this case?

  // Parameterless instance() is an unsafe/not-useful CERT addition?
  static SymbolicRiscOperatorsPtr instance() {
    SymbolicRiscOperatorsPtr ptr = SymbolicRiscOperatorsPtr(new SymbolicRiscOperators());
    return ptr;
  }

  // ??? standard or custom?
  explicit SymbolicRiscOperators(SMTSolver* solver_ = NULL):
    SymRiscOperators(SymbolicState::instance(), solver_) {
    computingDefiners(TRACK_LATEST_DEFINER);
    computingRegisterWriters(TRACK_LATEST_WRITER);
    //computingMemoryWriters(TRACK_LATEST_WRITER);
    const RegisterDictionary* regdict = RegisterDictionary::dictionary_pentium4();
    EIP = regdict->lookup("eip");
  }

  // CERT addition so we don't have to promote return value.
  SymbolicStatePtr get_sstate() {
    STRACE << "RiscOps::get_sstate()" << LEND;
    return boost::dynamic_pointer_cast<SymbolicState>(state);
  }

  // ??? Worthless?
  BaseStatePtr get_state() {
    STRACE << "RiscOps::get_state()" << LEND;
    return boost::dynamic_pointer_cast<SymbolicState>(state);
  }

  // CERT addition for some reason?
  void set_sstate(const SymbolicStatePtr &s) {
    set_state(s);
  }

  // A COPY of readMemory from our parent class. :-(
  SymbolicValuePtr readMemory_helper(const RegisterDescriptor &segreg,
                                     const BaseSValuePtr &address,
                                     const BaseSValuePtr &dflt,
                                     const BaseSValuePtr &condition);

  // A COPY of writeMemory from our parent class. :-(
  void writeMemory_helper(const RegisterDescriptor &segreg,
                          const BaseSValuePtr &address,
                          const BaseSValuePtr &value_,
                          const BaseSValuePtr &condition);

  // This is Cory's interface, and it's probably half-baked.
  SymbolicValuePtr read_register(const RegisterDescriptor &reg);

  // CERT needs a rational interface read memory. :-)
  SymbolicValuePtr read_memory(const SymbolicMemoryState* state,
                               const SymbolicValuePtr& addr, const size_t nbits);

  // New API by Cory to initialize memory.
  void initialize_memory(const SymbolicValuePtr &addr,
                         const SymbolicValuePtr &data);
};

//==============================================================================================
// Custom instruction dispatcher
//==============================================================================================

// Custom class not really needed, but included for completeness?
class CustomDispatcher: public RoseDispatcherX86 {

  // -----------------------------------------------------------------------------------------
  // Required official interface
  // -----------------------------------------------------------------------------------------

protected:

  // Constructors must take custom types to ensure promotion.
  explicit CustomDispatcher(const SymbolicRiscOperatorsPtr &ops): RoseDispatcherX86(ops, 32, NULL) {
  }

public:

  // Instance() methods must take custom types to ensure promotion.
  static CustomDispatcherPtr instance(const SymbolicRiscOperatorsPtr &ops) {
    return CustomDispatcherPtr(new CustomDispatcher(ops));
  }

  // -----------------------------------------------------------------------------------------
  // Custom interface
  // -----------------------------------------------------------------------------------------

  // Default constructors are a CERT addition?
  CustomDispatcher(): RoseDispatcherX86(SymbolicRiscOperators::instance(), 32, NULL) { }

  // Parameterless instance() is an unsafe/not-useful CERT addition?
  static CustomDispatcherPtr instance() {
    return CustomDispatcherPtr(new CustomDispatcher());
  }

  // Typecast the RiscOperators to our customized version.
  SymbolicRiscOperatorsPtr get_operators() {
    return boost::dynamic_pointer_cast<SymbolicRiscOperators>(RoseDispatcherX86::get_operators());
  }
};

// This class was renamed just for consistency with the overriden classes, even though it was
// not.  It is used for catching exceptions when emulating instructions, and is needed roughly
// whereever RISC operators and the instruction dispatcher are.
typedef rose::BinaryAnalysis::InstructionSemantics2::BaseSemantics::Exception SemanticsException;

// Extern declaration of the global_rops object.  This object is used so that we don't have to
// carry arround a SymbolicRiscOperatorsPtr everywhere that we want to be able to read from or
// write to a state.
extern SymbolicRiscOperatorsPtr global_rops;

// A helper function to create a symbolic RiscOps emulation environment.  I'd still prefer that
// the default constructor on the SymbolicRiscOperators did this work.
SymbolicRiscOperatorsPtr make_risc_ops();

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
