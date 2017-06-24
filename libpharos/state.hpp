// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_State_H
#define Pharos_State_H

#include "semantics.hpp"
#include "misc.hpp"

namespace pharos {

// Renames of standard ROSE typdefs.
typedef Semantics2::BaseSemantics::RegisterState BaseRegisterState;
typedef Semantics2::BaseSemantics::RegisterStatePtr BaseRegisterStatePtr;
typedef Semantics2::BaseSemantics::State BaseState;
typedef Semantics2::BaseSemantics::StatePtr BaseStatePtr;
typedef Semantics2::BaseSemantics::MemoryCell MemoryCell;
typedef Semantics2::BaseSemantics::MemoryCellPtr MemoryCellPtr;
typedef Semantics2::BaseSemantics::RiscOperators BaseRiscOperators;
typedef Semantics2::BaseSemantics::RiscOperatorsPtr BaseRiscOperatorsPtr;
typedef Semantics2::BaseSemantics::MemoryState BaseMemoryState;
typedef Semantics2::BaseSemantics::MemoryStatePtr BaseMemoryStatePtr;
typedef Semantics2::BaseSemantics::MemoryCellMap BaseMemoryCellMap;
typedef Semantics2::BaseSemantics::MemoryCellMapPtr BaseMemoryCellMapPtr;
typedef Semantics2::BaseSemantics::SValue BaseSValue;
typedef Semantics2::SymbolicSemantics::MemoryState::CellCompressor CellCompressor;
typedef Semantics2::SymbolicSemantics::MemoryState::CellCompressorChoice CellCompressorChoice;
typedef Semantics2::BaseSemantics::MemoryCellList::CellList CellList;
typedef Semantics2::BaseSemantics::RegisterStateGeneric RegisterStateGeneric;
typedef Semantics2::BaseSemantics::RegisterStateGenericPtr RegisterStateGenericPtr;

// Forward declarations of the smart pointer types.
typedef boost::shared_ptr<class SymbolicRiscOperators> SymbolicRiscOperatorsPtr;
typedef boost::shared_ptr<class SymbolicRegisterState> SymbolicRegisterStatePtr;
typedef boost::shared_ptr<class SymbolicMemoryState> SymbolicMemoryStatePtr;
typedef boost::shared_ptr<class SymbolicState> SymbolicStatePtr;

extern SymbolicRiscOperatorsPtr global_rops;

//==============================================================================================
// SymbolicRegisterState
//==============================================================================================

// Shared-ownership pointer to merge control object.
typedef Sawyer::SharedPointer<class CERTMerger> CERTMergerPtr;

// Controls merging of symbolic values.  Specifically permit passing of the condition
// expression from the state merge() to the symbolic value merge().
class CERTMerger: public Semantics2::SymbolicSemantics::Merger {
protected:
  CERTMerger(): Semantics2::SymbolicSemantics::Merger() {
    condition = SymbolicValue::incomplete(1);
  }

public:
  // The condition that determined whether this or other is the current value.
  SymbolicValuePtr condition;

  // Shared-ownership pointer to merge control object.
  typedef CERTMergerPtr Ptr;

  // Allocating constructor.
  static Ptr instance() {
    return Ptr(new CERTMerger);
  }
};

// Custom class required to implement equals().  At least for a while longer.
class SymbolicRegisterState: public RegisterStateGeneric {

protected:
  // Constructors are protected to ensure that instance() methods are used instead.

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicRegisterState(const SymbolicValuePtr &proto, const RegisterDictionary *rd):
    RegisterStateGeneric(proto, rd) {
    // moving the global_rops creation to pharos_main caused this message to always come out:
    //STRACE << "SymbolicRegisterState::SymbolicRegisterState(proto, rd)" << LEND;
    merger(CERTMerger::instance());

    // We still require pre-initialization of the registers in our system.   I'm not sure why.
    Semantics2::DispatcherX86Ptr dispatcher = RoseDispatcherX86::instance();
    dispatcher->set_register_dictionary(regdict);
#ifdef DF_FLAG_ONLY
    // For a while I mistakenly thought that the problem was specific to the direction flag
    // register.  That was reinforced by a bad workaround that initialized all registers rather
    // than just the one direction flag register.  Here's what should have worked if the
    // problem was really just the DF register (but it doesn't):

    //std::vector<RegisterDescriptor> regs;
    //regs.push_back(*(regdict->lookup("df")));
    //initialize_nonoverlapping(regs, false);
#else
    initialize_nonoverlapping(dispatcher->get_usual_registers(), false);
#endif
  }

  // Copy constructor should ensure a deep copy.
  // In general this doesn't happen at correct level if we don't implement it, but in this
  // case, we don't have any additional work an do calling the parent method is sufficient.
  explicit SymbolicRegisterState(const SymbolicRegisterState& other):
    RegisterStateGeneric(other) {
    STRACE << "SymbolicRegisterState::SymbolicRegisterState(other)" << LEND;
  }

public:

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicRegisterStatePtr instance(const SymbolicValuePtr &proto,
                                           const RegisterDictionary *rd) {
    STRACE << "SymbolicRegisterState::instance(SymbolicValuePtr, RegisterDictionary)" << LEND;
    return SymbolicRegisterStatePtr(new SymbolicRegisterState(proto, rd));
  }

  // Instance() methods must take custom types to ensure promotion. Yet Robb seems to think
  // it's ok to pass a BaseSValue in the TestSemantics jig... I guess we'll promote, and assert
  // if we didn't get the right kind of protoype value?  Long term we should really support
  // other arbitrary values.
  static SymbolicRegisterStatePtr instance(const BaseSValuePtr &proto,
                                           const RegisterDictionary *rd) {
    STRACE << "SymbolicRegisterState::instance(BaseSValuePtr, RegisterDictionary)" << LEND;
    SymbolicValuePtr sproto = SymbolicValue::promote(proto);
    return SymbolicRegisterStatePtr(new SymbolicRegisterState(sproto, rd));
  }

  // Default constructors are a CERT addition.
  static SymbolicRegisterStatePtr instance();

  // Each custom class must implement promote.
  static SymbolicRegisterStatePtr promote(const BaseRegisterStatePtr &v) {
    SymbolicRegisterStatePtr retval = boost::dynamic_pointer_cast<SymbolicRegisterState>(v);
    assert(retval!=NULL);
    return retval;
  }

  virtual BaseRegisterStatePtr create(const BaseSValuePtr &proto,
                                      const RegisterDictionary *rd) const ROSE_OVERRIDE {
    STRACE << "SymbolicRegisterState::create()" << LEND;
    return instance(SymbolicValue::promote(proto), rd);
  }

  virtual BaseRegisterStatePtr clone() const ROSE_OVERRIDE {
    STRACE << "SymbolicRegisterState::clone()" << LEND;
    return SymbolicRegisterStatePtr(new SymbolicRegisterState(*this));
  }

  // -----------------------------------------------------------------------------------------
  // Custom interface
  // -----------------------------------------------------------------------------------------

  // CERT addition so we don't have to promote return value.
  SymbolicRegisterStatePtr sclone() {
    STRACE << "SymbolicRegisterState::sclone()" << LEND;
    return SymbolicRegisterStatePtr(new SymbolicRegisterState(*this));
  }

  // This is the current state comparison, but it needs cleanup.
  bool equals(const SymbolicRegisterStatePtr& other);

  // Compare this state with another, and return a list of the changed registers.
  RegisterSet diff(const SymbolicRegisterStatePtr& other);

  // Custom version of the readRegister API that does not require a RiscOperators pointer.  It
  // simply uses a global variable to fill in the missing parameter.  This must be a global
  // variable because storing the smart pointer in the register state causes pointer reference
  // cycles that confuses the reference counter of the smart pointer and causes memory leaks.
  // A better solution should probably be identified.  This method does NOT alter the "create
  // on access" behaviors of the the standard readRegister() method.
  SymbolicValuePtr read_register(const RegisterDescriptor& rd) {
    BaseRiscOperators* ops = (BaseRiscOperators*)global_rops.get();
    return SymbolicValue::promote(RegisterStateGeneric::readRegister(
                                    rd, ops->undefined_(rd.get_nbits()), ops));
  }

  SymbolicValuePtr inspect_register(const RegisterDescriptor& rd);

  void type_recovery_test() const;

};

//==============================================================================================
// Symbolic Memory State
//==============================================================================================
class SymbolicMemoryState: public BaseMemoryCellMap {

protected:
  // Constructors are protected to ensure that instance() methods are used instead.

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicMemoryState(const MemoryCellPtr &protocell_)
    : BaseMemoryCellMap(protocell_->get_address(), protocell_->get_value()) {
    merger(CERTMerger::instance());
  }

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicMemoryState(const SymbolicValuePtr &addr, const SymbolicValuePtr &val)
    : BaseMemoryCellMap(addr, val) {
    merger(CERTMerger::instance());
  }

  // Copy constructor should ensure a deep copy.
  explicit SymbolicMemoryState(const SymbolicMemoryState & other)
    : BaseMemoryCellMap(other) {
    // Our merger is copied by default?
  }

public:

  // Promote to our type.
  static SymbolicMemoryStatePtr promote(const BaseMemoryStatePtr &x) {
    SymbolicMemoryStatePtr retval = boost::dynamic_pointer_cast<SymbolicMemoryState>(x);
    ASSERT_not_null(retval);
    return retval;
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicMemoryStatePtr instance(const SymbolicValuePtr &addr,
                                         const SymbolicValuePtr &val) {
    return SymbolicMemoryStatePtr(new SymbolicMemoryState(addr, val));
  }

  // Instance() methods must take custom types to ensure promotion.
  // But Robb calls the instance() method with BaseSValues in tracsem.cpp.
  static SymbolicMemoryStatePtr instance(const BaseSValuePtr &addr,
                                         const BaseSValuePtr &val) {
    SymbolicValuePtr saddr = SymbolicValue::promote(addr);
    SymbolicValuePtr sval = SymbolicValue::promote(val);
    return SymbolicMemoryStatePtr(new SymbolicMemoryState(saddr, sval));
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicMemoryStatePtr instance(const MemoryCellPtr &protocell) {
    return SymbolicMemoryStatePtr(new SymbolicMemoryState(protocell));
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicMemoryStatePtr instance(const SymbolicMemoryStatePtr &other) {
    return SymbolicMemoryStatePtr(new SymbolicMemoryState(*other));
  }

  // Default constructors are a CERT addition.
  static SymbolicMemoryStatePtr instance() {
    SymbolicValuePtr svalue = SymbolicValue::instance();
    return SymbolicMemoryStatePtr(new SymbolicMemoryState(svalue, svalue));
  }

  virtual BaseMemoryStatePtr create(const BaseSValuePtr &addr,
                                    const BaseSValuePtr &val) const ROSE_OVERRIDE {
    STRACE << "SymbolicMemoryCellMap::create(addr, val)" << LEND;
    SymbolicValuePtr addr_ = SymbolicValue::promote(addr);
    SymbolicValuePtr val_ = SymbolicValue::promote(val);
    return instance(addr_, val_);
  }

  virtual CellKey generateCellKey(const BaseSValuePtr &address) const ROSE_OVERRIDE {
    SymbolicValuePtr saddr = SymbolicValue::promote(address);
    return saddr->get_hash();
  }

  virtual BaseMemoryStatePtr clone() const ROSE_OVERRIDE {
    STRACE << "SymbolicMemoryState::clone()" << LEND;
    return BaseMemoryStatePtr(new SymbolicMemoryState(*this));
  }

  SymbolicMemoryStatePtr sclone() {
    STRACE << "SymbolicMemoryState::sclone()" << LEND;
    return SymbolicMemoryStatePtr(new SymbolicMemoryState(*this));
  }

  virtual bool merge(const BaseMemoryStatePtr& other_,
                     BaseRiscOperators* addrOps,
                     BaseRiscOperators* valOps) ROSE_OVERRIDE;

  // CERT needs a rational interface read memory. :-)
  SymbolicValuePtr read_memory(const SymbolicValuePtr& address, const size_t nbits) const;

  // CERT addition of new functionality.
  bool equals(const SymbolicMemoryStatePtr& other);

  // Testing type recovery code.
  void type_recovery_test() const;

};

class DUAnalysis;

//==============================================================================================
// CellMapChunks
//==============================================================================================

// A container of contiguous chunks of modified memory state
//
// This container can be iterated over using the begin() and end() iterators.  Each iterator
// dereferences to a Chunk, which is in turn a container of TreeNode reference representing
// the values in memory.
//
// E.g.:
//
// CellMapChunks chunks(usedef);
// for (const CellMapChunks::Chunk & chunk : chunks) {
//   // Iterator over the chunk's memory
//   for (TreeNodePtr & value : chunk) {
//     // Do something with each memory value
//   }
// }
//
class CellMapChunks {
 public:
  // Forward declarations
  class Chunk;
  class chunk_iterator;

  // Container typedefs
  typedef chunk_iterator iterator;
  typedef chunk_iterator const_iterator;
  typedef const Chunk    value_type;

  // Constructor
  CellMapChunks(const DUAnalysis & usedef, bool df_flag = false);

  // Chunk iterator begin
  iterator begin() const {
    return iterator(section_map.begin(), section_map.end());
  }

  // Chunk iterator end
  iterator end() const {
    return iterator(section_map.end(), section_map.end());
  }

 private:

  // A map of offsets to memory contents
  typedef std::map<int64_t, TreeNodePtr> offset_map_t;
  // A map of TreeNodes (minus additive constants) to offset maps
  typedef std::map<TreeNodePtr, offset_map_t, TreeNodePtrCompare> section_map_t;

  // Iterator typedefs
  typedef offset_map_t::const_iterator offset_iter_t;
  typedef section_map_t::const_iterator section_iter_t;

  // The map containing all the chunked data
  section_map_t section_map;

  // An iterator over the values of an offset_map_t
  class cell_iterator : public boost::iterator_adaptor<
    cell_iterator, offset_map_t::const_iterator, const TreeNodePtr>
  {
   public:
    cell_iterator() {}

    cell_iterator(const offset_iter_t &iter)
      : cell_iterator::iterator_adaptor(iter)
    {}

    // Return the offset asssociated with the value
    const offset_map_t::key_type &offset() const {
      return this->base()->first;
    }

    const TreeNodePtr &dereference() const {
      return this->base()->second;
    }
  };

 public:

  // A Chunk represents a set of contiguous set memory locations.  The locations can be
  // iterated over by begin() and end().  The symbolic base of the locations can be retrieved
  // using symbol().  The iterators returned can be dereferenced to TreeNodes, and their offset()
  // method returns the offset.
  class Chunk {
   public:
    typedef const TreeNodePtr value_type;
    typedef value_type &      reference_type;
    typedef cell_iterator     iterator;
    typedef iterator          const_iterator;
    iterator begin() const { return b; }
    iterator end() const {return e; }
    const TreeNodePtr & symbol() const { return symbolic; }
   private:
    friend class CellMapChunks::chunk_iterator;
    void clear() {
      b = cell_iterator();
      e = cell_iterator();
      Sawyer::clear(symbolic);
    }
    cell_iterator b, e;
    TreeNodePtr symbolic;
  };

  // The chunk iterator iterates over Chunks.  The Chunks returned are ephemeral, and are only valid until the next iteration.
  class chunk_iterator : public boost::iterator_facade<
    chunk_iterator,
    const Chunk,
    boost::forward_traversal_tag>
  {
   private:
    friend class CellMapChunks;
    friend class boost::iterator_core_access;

    chunk_iterator(const section_iter_t & start, const section_iter_t & end)
      : section_iter(start), section_iter_end(end)
    {
      if (start != end) {
        offset_iter = section_iter->second.begin();
        update_iter();
      }
    }

    // Current section
    section_iter_t section_iter;
    // Section end() iterator
    section_iter_t section_iter_end;

    // Current chunk offset
    offset_iter_t offset_iter;
    // Offset past end of contiguous block
    offset_iter_t offset_iter_end;

    // Chunk representing the current contiguous block
    Chunk chunk;

    // Update the chunk and offset_iter_end based on the current offset_iter
    void update_iter();

    reference dereference() const {
      return chunk;
    }

    //  Iterator equality
    bool equal(const iterator & other) const {
      return ((section_iter == other.section_iter)
              && ((section_iter == section_iter_end)
                  || (offset_iter == other.offset_iter)));
    }

    // Update to the next set of contiguous offsets, updating the section if necessary
    void increment();
  };
};

// Custom class required to implement equals().  At least for a while longer.
class SymbolicState: public BaseState {

protected:
  // Constructors are protected to ensure that instance() methods are used instead.

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicState(const SymbolicRegisterStatePtr & regs, const SymbolicMemoryStatePtr & mem):
    BaseState(regs, mem) { }

  // Copy constructor should ensure a deep copy.  BUG!?!?!?! But it doesn't!
  explicit SymbolicState(const SymbolicState &other): BaseState(other) {
    STRACE << "SymbolicState::SymbolicState(other)" << LEND;
  }

public:

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicStatePtr instance(const SymbolicRegisterStatePtr &regs,
                                   const SymbolicMemoryStatePtr &mem) {
    return SymbolicStatePtr(new SymbolicState(regs, mem));
  }

  // Default constructors are a CERT addition.
  static SymbolicStatePtr instance() {
    SymbolicMemoryStatePtr mstate = SymbolicMemoryState::instance();
    SymbolicRegisterStatePtr rstate = SymbolicRegisterState::instance();
    return SymbolicStatePtr(new SymbolicState(rstate, mstate));
  }

  // Each custom class must implement promote.
  static SymbolicStatePtr promote(const BaseStatePtr &v) {
    SymbolicStatePtr retval = boost::dynamic_pointer_cast<SymbolicState>(v);
    assert(retval!=NULL);
    return retval;
  }

  virtual BaseStatePtr create(const BaseRegisterStatePtr &regs,
                              const BaseMemoryStatePtr &mem) const ROSE_OVERRIDE {
    SymbolicRegisterStatePtr sregs = SymbolicRegisterState::promote(regs);
    SymbolicMemoryStatePtr smem = SymbolicMemoryState::promote(mem);
    return instance(sregs, smem);
  }

  virtual BaseStatePtr clone() const ROSE_OVERRIDE {
    STRACE << "SymbolicState::clone()" << LEND;
    SymbolicMemoryStatePtr mymem = SymbolicMemoryState::promote(memoryState());
    SymbolicMemoryStatePtr mem_clone = mymem->sclone();
    SymbolicRegisterStatePtr myregs = SymbolicRegisterState::promote(
      // this const_cast<> is due to a bug in BaseSemantics2.h, whete registerState() is
      // supposed to be const.
      (const_cast<SymbolicState *>(this))->registerState());
    SymbolicRegisterStatePtr reg_clone = myregs->sclone();
    SymbolicStatePtr state_clone = SymbolicStatePtr(new SymbolicState(reg_clone, mem_clone));
    return state_clone;
  }

 private:
  bool merge(const BaseStatePtr &other, BaseRiscOperators *ops) ROSE_OVERRIDE;

 public:
  bool merge(const BaseStatePtr &other, BaseRiscOperators *ops, const SymbolicValuePtr & cond);

  // -----------------------------------------------------------------------------------------
  // Custom interface
  // -----------------------------------------------------------------------------------------

  // CERT addition so we don't have to promote return value.
  SymbolicStatePtr sclone() {
    STRACE << "SymbolicState::sclone()" << LEND;
    SymbolicMemoryStatePtr mem_clone = get_memory_state()->sclone();
    SymbolicRegisterStatePtr reg_clone = get_register_state()->sclone();
    SymbolicStatePtr state_clone = SymbolicStatePtr(new SymbolicState(reg_clone, mem_clone));
    return state_clone;
  }

  // Dynamically cast the register state object to our custom class.  While this same method is
  // defined on our parent, it is not virtual, and so this only applies to our custom class.
  SymbolicRegisterStatePtr get_register_state() const {
    return boost::dynamic_pointer_cast<SymbolicRegisterState>(
      // this const_cast<> is due to a bug in BaseSemantics2.h, whete registerState() is
      // supposed to be const.
      (const_cast<SymbolicState *>(this))->registerState());
  }

  // Dynamically cast the memory state object to our custom class.  While this same method is
  // defined on our parent, it is not virtual, and so this only applies to our custom class.
  SymbolicMemoryStatePtr get_memory_state() const {
    return boost::dynamic_pointer_cast<SymbolicMemoryState>(memoryState());
  }

  // ???
  SymbolicValuePtr read_register(const RegisterDescriptor &reg) {
    STRACE << "SymbolicState::read_register()" << LEND;
    SymbolicValuePtr retval = SymbolicValue::promote(get_register_state()->read_register(reg));
    return retval;
  }

  // CERT needs a rational interface read memory. :-)
  SymbolicValuePtr read_memory(const SymbolicValuePtr& address, const size_t nbits) const {
    return get_memory_state()->read_memory(address, nbits);
  }

  // CERT addition of new functionality.
  bool equals(const SymbolicStatePtr& other) {
    STRACE << "SymbolicState::equals()" << LEND;
    if (get_register_state()->equals(other->get_register_state()) &&
        get_memory_state()->equals(other->get_memory_state())) return true;
    else return false;
  }

  void type_recovery_test() const;

};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
