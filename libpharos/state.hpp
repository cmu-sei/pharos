// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_State_H
#define Pharos_State_H

#include <rose.h>

#include "semantics.hpp"
#include "misc.hpp"

namespace pharos {

// Renames of standard ROSE typdefs.
using BaseRegisterState = Semantics2::BaseSemantics::RegisterState;
using BaseRegisterStatePtr = Semantics2::BaseSemantics::RegisterStatePtr;
using BaseState = Semantics2::BaseSemantics::State;
using BaseStatePtr = Semantics2::BaseSemantics::StatePtr;
using BaseRiscOperators = Semantics2::BaseSemantics::RiscOperators;
using BaseRiscOperatorsPtr = Semantics2::BaseSemantics::RiscOperatorsPtr;
using BaseMemoryState = Semantics2::BaseSemantics::MemoryState;
using BaseMemoryStatePtr = Semantics2::BaseSemantics::MemoryStatePtr;
using MemoryCell = Semantics2::BaseSemantics::MemoryCell;
using MemoryCellPtr = Semantics2::BaseSemantics::MemoryCellPtr;
using BaseMemoryCellMap = Semantics2::BaseSemantics::MemoryCellMap;
using BaseMemoryCellMapPtr = Semantics2::BaseSemantics::MemoryCellMapPtr;
using BaseMemoryCellList = Semantics2::BaseSemantics::MemoryCellList;
using BaseMemoryCellListPtr = Semantics2::BaseSemantics::MemoryCellListPtr;
using BaseSValue = Semantics2::BaseSemantics::SValue;
using RegisterStateGeneric = Semantics2::BaseSemantics::RegisterStateGeneric;
using RegisterStateGenericPtr = Semantics2::BaseSemantics::RegisterStateGenericPtr;

// Forward declarations of the smart pointer types.
using SymbolicRiscOperatorsPtr = boost::shared_ptr<class SymbolicRiscOperators>;
using SymbolicRegisterStatePtr = boost::shared_ptr<class SymbolicRegisterState>;
using SymbolicMemoryMapStatePtr = boost::shared_ptr<class SymbolicMemoryMapState>;
using SymbolicMemoryListStatePtr = boost::shared_ptr<class SymbolicMemoryListState>;
using SymbolicStatePtr = boost::shared_ptr<class SymbolicState>;

extern SymbolicRiscOperatorsPtr global_rops;

//==============================================================================================
// SymbolicRegisterState
//==============================================================================================

// Shared-ownership pointer to merge control object.
using CERTMergerPtr = Sawyer::SharedPointer<class CERTMerger>;

// Controls merging of symbolic values.  Specifically permit passing of the condition
// expression from the state merge() to the symbolic value merge().
class CERTMerger: public Semantics2::SymbolicSemantics::Merger {
 protected:
  CERTMerger(): Semantics2::SymbolicSemantics::Merger() {
    inverted = false;
    condition = SymbolicValue::incomplete(1);
  }

 public:
  // Should the condition be inverted?
  bool inverted = false;
  // The condition that determined whether this or other is the current value.
  SymbolicValuePtr condition;

  // Shared-ownership pointer to merge control object.
  using Ptr = CERTMergerPtr;

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
  explicit SymbolicRegisterState(const SymbolicValuePtr &proto,
                                 const RegisterDictionary *rd);

  // Copy constructor should ensure a deep copy.
  // In general this doesn't happen at correct level if we don't implement it, but in this
  // case, we don't have any additional work to do calling the parent method is sufficient.
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

  // Each custom class must implement promote.
  static SymbolicRegisterStatePtr promote(const BaseRegisterStatePtr &v) {
    SymbolicRegisterStatePtr retval = boost::dynamic_pointer_cast<SymbolicRegisterState>(v);
    assert(retval!=NULL);
    return retval;
  }

  virtual BaseRegisterStatePtr create(
    const BaseSValuePtr &proto, const RegisterDictionary *rd)
    const override
  {
    STRACE << "SymbolicRegisterState::create()" << LEND;
    return instance(SymbolicValue::promote(proto), rd);
  }

  virtual BaseRegisterStatePtr clone() const override {
    STRACE << "SymbolicRegisterState::clone()" << LEND;
    return SymbolicRegisterStatePtr(new SymbolicRegisterState(*this));
  }

  using Formatter = Semantics2::BaseSemantics::Formatter;
  virtual void print(std::ostream&, Formatter&) const override;

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
  SymbolicValuePtr read_register(RegisterDescriptor rd) {
    BaseRiscOperators* ops = (BaseRiscOperators*)global_rops.get();
    return SymbolicValue::promote(RegisterStateGeneric::readRegister(
                                    rd, ops->undefined_(rd.get_nbits()), ops));
  }

  // This should probably be peekRegister() for ROSE compatability.
  SymbolicValuePtr inspect_register(RegisterDescriptor rd);
};

//==============================================================================================
// Symbolic Memory State (map-based model)
//==============================================================================================
class SymbolicMemoryMapState: public BaseMemoryCellMap {

 protected:
  // Constructors are protected to ensure that instance() methods are used instead.

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicMemoryMapState(const MemoryCellPtr &protocell_)
    : BaseMemoryCellMap(protocell_->get_address(), protocell_->get_value()) {
    merger(CERTMerger::instance());
  }

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicMemoryMapState(const SymbolicValuePtr &addr, const SymbolicValuePtr &val)
    : BaseMemoryCellMap(addr, val) {
    merger(CERTMerger::instance());
  }

  // Copy constructor should ensure a deep copy.
  explicit SymbolicMemoryMapState(const SymbolicMemoryMapState & other)
    : BaseMemoryCellMap(other) {
    // Our merger is copied by default?
  }

 public:

  // Promote to our type.
  static SymbolicMemoryMapStatePtr promote(const BaseMemoryStatePtr &x) {
    SymbolicMemoryMapStatePtr retval = boost::dynamic_pointer_cast<SymbolicMemoryMapState>(x);
    ASSERT_not_null(retval);
    return retval;
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicMemoryMapStatePtr instance(const SymbolicValuePtr &addr,
                                            const SymbolicValuePtr &val) {
    return SymbolicMemoryMapStatePtr(new SymbolicMemoryMapState(addr, val));
  }

  // Instance() methods must take custom types to ensure promotion.
  // But Robb calls the instance() method with BaseSValues in tracsem.cpp.
  static SymbolicMemoryMapStatePtr instance(const BaseSValuePtr &addr,
                                            const BaseSValuePtr &val) {
    SymbolicValuePtr saddr = SymbolicValue::promote(addr);
    SymbolicValuePtr sval = SymbolicValue::promote(val);
    return SymbolicMemoryMapStatePtr(new SymbolicMemoryMapState(saddr, sval));
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicMemoryMapStatePtr instance(const MemoryCellPtr &protocell) {
    return SymbolicMemoryMapStatePtr(new SymbolicMemoryMapState(protocell));
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicMemoryMapStatePtr instance(const SymbolicMemoryMapStatePtr &other) {
    return SymbolicMemoryMapStatePtr(new SymbolicMemoryMapState(*other));
  }

  // Default constructors are a CERT addition.
  static SymbolicMemoryMapStatePtr instance() {
    SymbolicValuePtr svalue = SymbolicValue::instance();
    return SymbolicMemoryMapStatePtr(new SymbolicMemoryMapState(svalue, svalue));
  }

  virtual BaseMemoryStatePtr create(const BaseSValuePtr &addr,
                                    const BaseSValuePtr &val) const override {
    STRACE << "SymbolicMemoryMapState::create(addr, val)" << LEND;
    SymbolicValuePtr addr_ = SymbolicValue::promote(addr);
    SymbolicValuePtr val_ = SymbolicValue::promote(val);
    return instance(addr_, val_);
  }

  virtual CellKey generateCellKey(const BaseSValuePtr &address) const override {
    SymbolicValuePtr saddr = SymbolicValue::promote(address);
    return saddr->get_hash();
  }

  virtual BaseMemoryStatePtr clone() const override {
    STRACE << "SymbolicMemoryMapState::clone()" << LEND;
    return BaseMemoryStatePtr(new SymbolicMemoryMapState(*this));
  }

  SymbolicMemoryMapStatePtr sclone() {
    STRACE << "SymbolicMemoryMapState::sclone()" << LEND;
    return SymbolicMemoryMapStatePtr(new SymbolicMemoryMapState(*this));
  }

  virtual bool merge(const BaseMemoryStatePtr& other_,
                     BaseRiscOperators* addrOps,
                     BaseRiscOperators* valOps) override;

  using Formatter = Semantics2::BaseSemantics::Formatter;
  virtual void print(std::ostream&, Formatter&) const override;

  // CERT needs a rational interface read memory. :-)
  SymbolicValuePtr read_memory(const SymbolicValuePtr& address, const size_t nbits) const;
  void write_memory(const SymbolicValuePtr& address, const SymbolicValuePtr& value);

  // CERT addition of new functionality.
  bool equals(const SymbolicMemoryMapStatePtr& other);
};

//==============================================================================================
// Symbolic Memory State (list-based model)
//==============================================================================================
class SymbolicMemoryListState: public BaseMemoryCellList {

 protected:
  // Constructors are protected to ensure that instance() methods are used instead.

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicMemoryListState(const MemoryCellPtr &protocell_)
    : BaseMemoryCellList(protocell_->get_address(), protocell_->get_value()) {
  }

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicMemoryListState(const SymbolicValuePtr &addr, const SymbolicValuePtr &val)
    : BaseMemoryCellList(addr, val) {
  }

  // Copy constructor should ensure a deep copy.
  explicit SymbolicMemoryListState(const SymbolicMemoryListState & other)
    : BaseMemoryCellList(other) {
  }

 public:

  // Promote to our type.
  static SymbolicMemoryListStatePtr promote(const BaseMemoryStatePtr &x) {
    SymbolicMemoryListStatePtr retval = boost::dynamic_pointer_cast<SymbolicMemoryListState>(x);
    ASSERT_not_null(retval);
    return retval;
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicMemoryListStatePtr instance(const SymbolicValuePtr &addr,
                                             const SymbolicValuePtr &val) {
    return SymbolicMemoryListStatePtr(new SymbolicMemoryListState(addr, val));
  }

  // Instance() methods must take custom types to ensure promotion.
  // But Robb calls the instance() method with BaseSValues in tracesem.cpp.
  static SymbolicMemoryListStatePtr instance(const BaseSValuePtr &addr,
                                             const BaseSValuePtr &val) {
    SymbolicValuePtr saddr = SymbolicValue::promote(addr);
    SymbolicValuePtr sval = SymbolicValue::promote(val);
    return SymbolicMemoryListStatePtr(new SymbolicMemoryListState(saddr, sval));
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicMemoryListStatePtr instance(const MemoryCellPtr &protocell) {
    return SymbolicMemoryListStatePtr(new SymbolicMemoryListState(protocell));
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicMemoryListStatePtr instance(const SymbolicMemoryListStatePtr &other) {
    return SymbolicMemoryListStatePtr(new SymbolicMemoryListState(*other));
  }

  // Default constructors are a CERT addition.
  static SymbolicMemoryListStatePtr instance() {
    SymbolicValuePtr svalue = SymbolicValue::instance();
    return SymbolicMemoryListStatePtr(new SymbolicMemoryListState(svalue, svalue));
  }

  virtual BaseMemoryStatePtr create(const BaseSValuePtr &addr,
                                    const BaseSValuePtr &val) const override {
    STRACE << "SymbolicMemoryListState::create(addr, val)" << LEND;
    SymbolicValuePtr addr_ = SymbolicValue::promote(addr);
    SymbolicValuePtr val_ = SymbolicValue::promote(val);
    return instance(addr_, val_);
  }

  virtual BaseMemoryStatePtr clone() const override {
    STRACE << "SymbolicMemoryListState::clone()" << LEND;
    return BaseMemoryStatePtr(new SymbolicMemoryListState(*this));
  }

  using Formatter = Semantics2::BaseSemantics::Formatter;
  virtual void print(std::ostream&, Formatter&) const override;

  SymbolicMemoryListStatePtr sclone() {
    STRACE << "SymbolicMemoryListState::sclone()" << LEND;
    return SymbolicMemoryListStatePtr(new SymbolicMemoryListState(*this));
  }


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
  using iterator = chunk_iterator;
  using const_iterator = chunk_iterator;
  using value_type = const Chunk;

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
  using offset_map_t = std::map<int64_t, TreeNodePtr>;
  // A map of TreeNodes (minus additive constants) to offset maps
  using section_map_t = std::map<TreeNodePtr, offset_map_t, TreeNodePtrCompare>;

  // Iterator typedefs
  using offset_iter_t = offset_map_t::const_iterator;
  using section_iter_t = section_map_t::const_iterator;

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
  // using symbol().  The iterators returned can be dereferenced to TreeNodes, and their
  // offset() method returns the offset.
  class Chunk {
   public:
    using value_type = const TreeNodePtr;
    using reference_type = value_type &;
    using iterator = cell_iterator;
    using const_iterator = iterator;
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

  // The chunk iterator iterates over Chunks.  The Chunks returned are ephemeral, and are only
  // valid until the next iteration.
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

//==============================================================================================
// SymbolicState (registers and memory, using either the list-based or map-based memory model)
//==============================================================================================

// Custom class required to implement equals().  At least for a while longer.
class SymbolicState: public BaseState {

 protected:
  // Are we using the list-based or map-based memory model?
  bool map_based;

  // Constructors are protected to ensure that instance() methods are used instead.

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicState(const SymbolicRegisterStatePtr & regs,
                         const SymbolicMemoryMapStatePtr & mem):
    BaseState(regs, mem) {
    map_based = true;
  }

  // Constructors must take custom types to ensure promotion.
  explicit SymbolicState(const SymbolicRegisterStatePtr& regs,
                         const SymbolicMemoryListStatePtr& mem):
    BaseState(regs, mem) {
    map_based = false;
  }

  // Copy constructor should ensure a deep copy?
  explicit SymbolicState(const SymbolicState &other): BaseState(other) {
    STRACE << "SymbolicState::SymbolicState(other)" << LEND;
    map_based = other.map_based;
  }

 public:

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicStatePtr instance(const SymbolicRegisterStatePtr &regs,
                                   const SymbolicMemoryMapStatePtr &mem) {
    return SymbolicStatePtr(new SymbolicState(regs, mem));
  }

  // Instance() methods must take custom types to ensure promotion.
  static SymbolicStatePtr instance(const SymbolicRegisterStatePtr& regs,
                                   const SymbolicMemoryListStatePtr& mem) {
    return SymbolicStatePtr(new SymbolicState(regs, mem));
  }

  // There's no default constructor for SymbolicState, because you might want a list-based
  // memory state or a map-based memory state.  It seems better to require the caller to be
  // clear about that each time.

  // Each custom class must implement promote.
  static SymbolicStatePtr promote(const BaseStatePtr &v) {
    SymbolicStatePtr retval = boost::dynamic_pointer_cast<SymbolicState>(v);
    assert(retval!=NULL);
    return retval;
  }

  virtual BaseStatePtr create(const BaseRegisterStatePtr &regs,
                              const BaseMemoryStatePtr &mem) const override {
    SymbolicRegisterStatePtr sregs = SymbolicRegisterState::promote(regs);
    if (map_based) {
      SymbolicMemoryMapStatePtr smem = SymbolicMemoryMapState::promote(mem);
      return instance(sregs, smem);
    }
    else {
      SymbolicMemoryListStatePtr smem = SymbolicMemoryListState::promote(mem);
      return instance(sregs, smem);
    }
  }

  virtual BaseStatePtr clone() const override {
    STRACE << "SymbolicState::clone()" << LEND;
    SymbolicRegisterStatePtr reg_clone = get_register_state()->sclone();
    // Use Dynamic cast instead of promote to determine which type of memory state we have.
    if (map_based) {
      SymbolicMemoryMapStatePtr smem = SymbolicMemoryMapState::promote(memoryState());
      SymbolicMemoryMapStatePtr mem_clone = smem->sclone();
      return SymbolicStatePtr(new SymbolicState(reg_clone, mem_clone));
    }
    else {
      SymbolicMemoryListStatePtr smem = SymbolicMemoryListState::promote(memoryState());
      SymbolicMemoryListStatePtr mem_clone = smem->sclone();
      return SymbolicStatePtr(new SymbolicState(reg_clone, mem_clone));
    }
  }

 private:
  bool merge(const BaseStatePtr &other, BaseRiscOperators *ops) override;

 public:
  bool merge(const BaseStatePtr &other, BaseRiscOperators *ops, const SymbolicValuePtr & cond);

  // -----------------------------------------------------------------------------------------
  // Custom interface
  // -----------------------------------------------------------------------------------------

  // CERT addition so we don't have to promote return value.
  SymbolicStatePtr sclone() {
    STRACE << "SymbolicState::sclone()" << LEND;
    return promote(clone());
  }

  // Dynamically cast the register state object to our custom class.  While this same method is
  // defined on our parent, it is not virtual, and so this only applies to our custom class.
  SymbolicRegisterStatePtr get_register_state() const {
    return boost::dynamic_pointer_cast<SymbolicRegisterState>(registerState());
  }

  // ???
  SymbolicValuePtr read_register(RegisterDescriptor reg) {
    STRACE << "SymbolicState::read_register()" << LEND;
    SymbolicValuePtr retval = SymbolicValue::promote(get_register_state()->read_register(reg));
    return retval;
  }

  // CERT needs a rational interface read memory. :-)
  SymbolicValuePtr read_memory(const SymbolicValuePtr& address, const size_t nbits) const {
    if (map_based) {
      const SymbolicMemoryMapStatePtr& mem = SymbolicMemoryMapState::promote(memoryState());
      return mem->read_memory(address, nbits);
    }
    else {
      abort(); // Not implemented
      //const SymbolicMemoryListStatePtr& mem = SymbolicMemoryListState::promote(memoryState());
      //return mem->read_memory(address, nbits);
    }
  }

  // Are we using the list-based or map-based memory model?
  bool is_map_based() const { return map_based; }

  // CERT addition of new functionality.
  bool equals(const SymbolicStatePtr& other) {
    STRACE << "SymbolicState::equals()" << LEND;
    if (map_based && other->map_based) {
      const SymbolicRegisterStatePtr& regs = SymbolicRegisterState::promote(registerState());
      const SymbolicMemoryMapStatePtr& mem = SymbolicMemoryMapState::promote(memoryState());
      const SymbolicRegisterStatePtr& oregs = SymbolicRegisterState::promote(other->registerState());
      const SymbolicMemoryMapStatePtr& omem = SymbolicMemoryMapState::promote(other->memoryState());
      if (regs->equals(oregs) && mem->equals(omem)) return true;
      else return false;
    }
    else {
      abort(); // Not implemented
    }
  }
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
