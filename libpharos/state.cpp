// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include "state.hpp"
#include "riscops.hpp"
#include "defuse.hpp"

namespace pharos {

// Copied from riscops.hpp
extern SymbolicRiscOperatorsPtr global_rops;

//#define STATE_DEBUG
#ifdef STATE_DEBUG
#define DSTREAM OINFO
#else
#define DSTREAM SDEBUG
#endif

using Rose::BinaryAnalysis::SymbolicExpr::OP_ITE;

CERTMerger::Ptr CERTMerger::instance() {
  return Ptr(new CERTMerger{});
}

SymbolicRegisterState::SymbolicRegisterState(
  const SymbolicValuePtr &proto, RegisterDictionaryPtrArg rd):
  RegisterStateGeneric(proto, rd)
{
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

// Compare the symbolic values of two register states.
bool SymbolicRegisterState::equals(const SymbolicRegisterStatePtr & other) {
  STRACE << "GenericRegisterState::equals()" << LEND;
  for (const RegisterStateGeneric::RegPairs& rpl : registers_.values()) {
    for (const RegisterStateGeneric::RegPair& rp : rpl) {
      // SEMCLEANUP Make these (and others) be references for performance?
      SymbolicValuePtr value = SymbolicValue::promote(rp.value);
      SymbolicValuePtr ovalue = other->read_register(rp.desc);

      // If both values are in the incomplete state, it doesn't really matter if they're equal.
      // Continue to the next register, effectively returning true for this register.
      if (value->is_incomplete() && ovalue->is_incomplete()) {
        DSTREAM << "Register " << unparseX86Register(rp.desc, {})
                << " ignored because both values were incomplete." << LEND;
        continue;
      }

      // If one or the other is incomplete (but not both) return false to iterate again.
      if (value->is_incomplete() || ovalue->is_incomplete()) {
        DSTREAM << "Register " << unparseX86Register(rp.desc, {})
                << " has differing correctness, iterating "
                << *value << " != " << *ovalue << LEND;
        return false;
      }

      // For all other situations, the values must mach symbolically.
      if (!(*value == *ovalue)) {
        DSTREAM << "Register " << unparseX86Register(rp.desc, {}) << " changed: "
                << *value << " != " << *ovalue << LEND;
        return false;
      }
    }
  }

  // If we made it this far, the register state as a whole was unchanged.
  DSTREAM << "Register state was unchanged." << LEND;
  return true;
}

SymbolicValuePtr SymbolicRegisterState::inspect_register(RegisterDescriptor rd) {
  RegisterStateGeneric::AccessCreatesLocationsGuard(this, false);
  try {
    return read_register(rd);
  }
  catch (const RegisterNotPresent &) {
    return SymbolicValuePtr();
  }
}


// Compare to register states.
RegisterSet SymbolicRegisterState::diff(const SymbolicRegisterStatePtr & other) {
  RegisterStateGeneric::AccessCreatesLocationsGuard(this, false);
  RegisterSet changed;

  // For each register in our state, compare it with the other.
  for (const RegisterStateGeneric::RegPairs& rpl : registers_.values()) {
    for (const RegisterStateGeneric::RegPair& rp : rpl) {
      SymbolicValuePtr value = SymbolicValue::promote(rp.value);
      SymbolicValuePtr ovalue = other->inspect_register(rp.desc);
      // If there's no value at all in the output state, it must be unchanged.
      if (!ovalue) continue;
      // Report everything that's not guaranteed to match.  The caller can think harder about
      // the results if they want, but we shouldn't force more analysis than is required here.
      if (!(value->mustEqual(ovalue, SmtSolverPtr()))) {
        changed.insert(rp.desc);
      }
    }
  }

  // Return the register state that contains only the changed entries.
  return changed;
}

// The comparsion of two symbolic values used in SymbolicMemoryMapState::equals().  We need to
// call this logic twice, so it was cleaner to put it here.
bool mem_compare(SymbolicValuePtr addr, SymbolicValuePtr value, SymbolicValuePtr ovalue) {
  // If both values are in the incomplete state, it doesn't really matter if they're equal.
  // Continue to the next register, effectively returning true for this register.
  if (value->is_incomplete() && ovalue->is_incomplete()) {
    DSTREAM << "Memory cell " << *addr << " changed:" << *value << " != " << *ovalue
            << " ignored because both values were incomplete." << LEND;
    return true;
  }

  // If one or the other is incomplete (but not both) return false to iterate again.
  if (value->is_incomplete() || ovalue->is_incomplete()) {
    DSTREAM << "Memory cell " << *addr << " changed:" << *value << " != " << *ovalue
            << " has differing correctness, iterating "
            << *value << " != " << *ovalue << LEND;
    return false;
  }

  // For all other situations, the values must mach symbolically.
  // This is at least one place where operator== is being used (ambigously?)
  if (*value == *ovalue) return true;

  DSTREAM << "Memory cell " << *addr << " changed:" << *value << " != " << *ovalue << LEND;
  return false;
}

CellMapChunks::CellMapChunks(const DUAnalysis & usedef, bool df_flag) {
  const auto & input_state = usedef.get_input_state();
  const auto & output_state = usedef.get_output_state();
  if (!input_state || !output_state) {
    return;
  }

  // The df f should be treated as a constant value when chunking addresses
  RegisterDictionaryPtrArg regdict = usedef.ds.get_regdict();
  RegisterDescriptor df_reg = regdict->find("df");
  const auto & df_sym = const_cast<SymbolicStatePtr &>(input_state)->read_register(df_reg);
  const auto & df_tn = df_sym ? df_sym->get_expression() : TreeNodePtr();
  auto df_value = SymbolicExpr::makeBooleanConstant(df_flag);

  // Build the sorted memory map
  const SymbolicMemoryMapStatePtr& mstate =
    SymbolicMemoryMapState::promote(output_state->memoryState());
  for (const auto & cell : mstate->allCells()) {
    const SymbolicValuePtr & addr = SymbolicValue::promote(cell->address());
    auto expr = addr->get_expression();
    if (df_tn) {
      // Set references of df in the expression to the value of df_flag, and re-evaluate
      expr = expr->substitute(df_tn, df_value);
    }
    // Extract the possible values, dealing with the possibility of ITEs
    AddConstantExtractor ade(expr);
    for (const auto & ade_data : ade.get_data()) {
      // Variable portion
      const auto & var = ade_data.first;
      // Offset (only use the first)
      auto offset = *ade_data.second.begin();

      // Find the variable portion in the map
      section_map_t::iterator iter = section_map.find(var);
      if (iter == section_map.end()) {
        // If this variable potion is not in the map, add it
        iter = section_map.insert(std::make_pair(var, offset_map_t())).first;
      }
      // last_value has the existing value in the map for this offset (will create if
      // not extant)
      auto & last_value = iter->second[offset];
      // The value for this memory location
      const auto & value = SymbolicValue::promote(cell->value())->get_expression();
      if (last_value) {
        // If a value already existed, add this value to it via an ITE
        auto tcond = SymbolicExpr::makeIntegerVariable(1, "", INCOMPLETE);
        auto ite = InternalNode::instance(OP_ITE, std::move(tcond), value, last_value);
        last_value = std::move(ite);
      } else {
        // Otherwise, store the value
        last_value = value;
      }
    }
  }
}

void CellMapChunks::chunk_iterator::update_iter()
{
  int64_t offset = offset_iter->first;
  offset_iter_t i = offset_iter;
  for (++i; i != section_iter->second.end(); ++i) {
    ++offset;
    if (i->first != offset) {
      break;
    }
  }
  offset_iter_end = i;
  chunk.b = cell_iterator(offset_iter);
  chunk.e = cell_iterator(i);
  chunk.symbolic = section_iter->first;
}

void CellMapChunks::chunk_iterator::increment()
{
  offset_iter = offset_iter_end;
  if (offset_iter == section_iter->second.end()) {
    ++section_iter;
    if (section_iter == section_iter_end) {
      offset_iter = offset_iter_t();
      chunk.clear();
      return;
    }
    offset_iter = section_iter->second.begin();
  }
  update_iter();
}


// Type recovery test!

using TreeNodeVisitor = Rose::BinaryAnalysis::SymbolicExpr::Visitor;
using VisitAction = Rose::BinaryAnalysis::SymbolicExpr::VisitAction;

class TypeRecoveryVisitor: public TreeNodeVisitor {

  std::string indent;

 public:

  // We should really pass the Formatter into the constructor to get the proper indentation prefix.
  TypeRecoveryVisitor() {
    indent = "    ";
  }
  virtual VisitAction preVisit(const TreeNodePtr& tn) {
    OINFO << indent << tn->hash() << ": "<< *tn << LEND;
    indent = indent + "  ";
    return Rose::BinaryAnalysis::SymbolicExpr::CONTINUE;
  }
  virtual VisitAction postVisit(UNUSED const TreeNodePtr& tn) {
    indent = indent.substr(0, indent.size() - 2);
    return Rose::BinaryAnalysis::SymbolicExpr::CONTINUE;
  }
};

static bool
sortByOffset(const RegisterStateGeneric::RegPair &a, const RegisterStateGeneric::RegPair &b) {
  return a.desc.get_offset() < b.desc.get_offset();
}

void SymbolicRegisterState::print(std::ostream& stream, Formatter& fmt) const {
  // Print the register state using the standard ROSE API.
  RegisterStateGeneric::print(stream, fmt);
  return;

  // Disable the following code by returning early.  Right now, the code below is really just a
  // stub for extending this system to print something else we might want to report, primarily
  // in the tracesem program, but it makes the output less useful in its current state.

  size_t maxlen = 6;

  // This is an approximation of the behavior before we switched to print().
  //TypeRecoveryVisitor trv;
  for (const RegisterStateGeneric::RegPairs& rpl : registers_.values()) {
    RegisterStateGeneric::RegPairs regPairs = rpl;
    std::sort(regPairs.begin(), regPairs.end(), sortByOffset);
    for (const RegisterStateGeneric::RegPair& rp : regPairs) {
      std::string regname = unparseX86Register(rp.desc, regdict);
      // We used to filter a couple of different ways (for all registers printed, not just our extensions).
      // e.g. if (rp.desc.get_major() != 0) continue;
      // e.g. if (regname == "eax" || regname == "ebx") { ...}
      // Disabled because the current code would only filter for half the output anyway.

      // We have to re-emit the register name... :-(
      stream << fmt.get_line_prefix() << std::setw(maxlen) << std::left << regname << std::endl;

      SymbolicValuePtr value = SymbolicValue::promote(rp.value);
      for (const TreeNodePtr& v : value->get_possible_values()) {
        stream << fmt.get_line_prefix() << "  possible=" << *v << LEND;
      }

      // This is frequently huge, so I've commented it out.  It should really be controlled by
      // an option on an overriden Formatter class.
      //OINFO << fmt.get_line_prefix() << "  hashes=" << LEND;
      //TreeNodePtr tn = value->get_expression();
      //tn->depthFirstTraversal(trv);
    }
  }
}

bool SymbolicState::merge(const BaseStatePtr &, BaseRiscOperators *) {
  // We do not want this class to be merged without a given condition (I.e., by the ROSE API
  // internals.
  abort();
}

bool SymbolicState::merge(const BaseStatePtr &other, BaseRiscOperators *ops,
                          const SymbolicValuePtr & condition)
{
  // Get the currenter CERTMerger() object which contains context for the merge operation, and
  // set the condition there, so that it will be available later in createOptionalMerge().
  if (!map_based) abort(); // Not implemented.
  const SymbolicMemoryMapStatePtr& mstate = SymbolicMemoryMapState::promote(memoryState());
  CERTMergerPtr cert_mem_merger = mstate->merger().dynamicCast<CERTMerger>();
  cert_mem_merger->condition = condition;
  CERTMergerPtr cert_reg_merger = get_register_state()->merger().dynamicCast<CERTMerger>();
  cert_reg_merger->condition = condition;

  // Call the standard merge method.
  return BaseState::merge(other, ops);
}

// =========================================================================================
// The new more standardized approach!
// =========================================================================================

SymbolicValuePtr SymbolicMemoryMapState::read_memory(
  const SymbolicValuePtr& address, const size_t nbits) const {
  SymbolicRiscOperators* ops = global_rops.get();
  return(ops->read_memory(this, address, nbits));
}

void SymbolicMemoryMapState::write_memory(
  const SymbolicValuePtr& address, const SymbolicValuePtr& value) {
  SymbolicRiscOperators* ops = global_rops.get();
  return(writeMemory(address, value, ops, ops));
}

void SymbolicMemoryMapState::print(std::ostream& stream, Formatter& fmt) const {
  // Print the register state using the standard ROSE API.
  MemoryCellMap::print(stream, fmt);

  //TypeRecoveryVisitor trv;
  //for (const MemoryCellPtr& cell : allCells()) {
  //  SymbolicValuePtr address = SymbolicValue::promote(cell->get_address());
  //  SymbolicValuePtr value = SymbolicValue::promote(cell->get_value());
  //  TreeNodePtr tn = value->get_expression();
  //  tn->depthFirstTraversal(trv);
  //}
}

void SymbolicMemoryListState::print(std::ostream& stream, Formatter& fmt) const {
  // Print the re state using the standard ROSE API.
  MemoryCellList::print(stream, fmt);

  for (const MemoryCellPtr& cell : allCells()) {
    SymbolicValuePtr address = SymbolicValue::promote(cell->address());
    SymbolicValuePtr value = SymbolicValue::promote(cell->value());
  }
}

// Compare to memory states based on their symbolic values.
bool SymbolicMemoryMapState::equals(const SymbolicMemoryMapStatePtr& other) {
  for (const MemoryCellPtr & cell : allCells()) {
    SymbolicValuePtr ma = SymbolicValue::promote(cell->address());
    SymbolicValuePtr mv = SymbolicValue::promote(cell->value());

    MemoryCellPtr ocell = other->findCell(ma);
    if (ocell) {
      SymbolicValuePtr omv = SymbolicValue::promote(ocell->value());
      if (!mem_compare(ma, mv, omv)) return false;
    }
    else {
      if (ma->is_incomplete()) {
        DSTREAM << "Memory cell (incomplete) " << *ma << " was not found (ignoring)." << LEND;
      }
      else {
        DSTREAM << "Memory cell (complete) " << *ma << " was not found." << LEND;
        return false;
      }
    }
  }
  for (const MemoryCellPtr & ocell : other->allCells()) {
    SymbolicValuePtr oma = SymbolicValue::promote(ocell->address());
    SymbolicValuePtr omv = SymbolicValue::promote(ocell->value());

    MemoryCellPtr cell = findCell(oma);
    if (cell) {
      SymbolicValuePtr mv = SymbolicValue::promote(cell->value());
      if (!mem_compare(oma, mv, omv)) return false;
    }
    else {
      if (oma->is_incomplete()) {
        DSTREAM << "Memory cell (incomplete) " << *oma << " was not found (ignoring)." << LEND;
      }
      else {
        DSTREAM << "Memory cell (complete) " << *oma << " was not found." << LEND;
        return false;
      }
    }
  }

  // If we made it this far, the memory state as a whole was unchanged.
  DSTREAM << "Memory state unchanged." << LEND;
  return true;
}

using InputOutputPropertySet = Semantics2::BaseSemantics::InputOutputPropertySet;

bool SymbolicMemoryMapState::merge(const BaseMemoryStatePtr& other_,
                                   BaseRiscOperators* addrOps,
                                   BaseRiscOperators* valOps) {

  // The BaseMergerPtr is really a CERTMergerPtr.
  const CERTMergerPtr& cert_merger = merger().dynamicCast<CERTMerger>();
  // We should always have a CERTMerger object.
  assert(cert_merger);

  std::set<CellKey> processed;
  // =====================================================================================
  // Begin copy of ROSE standard code
  // =====================================================================================
  BaseMemoryCellMapPtr other = boost::dynamic_pointer_cast<BaseMemoryCellMap>(other_);
  ASSERT_not_null(other);
  bool changed = false;

  for (const MemoryCellPtr &otherCell : other->allCells()) {
    bool thisCellChanged = false;
    CellKey key = generateCellKey(otherCell->address());
    if (const MemoryCellPtr &thisCell = cells.getOrDefault(key)) {
      BaseSValuePtr otherValue = otherCell->value();
      BaseSValuePtr thisValue = thisCell->value();
      BaseSValuePtr newValue = thisValue->createOptionalMerge(otherValue, merger(), valOps->solver()).orDefault();
      if (newValue)
        thisCellChanged = true;

      const auto & otherWriters = otherCell->getWriters();
      const auto & thisWriters = thisCell->getWriters();
      auto newWriters = otherWriters | thisWriters;
      if (newWriters != thisWriters)
        thisCellChanged = true;

      const InputOutputPropertySet & otherProps = otherCell->ioProperties();
      const InputOutputPropertySet & thisProps = thisCell->ioProperties();
      InputOutputPropertySet newProps = otherProps | thisProps;
      if (newProps != thisProps)
        thisCellChanged = true;

      if (thisCellChanged) {
        if (!newValue)
          newValue = thisValue->copy();

        //SymbolicValuePtr thisCellSV = SymbolicValue::promote(thisCell->get_address());
        //SymbolicValuePtr newValueSV = SymbolicValue::promote(newValue);
        //OINFO << "Writing to memory 1 ADDR=  "
        //      << *thisCellSV->get_expression() << ", VAL= " << *newValueSV->get_expression() << LEND;

        writeMemory(thisCell->address(), newValue, addrOps, valOps);
        latestWrittenCell_->setWriters(newWriters);
        latestWrittenCell_->ioProperties() = newProps;
        changed = true;
      }
    }
    // =====================================================================================
    // End copy of ROSE standard code
    // =====================================================================================

    // SEI added the entire else clause here.  This code merges an incomplete value with a cell
    // in the other memory state that is not in this memory state.
    else {
      BaseSValuePtr otherValue = otherCell->value();

      // Create the incomplete value.  But first mark that we want to use the inverted
      // condition, because we're calling other->merge(this) rather than this->merge(other) and
      // the condition is tied to which object is this and which is other.  Immediately after
      // completing the merge of this value, set inverted back to false.
      cert_merger->inverted = true;
      BaseSValuePtr newValue = otherValue->createOptionalMerge(BaseSValuePtr(), merger(), valOps->solver()).orDefault();
      cert_merger->inverted = false;

      if (!newValue) continue;
      // Write the merged cell into this memory state.

      //SymbolicValuePtr otherCellSV = SymbolicValue::promote(otherCell->get_address());
      //SymbolicValuePtr newValueSV = SymbolicValue::promote(newValue);
      //OINFO << "Writing to memory 2 ADDR=  "
      //      << *otherCellSV->get_expression() << ", VAL= " << *newValueSV->get_expression() << LEND;

      writeMemory(otherCell->address(), newValue, addrOps, valOps);
      latestWrittenCell_->setWriters(otherCell->getWriters());
      latestWrittenCell_->ioProperties() = otherCell->ioProperties();
      changed = true;
    }

    processed.insert(key); // SEI addition to track whether we've already processed a value.
  }

  // SEI added the entire second pass, where we evaluate all cells in this memory state,
  // merging any that weren't already processed (found in the other memory state) with an
  // incomplete value.
  for (const MemoryCellPtr &thisCell : allCells()) {
    CellKey key = generateCellKey(thisCell->address());
    // If we've already processed this key, we're done.
    if(processed.find(key) != processed.end()) continue;
    BaseSValuePtr thisValue = thisCell->value();
    // This cell must exist only in this memory state.  Merge it with an incomplete value.
    BaseSValuePtr newValue = thisValue->createOptionalMerge(BaseSValuePtr(), merger(), valOps->solver()).orDefault();
    if (!newValue) continue;
    // Write the merged cell into this memory state.

    //SymbolicValuePtr thisCellSV = SymbolicValue::promote(thisCell->get_address());
    //SymbolicValuePtr newValueSV = SymbolicValue::promote(newValue);
    //OINFO << "Writing to memory 3 ADDR=  "
    //      << *thisCellSV->get_expression() << ", VAL= " << *newValueSV->get_expression() << LEND;

    writeMemory(thisCell->address(), newValue, addrOps, valOps);
    latestWrittenCell_->setWriters(thisCell->getWriters());
    latestWrittenCell_->ioProperties() = thisCell->ioProperties();
    changed = true;
  }

  return changed;
}

// Create an expression representing: if a==b then c else d.
// Expressed as a treenode, that's: (ite (zerop (add a b)) c d).
SymbolicValuePtr create_equality(
  const SymbolicValuePtr& a,
  const SymbolicValuePtr& b,
  const SymbolicValuePtr& c,
  const SymbolicValuePtr& d)
{
  // Get the TreeNodes from each expression.
  const TreeNodePtr& atn = a->get_expression();
  const TreeNodePtr& btn = b->get_expression();
  const TreeNodePtr& ctn = c->get_expression();
  const TreeNodePtr& dtn = d->get_expression();

  OINFO << "Equality a=" << *a << LEND;
  OINFO << "Equality b=" << *b << LEND;
  OINFO << "Equality c=" << *c << LEND;
  OINFO << "Equality d=" << *d << LEND;

  // Construct the new expression.
  using Rose::BinaryAnalysis::SymbolicExpr::OP_XOR;
  using Rose::BinaryAnalysis::SymbolicExpr::OP_ZEROP;
  using Rose::BinaryAnalysis::SymbolicExpr::OP_ITE;
  TreeNodePtr xor_expr = InternalNode::instance(OP_XOR, atn, btn);
  TreeNodePtr zerop_expr = InternalNode::instance(OP_ZEROP, xor_expr);
  TreeNodePtr ite_expr = InternalNode::instance(OP_ITE, zerop_expr, ctn, dtn);

  // Create a symbolic value from the newly created expression.
  SymbolicValuePtr retval = SymbolicValue::treenode_instance(ite_expr);

  // There's more work to be done here to set the definers and so forth.  I'm a little unclear
  // on exactly what should be done, so we'll start by seeing if the ITE expression was
  // constructed correctly.
  OINFO << "Equality r=" << *retval << LEND;
  return retval;
}

// It's unclear which of these really need to be tested, but it seemed prudent to list all of
// the possible IO properties here to make it easier to understand what they mean.

using Semantics2::BaseSemantics::IO_READ;               // read on behalf of an instruction.
using Semantics2::BaseSemantics::IO_WRITE;              // written on behalf of an instruction.
using Semantics2::BaseSemantics::IO_INIT;               // written without an instruction.
using Semantics2::BaseSemantics::IO_READ_BEFORE_WRITE;  // read without having IO_WRITE.
using Semantics2::BaseSemantics::IO_READ_AFTER_WRITE;   // read after being written.
using Semantics2::BaseSemantics::IO_READ_UNINITIALIZED; // read without having IO_WRITE or IO_INIT.

// From the base list-based memory representation.
using CellList = Semantics2::BaseSemantics::MemoryCellList::CellList;

// Rose::BinaryAnalysis::InstructionSemantics2::BaseSemantics::MemoryCellList’ is not a namespace or unscoped enum

// Convert a list-based memory state into a map-based memory state.
SymbolicMemoryMapStatePtr convert_memory_list_to_map(
  SymbolicMemoryListStatePtr list_mem,
  size_t max_aliases, bool give_up)
{
  // Our primary return value is of course the map-based memory model.
  SymbolicMemoryMapStatePtr map_mem = SymbolicMemoryMapState::instance();
  SymbolicRiscOperators* ops = global_rops.get();

  // Wrong, but what is correct?
  SymbolicValuePtr segreg = SymbolicValue::instance();

  // But we should also be producing a "substitution map" that helps us understand how
  // variables relate to one-another from a substitution perspective.

  // For each memory operation in the list...
  const CellList& cells = list_mem->get_cells();
  CellList::const_reverse_iterator rcursor = cells.rbegin();
  while (rcursor != cells.rend()) {
    // Get the address and the value.
    const MemoryCellPtr& cell = *rcursor;
    const SymbolicValuePtr& address = SymbolicValue::promote(cell->address());
    const SymbolicValuePtr& value = SymbolicValue::promote(cell->value());

    // If the cell is a write, no aliasing has occurred, and we just update the map.  Any
    // aliasing that might have occurred will be handled when we subsequently read.
    if (cell->ioProperties() == IO_WRITE) {
      OINFO << "Write: addr=" << *address << " value=" << *value << LEND;
      map_mem->write_memory(address, value);
      // Advance immediately to the next cell in the list.
      rcursor++;
      continue;
    }

    // Otherwise read the existing value from the memory map.

    // Is this way more graceful?
    const SymbolicValuePtr& evalue = map_mem->read_memory(address, 8);

    // Or this way?
    //MemoryCellPtr ecell = map_mem->findCell(address);
    //if (ecell) {
    //  SymbolicValuePtr evalue = SymbolicValue::promote(ecell->get_value());
    //}

    // If the memory cell does not exist in the map yet, then the action is easy -- simply add
    // the cell to the map representation.  There's not nedd to handle cases with overlapping
    // reads and writes, because we're processing reads and writes one byte at a time.
    if (!evalue) {
      OINFO << "Init: addr=" << *address << " value=" << *value << LEND;
      map_mem->write_memory(address, value);
      rcursor++;
      continue;
    }

    // If the correct value is already in the map, then there's nothing to do.
    if (value->mustEqual(evalue)) {
      OINFO << "Exists: addr=" << *address << " value=" << *value << LEND;
      // Do nothing
      rcursor++;
      continue;
    }

    // At this point, the value in the map is different from the value in the list read, and
    // things get more complicated because possible aliasing has occurred.

    // If the caller wants no aliasing at all, the only thing that we need to do is mark that
    // any future references to variable representing the unknown aliases now should refer to
    // the variable that we presumed was NOT aliased.  This is incorrect reasoning, but it's
    // always convenient and sometimes a useful approximation of program behavior.
    if (max_aliases == 0) {
      // This may be where we should make an entry in the substitution map to mark that we've
      // changed our view of the world.

      // substition_map[evalue] = value;
      OINFO << "Alias ignore: addr=" << *address << " value=" << *value << LEND;

      rcursor++;
      continue;
    }

    // If the caller just wants us to keep the single unknown variable representing the
    // possible aliases, we simply write it into the map and move on.
    if (max_aliases == 1) {
      OINFO << "Alias accept: addr=" << *address << " value=" << *value << LEND;
      map_mem->write_memory(address, value);
      rcursor++;
      continue;
    }

    // Otherwise the caller wants us to look for aliases and so something with them.

    // Our goal is to accumulate an unordered list of addreses that may alias this address.
    ValueSet aliases;

    // Did we find maximum number of aliases before finding an entry that must alias?
    bool tired = false;

    // We need to walk backwards through the cells that have already been written looking for
    // cells that may alias the current cell.
    //CellList::const_iterator cursor;
    auto acursor = std::reverse_iterator<decltype (rcursor)>(rcursor);
    // We shouldn't actually reach the beginning of the list, because we already know there's a
    // different value in the memory map, but obviously we should check for that anyway.
    while (acursor.base() != cells.rbegin()) {
      const MemoryCellPtr& acell = *acursor;
      // If the cell may have aliased the current cell, then add it to the list of aliases.
      if (cell->mayAlias(acell, ops)) {
        const SymbolicValuePtr& alias_addr = SymbolicValue::promote(acell->address());
        aliases.insert(alias_addr);
        // If it also must have aliased our current cell, then we're done looking for aliases.
        if (cell->mustAlias(acell, ops)) break;
        // Once we've found the maximum number of aliases, sstop looking.
        if ((max_aliases - 1) == aliases.size()) {
          tired = true;
          break;
        }
      }
      acursor++;
    }

    OINFO << "Found " << aliases.size() << " aliases." << LEND;

    // We should always find aliases, but if we didn't let's not crash.  Perhaps the
    // constraints interacted in some complex way to eliminate the possible alias?
    if (aliases.size() < 1) {
      GERROR << "No aliases found for " << *address << LEND;
      OINFO << "Alias error: addr=" << *address << " value=" << *value << LEND;
      map_mem->write_memory(address, value);
      rcursor++;
      continue;
    }

    // At this point, we've either found all of the addresses that may alias the current cell,
    // or we reached the maximum number of aliases that the caller requested.

    // If the caller wants us to just give up when we reach the maximum number of aliases, we
    // write the single unknown variable representing the possible aliases and move on.
    if (tired && give_up) {
      OINFO << "Alias tired: addr=" << *address << " value=" << *value << LEND;
      map_mem->write_memory(address, value);
      rcursor++;
      continue;
    }

    // The current cell is always one of the possible aliases, and we always want it to be the
    // innermost value.  Begin constructing the "fancy" aliasing term.
    SymbolicValuePtr fancy = value;

    // For each possible alias construct an ITE term that correctly constrains the values.
    for (const SymbolicValuePtr& alias: aliases) {
      // We know what the value of the alias is by reading the map.
      const SymbolicValuePtr& avalue = map_mem->read_memory(alias, 8);
      assert(avalue); // Should never happen.
      fancy = create_equality(address, alias, avalue, fancy);
    }

    OINFO << "Alias fancy: addr=" << *address << " value=" << *fancy << LEND;
    // This is the moment we've all been waiting for -- write the fancy value into the map.
    map_mem->write_memory(address, fancy);
    // And then process the next cell in the memory list...
    rcursor++;
  }

  return map_mem;
}


} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
