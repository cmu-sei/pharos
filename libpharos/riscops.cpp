// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#include "riscops.hpp"
#include "masm.hpp"
#include "descriptors.hpp"

// This class was copied from Robb's code where it was private.  Minor changes were made to
// eliminate warnings about shadowed variables, but it is otherwise unchanged.  Once the
// location-based definers stuff is sorted out, this class can be removed.
class PartialDisableUsedef {
private:
  bool saved_value;
  SymRiscOperators *rops;
public:
  PartialDisableUsedef(SymRiscOperators *pops): saved_value(false), rops(pops) {
    saved_value = rops->getset_omit_cur_insn(true);
  }
  ~PartialDisableUsedef() {
    rops->getset_omit_cur_insn(saved_value);
  }
};


// This global variable gives us a way to read/write memory without having to carry around a
// SymbolicRiscOperatorsPtr everywhere.  And it doesn't consume dozen of gigabytes of RAM. :-)
SymbolicRiscOperatorsPtr global_rops;

// A helper function to create a symbolic emulation environment.
SymbolicRiscOperatorsPtr make_risc_ops() {
  SymbolicValuePtr stupid_svalue = SymbolicValue::instance();
  SymbolicMemoryStatePtr stupid_mem = SymbolicMemoryState::instance(stupid_svalue, stupid_svalue);
  const RegisterDictionary* regdict = RegisterDictionary::dictionary_pentium4();
  SymbolicRegisterStatePtr stupid_regs = SymbolicRegisterState::instance(stupid_svalue, regdict);
  SymbolicStatePtr stupid_state = SymbolicState::instance(stupid_regs, stupid_mem);
  return SymbolicRiscOperators::instance(stupid_state);
}

//==============================================================================================
// Our extensions to the interface
//==============================================================================================

// Things that Cory thinks should be proxied through to the memory and register classes.
SymbolicValuePtr SymbolicRiscOperators::read_register(const RegisterDescriptor &reg) {
  STRACE << "RiscOps::read_register(): " << LEND;
  return get_sstate()->read_register(reg);
}

//==============================================================================================
// Starting instructions, reading & writing registers (official interface).
//==============================================================================================

// Overridden to force IP to correct value, and clear assorted vectors...
// And this isn't even remotely in this class anymore.  It's in Disassembly!
// Cory says these comments are old, and this should get cleaned up?
void SymbolicRiscOperators::startInstruction(SgAsmInstruction *insn) {
  STRACE << "============================================================================" << LEND;
  STRACE << "RiscOps::startInstruction(): " << debug_instruction(insn) << LEND;
  STRACE << "============================================================================" << LEND;

  // Clear our vectors.
  reads.clear();
  writes.clear();

  // Force IP to a value that will not cause assertions...
  //state->registers->ip = ValueType<32>(insn->get_address());

  // Do the standard parent behavior...
  RiscOperators::startInstruction(insn);
}

BaseSValuePtr SymbolicRiscOperators::readRegister(const RegisterDescriptor &reg) {
  assert(state!=NULL);
  PartialDisableUsedef disabled(this);
  BaseSValuePtr bv = get_sstate()->readRegister(reg, this);

  SymbolicValuePtr sv = SymbolicValue::promote(bv);
  if (!(reg == *EIP)) {
    SymbolicValuePtr svc = sv->scopy();
    reads.push_back(AbstractAccess(true, reg, svc, get_sstate()));
    STRACE << "RiscOps::readRegister() reg=" << unparseX86Register(reg, NULL)
           << " value=" << *sv << LEND;
  }
  return bv;
}

void SymbolicRiscOperators::writeRegister(const RegisterDescriptor &reg, const BaseSValuePtr &a) {
  //STRACE << "RiscOps::writeRegister() reg=" << unparseX86Register(reg, NULL)
  // << " value=" << *a << LEND;
  assert(state!=NULL);

  // This bit width test is to avoid a problem where the ROSE code asserts when then sizes
  // don't match.  ROSE should be doing something to automatically resize these operands so
  // that they do match, but in the mean time, we shouldn't ever call upstream code with
  // mismatched sizes.  Not knowing what else to do I'm just going to log the error and return.
  if (a->get_width() != reg.get_nbits()) {
    SWARN << "Mismatched register write sizes in: " << debug_instruction(cur_insn) << LEND;
    return;
  }

  SymbolicValuePtr sva = SymbolicValue::promote(a)->scopy();
  // Automatic downgrade of sva to Base?
  get_sstate()->writeRegister(reg, sva, this);

  // Beginning of code copied inappropriately from RiscOperators::writeRegister().
  // We've made a copy of this code because we need to comment out the call to
  // PartialDisableUsedef() because it prevents registers moves from showing up in the
  // definers list, which we appear to need for ObjDigger to function correctly.

  // We ought to do this:
  //SymRiscOperators::writeRegister(reg, a);

  // Instead we do this:
  BaseSValuePtr ra = BaseSValue::promote(a->copy());
  // Here's the change from standard ROSE!!!!
  //PartialDisableUsedef du(this);
  BaseRiscOperators::writeRegister(reg, ra);

  // Update register properties and writer info.
  RegisterStateGenericPtr regs = RegisterStateGeneric::promote(get_state()->get_register_state());
  SgAsmInstruction *insn = get_insn();
  if (insn) {
    switch (computingRegisterWriters()) {
    case TRACK_NO_WRITERS:
      break;
    case TRACK_LATEST_WRITER:
      regs->setWriters(reg, insn->get_address());
      break;
    case TRACK_ALL_WRITERS:
      regs->insertWriters(reg, insn->get_address());
      break;
    }
    regs->updateWriteProperties(reg, (insn ? Semantics2::BaseSemantics::IO_WRITE : Semantics2::BaseSemantics::IO_INIT));
  }
  // End of code copied inappropriately from RiscOperators::writeRegister()

  // rbv, srbv, etc. is needless sanity checking! Remove when done debugging.
  BaseSValuePtr rbv = get_sstate()->readRegister(reg, this);
  SymbolicValuePtr srbv = SymbolicValue::promote(rbv);
  //STRACE << "RiscOps::writeRegister() srbv=" << *srbv << LEND;

  // This is a hack related to the PartialDisableUseDef mentioned above, that is currently
  // required to get correct output from ObjDigger.  As we develop a real solution for
  // location-based definers, we shouldn't need this anymore.
  srbv->defined_by(cur_insn);
  // mwd: defined_by() no longer sets the modifiers
  srbv->add_modifier(cur_insn);

  // Slightly hackish, but something Cory thinks we should keep for simplicity.
  if (!(reg == *EIP)) {
    SymbolicValuePtr srbvc = srbv->scopy();
    writes.push_back(AbstractAccess(false, reg, srbvc, get_sstate()));
    STRACE << "RiscOps::writeRegister() reg=" << unparseX86Register(reg, NULL)
           << " value=" << *srbvc << LEND;
  }
}

BaseSValuePtr SymbolicRiscOperators::readMemory(const RegisterDescriptor &segreg,
                                                const BaseSValuePtr &addr,
                                                const BaseSValuePtr &dflt,
                                                const BaseSValuePtr &cond) {
  PartialDisableUsedef disabled(this);
  SymbolicValuePtr saddr = SymbolicValue::promote(addr)->scopy();
  SymbolicValuePtr retval;

  SymbolicValuePtr sdflt = SymbolicValue::promote(dflt);
  // If the address is invalid, then the memory at that address is invald.  It's unclear how
  // naughty we're being here with respect to the immutabiltiy of dflt.  As far as Cory knows,
  // it was always a newly constructed undefined just for this read...
  if (saddr->is_incomplete()) {

#ifdef CUSTOM_ROSE
    // This approach still requires a small change to ROSE to work.  It's the more complete
    // solution because it actually uses the default value passed to us by the caller.
    // Unfortunately, it also requires a custom constructor on LeafNode that we added.
    sdflt->set_incomplete(true);
#else
    // In practice however, the default values passed to us are pretty much always LeafNode
    // variables that nobody care about, so it's just as valid to replace it with a value of
    // our own that has the correct flag bits set.
    size_t nbits = sdflt->get_width();
    TreeNodePtr tn = LeafNode::createVariable(nbits, "", INCOMPLETE);
    sdflt->set_expression(tn);
#endif
    SDEBUG << "Marking as incomplete read of incomplete address: " << *saddr
           << " default value: " << *sdflt << LEND;
  }

  // Check for reads to constant addresses.  We might want to kludge up several things here,
  // including reads of imports and reads of constant initialized data.  This has to be in
  // RiscOps and not the MemoryState because we want to handle full size (not byte size) reads.
  BOOST_FOREACH(const TreeNodePtr& tn, saddr->get_possible_values()) {
    if (tn->isNumber()) {
      rose_addr_t known_addr = tn->toInt();
      ImportDescriptor *id = global_descriptor_set->get_import(known_addr);
      // Handle the special case of reading an import descriptor!  Let's mock this up so that
      // we return the value at the address, we return the address itself.  That's the
      // convention that we use to signal whatever value was filled in by the loader at runtime
      // for address of the imported function.
      if (id != NULL) {
        SDEBUG << "Memory read of " << addr_str(known_addr)
               << " reads import " << id->get_long_name() << LEND;
        if (cur_insn != NULL) {
          SDEBUG << "The memory read ocurred in insn: " << debug_instruction(cur_insn) << LEND;
          CallDescriptor* cd = global_descriptor_set->get_call(cur_insn->get_address());
          if (cd != NULL) {
            SDEBUG << "Added target " << *id << " to " << *cd << LEND;
            cd->add_import_target(id);
          }
        }

        // Initialize the memory state with the fixed variable associated defined by the loader
        // and stored in the import descriptor.
        SDEBUG << "Initialized with " << *(id->get_loader_variable()) << LEND;
        SymbolicValuePtr sv = SymbolicValue::constant_instance(tn->nBits(), known_addr);
        initialize_memory(sv, id->get_loader_variable());
      }
    }
  }

  // Call the stock ROSE readMemory()!  Hooray!
  retval = SymbolicValue::promote(RiscOperators::readMemory(segreg, addr, sdflt, cond));
  // This is what's really still needed as a modification to the standard readMemory().
  retval->add_defining_instructions(cur_insn);

  STRACE << "RiscOps::readMemory() addr=" << *saddr << LEND;
  STRACE << "RiscOps::readMemory() retval=" << *retval << LEND;
  SymbolicValuePtr srv = retval->scopy();

  // We have to do some serious naughtiness to get around the fact that ROSE declared this
  // method as const, thus preventing us from updating our records of memory reads...  This
  // should probably be loosened up in ROSE.
  AbstractAccessVector *m_read = const_cast<AbstractAccessVector *> (&reads);
  size_t nbits = sdflt->get_width();
  (*m_read).push_back(AbstractAccess(true, saddr, nbits, srv, get_sstate()));

  return retval;
}

typedef Semantics2::BaseSemantics::MemoryCellList MemoryCellList;
typedef Semantics2::BaseSemantics::MemoryCellListPtr MemoryCellListPtr;

// Beginning of code copied inappropriately from RiscOperators::writeMemory() We've made a copy
// of this code because we need to comment out the call to PartialDisableUsedef() because it
// prevents register moves from showing up in the definers list, which we appear to need for
// ObjDigger to function correctly.  On January 22, 2016, this copy was functionally identical
// to the stock ROSE implementation EXCEPT the PartialDisableUsedef)() call.
void SymbolicRiscOperators::writeMemory_helper(UNUSED const RegisterDescriptor &segreg,
                                               const BaseSValuePtr &address,
                                               const BaseSValuePtr &value_,
                                               const BaseSValuePtr &condition) {

  // SEI observes that condition is used now!
  ASSERT_require(1==condition->get_width()); // FIXME: condition is not used
  if (condition->is_number() && !condition->get_number())
    return;
  if (address->isBottom())
    return;
  BaseSValuePtr value = BaseSValue::promote(value_->copy());

  // There's SEI confusion/disagreement about whether this should be commented out or not.
  // The Pharos code has historically required that it be commented out.
  //PartialDisableUsedef du(this);

  size_t nbits = value->get_width();
  ASSERT_require(0 == nbits % 8);
  size_t nbytes = nbits/8;
  BaseMemoryStatePtr mem = get_state()->get_memory_state();
  for (size_t bytenum=0; bytenum<nbytes; ++bytenum) {
    size_t byteOffset = 0;
    if (1 == nbytes) {
      // void
    } else if (ByteOrder::ORDER_MSB == mem->get_byteOrder()) {
      byteOffset = nbytes - (bytenum+1);
    } else if (ByteOrder::ORDER_LSB == mem->get_byteOrder()) {
      byteOffset = bytenum;
    } else {
      // See BaseSemantics::MemoryState::set_byteOrder SEI modified to runtime_error
      throw std::runtime_error("multi-byte write with memory having unspecified byte order");
    }

    BaseSValuePtr byte_value = extract(value, 8*byteOffset, 8*byteOffset+8);
    BaseSValuePtr byte_addr = add(address, number_(address->get_width(), bytenum));
    state->writeMemory(byte_addr, byte_value, this, this);

    // Update the latest writer info if we have a current instruction and the memory state
    // supports it.
    if (computingMemoryWriters() != TRACK_NO_WRITERS) {
      if (SgAsmInstruction *insn = get_insn()) {
        if (MemoryCellListPtr cellList =
            boost::dynamic_pointer_cast<MemoryCellList>(mem)) {
          if (MemoryCellPtr cell = cellList->latestWrittenCell()) {
            switch (computingMemoryWriters()) {
            case TRACK_NO_WRITERS:
              break;
            case TRACK_LATEST_WRITER:
              cell->setWriter(insn->get_address());
              break;
            case TRACK_ALL_WRITERS:
              cell->insertWriter(insn->get_address());
              break;
            }
          }
        } else if (BaseMemoryCellMapPtr cellMap =
                   boost::dynamic_pointer_cast<BaseMemoryCellMap>(mem)) {
          if (MemoryCellPtr cell = cellMap->latestWrittenCell()) {
            switch (computingMemoryWriters()) {
            case TRACK_NO_WRITERS:
              break;
            case TRACK_LATEST_WRITER:
              cell->setWriter(insn->get_address());
              break;
            case TRACK_ALL_WRITERS:
              cell->insertWriter(insn->get_address());
              break;
            }
          }
        }
      }
    }
  }
}

void SymbolicRiscOperators::writeMemory(UNUSED const RegisterDescriptor &segreg,
                                        const BaseSValuePtr &addr,
                                        const BaseSValuePtr &data,
                                        const BaseSValuePtr &cond) {
  // Debugging
  STRACE << "SRiscOp::writeMemory() addr=" << *addr << LEND;
  STRACE << "SRiscOp::writeMemory() data=" << *data << LEND;
  SymbolicValuePtr saddr = SymbolicValue::promote(addr)->scopy();
  SymbolicValuePtr sdata = SymbolicValue::promote(data)->scopy();
  STRACE << "SRiscOp::writeMemory() saddr=" << *saddr << LEND;
  STRACE << "SRiscOp::writeMemory() sdata=" << *sdata << LEND;

  // Tested lightly with the few cases that Cory knew of (which were really not import
  // overwrites).  This makes more sense here, but it might actually be cleaner back in defuse
  // where it was before Cory moved it here.
  BOOST_FOREACH(const TreeNodePtr& tn, saddr->get_possible_values()) {
    if (tn->isNumber()) {
      rose_addr_t known_addr = tn->toInt();
      ImportDescriptor *id = global_descriptor_set->get_import(known_addr);
      if (id != NULL) {
        SWARN << "Instruction " << debug_instruction(cur_insn) << " overwrites import "
              << id->get_long_name() << " at address " << addr_str(known_addr) << LEND;
      }
    }
  }

#if 1
  // This is what currently works.
  writeMemory_helper(segreg, addr, data, cond);
#else
  // This how we ought to do it.
  RiscOperators::writeMemory(segreg, addr, data, cond);
#endif

  // This one line is the call to RiscOperators::writeMemory that we ought to be using...
  // RiscOperators::writeMemory(segreg, addr, data, cond);
  writes.push_back(AbstractAccess(false, saddr, data->get_width(), sdata, get_sstate()));
}

// This API invented by Cory to initialize memory with a known symbolic value rather than a new
// random value.  It's currently used primarily by the imports in registers code from
// readMemory above.  It was partially copied from Robb's implementation of
// RiscOps::readMemory(), and a better implementation would be a version of readMemory() that
// took the default value as an optional parameter. That was a little more complicated for Cory
// to figure out.
void SymbolicRiscOperators::initialize_memory(const SymbolicValuePtr &addr,
                                              const SymbolicValuePtr &data) {
  STRACE << "SymbolicRiscOp::initialize_memory() addr=" << *addr << LEND;
  STRACE << "SymbolicRiscOp::initialize_memory() data=" << *data << LEND;

  // Read the bytes in little endian order and concatenate them together. InsnSemanticsExpr
  // will simplify the expression so that reading after writing a multi-byte value will return
  // the original value written rather than a concatenation of byte extractions.

  size_t nbits = data->get_width();
  assert(8==nbits || 16==nbits || 32==nbits);
  size_t nbytes = nbits/8;
  SymbolicStatePtr sstate = SymbolicState::promote(get_state());
  SymbolicMemoryStatePtr mem = SymbolicMemoryState::promote(sstate->get_memory_state());
  for (size_t bytenum=0; bytenum<nbits/8; ++bytenum) {
    size_t byteOffset = ByteOrder::ORDER_MSB==mem->get_byteOrder() ? nbytes-(bytenum+1) : bytenum;
    SymbolicValuePtr byte_dflt = SymbolicValue::promote(extract(data, 8*byteOffset, 8*byteOffset+8));
    SymbolicValuePtr byte_addr = SymbolicValue::promote(add(addr, number_(addr->get_width(), bytenum)));
    STRACE << "SymbolicRiscOp::initialize_memory() byte_addr=" << *byte_addr << LEND;
    STRACE << "SymbolicRiscOp::initialize_memory() byte_data=" << *byte_dflt << LEND;
    // Read (and possibly create), but discard return value.
    //SymbolicStatePtr sstate = SymbolicStatePtr::promote(state);
    state->readMemory(byte_addr, byte_dflt, this, this);
  }
}

// CERT needs a rational interface read memory. :-) This API is not called from anywhere in
// Robb's infrastructure, but instead called when the symbolic state computation is complete.
// This routines needs to do the same work for reassembling multiple bytes into a return value,
// but instead of creating new values in the state, it returns an invalid symbolic value to
// indicate that the value doesn't exist.  Yes, this another copy of the code from ROSE.  :-(
// This one is hacked so that we read only _read_ memory without writing to it.
SymbolicValuePtr SymbolicRiscOperators::read_memory(const SymbolicMemoryState* mem,
                                                    const SymbolicValuePtr &address,
                                                    const size_t nbits) {
  GDEBUG << "RiscOps::read_memory(address, " << nbits << "):" << LEND;
  GDEBUG << "RiscOps::read_memory() address = " << *address << LEND;

  assert(0 == nbits % 8);

  // Read the bytes and concatenate them together. InsnSemanticsExpr will simplify the
  // expression so that reading after writing a multi-byte value will return the original value
  // written rather than a concatenation of byte extractions.

  SymbolicValuePtr retval;
  InsnSet defs;
  // SEI added the mods set.
  InsnSet mods;

  // SEI upgraded to our SymbolicState and SymbolicMemoryState here...
  for (size_t bytenum=0; bytenum<nbits/8; ++bytenum) {
    BaseSValuePtr byte_addr = add(address, number_(address->get_width(), bytenum));
    // SEI changed the type of byte_value.
    STRACE << "Reading bytenum: " << bytenum << " at: " << *address << LEND;

    const MemoryCellPtr cell = mem->findCell(SymbolicValue::promote(byte_addr));
    // If we can't find one of the bytes required to assemble the return value, then signal our
    // failure by returning an invalid value.
    if (!cell) return SymbolicValuePtr();
    SymbolicValuePtr byte_value = SymbolicValue::promote(cell->get_value());
    // Not possible?
    if (byte_value->is_invalid()) return SymbolicValuePtr();

    //SValuePtr byte_value = SValue::promote(state->readMemory(byte_addr, byte_dflt, this, this));
    if (0==bytenum) {
      retval = byte_value;
    } else if (ByteOrder::ORDER_MSB==mem->get_byteOrder()) {
      retval = SymbolicValue::promote(concat(byte_value, retval));
    } else {
      retval = SymbolicValue::promote(concat(retval, byte_value));
    }
    const InsnSet &definers = byte_value->get_defining_instructions();
    defs.insert(definers.begin(), definers.end());
    //const InsnSet &modifiers = byte_value->get_modifiers(); // copying modifiers in read_memory()
    //BOOST_FOREACH(const SgAsmInstruction* i, modifiers) {
    //  STRACE << "Adding modifier: " << debug_instruction(i) << LEND;
    //}
    //mods.insert(modifiers.begin(), modifiers.end());  // in our read_memory implementation!
  }

  assert(retval!=NULL && retval->get_width()==nbits);
  BOOST_FOREACH(SgAsmInstruction* i, defs) {
    retval->add_defining_instructions(i);
  }
  retval->set_modifiers(mods);
  GDEBUG << "RiscOps::read_memory() retval = " << *retval << LEND;
  return retval;
}

//==============================================================================================
// RISC Operators
//==============================================================================================

void SymbolicRiscOperators::interrupt(int majr, int minr) {
  STRACE << "Ignoring interrupt: major=" << majr << " minor=" << minr << LEND;
}

BaseSValuePtr SymbolicRiscOperators::or_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::or_(a_, b_));

  // Any register OR'd with 0xFFFFFFFF is really just "mov reg, 0xFFFFFFFF"
  if (a_->is_number() && 0xFFFFFFFF == a_->get_number()) {
    retval->set_modifiers(a->get_modifiers()); // maintainence RiscOps::or_();
  }
  else if (b_->is_number() && 0xFFFFFFFF == b_->get_number()) {
    retval->set_modifiers(b->get_modifiers()); // maintainence RiscOps::or_();
  }

  if (STRACE) {
    STRACE << "RiscOps::or() a=" << *a << LEND;
    STRACE << "RiscOps::or() b=" << *b << LEND;
    STRACE << "RiscOps::or() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::concat(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::concat(a_, b_));
  // For the concatenation operator, it's not good enough to rely on the standard call to
  // defined_by().  We need to merge the modifiers from both parameters.  When concat is used
  // to join memory bytes (the most common case even if it's not the only one), failure to
  // merge the modifiers results in writes and reads from memory losing those modifiers.
  retval->set_modifiers(a->get_modifiers()); // maintainence RiscOps::concat();
  retval->add_modifiers(b->get_modifiers()); // maintainence RiscOps::concat();
  if (STRACE) {
    STRACE << "RiscOps::concat() a=" << *a << LEND;
    STRACE << "RiscOps::concat() b=" << *b << LEND;
    STRACE << "RiscOps::concat() r=" << *retval << LEND;
  }
  return retval;
}

//==============================================================================================
// Unused RISC Operators
//==============================================================================================

// The RISC Operators from here until the end of the file are not modified from the standard
// ROSE implementation.  We used to override all of these methods but no longer need to do
// so. :-) It's a non-zero amount of coding effort to promote all of the types, call the parent
// method implementation, and emit the STRACE logging messages, so rather than removing the
// code completely, I've simply ifdef'd it out.

// mwd: Re-enabled to add "add_modifer" appropriately, as the default versions in rose no
// longer use defined_by() which previously handled this.  This will disappear (and the #if
// will go back to 0) once we ditch modifiers completely.

#if 1
BaseSValuePtr SymbolicRiscOperators::boolean_(bool b) {
  BaseSValuePtr retval = RiscOperators::boolean_(b);
  SymbolicValuePtr sretval = SymbolicValue::promote(retval);
  if (!omit_cur_insn) {
    sretval->add_modifier(get_insn());
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::number_(size_t nbits, uint64_t value) {
  BaseSValuePtr retval = RiscOperators::number_(nbits, value);
  SymbolicValuePtr sretval = SymbolicValue::promote(retval);
  if (!omit_cur_insn) {
    sretval->add_modifier(get_insn());
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::and_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::and_(a_, b_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::and() a=" << *a << LEND;
    STRACE << "RiscOps::and() b=" << *b << LEND;
    STRACE << "RiscOps::and() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::xor_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::xor_(a_, b_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::xor() a=" << *a << LEND;
    STRACE << "RiscOps::xor() b=" << *b << LEND;
    STRACE << "RiscOps::xor() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::invert(const BaseSValuePtr &a_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::invert(a_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::invert() a=" << *a << LEND;
    STRACE << "RiscOps::invert() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::extract(const BaseSValuePtr &a_, size_t begin_bit, size_t end_bit) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::extract(a_, begin_bit, end_bit));
  if (!omit_cur_insn && retval->get_width() != a->get_width()) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::extract() b=" << begin_bit << " e=" << end_bit << " a=" << *a << LEND;
    STRACE << "RiscOps::extract() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::leastSignificantSetBit(const BaseSValuePtr &a_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::leastSignificantSetBit(a_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::leastSignificantBit() a=" << *a << LEND;
    STRACE << "RiscOps::leastSignificantBit() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::mostSignificantSetBit(const BaseSValuePtr &a_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::mostSignificantSetBit(a_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::mostSignificantBit() a=" << *a << LEND;
    STRACE << "RiscOps::mostSignificantBit() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::rotateLeft(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr sa = SymbolicValue::promote(sa_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::rotateLeft(a_, sa_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::rotateLeft() a=" << *a << LEND;
    STRACE << "RiscOps::rotateLeft() sa=" << *sa << LEND;
    STRACE << "RiscOps::rotateLeft() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::rotateRight(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr sa = SymbolicValue::promote(sa_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::rotateRight(a_, sa_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::rotateRight() a=" << *a << LEND;
    STRACE << "RiscOps::rotateRight() sa=" << *sa << LEND;
    STRACE << "RiscOps::rotateRight() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::shiftLeft(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr sa = SymbolicValue::promote(sa_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::shiftLeft(a_, sa_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::shiftLeft() a=" << *a << LEND;
    STRACE << "RiscOps::shiftLeft() sa=" << *sa << LEND;
    STRACE << "RiscOps::shiftLeft() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::shiftRight(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr sa = SymbolicValue::promote(sa_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::shiftRight(a_, sa_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::shiftRight() a=" << *a << LEND;
    STRACE << "RiscOps::shiftRight() sa=" << *sa << LEND;
    STRACE << "RiscOps::shiftRight() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::shiftRightArithmetic(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr sa = SymbolicValue::promote(sa_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::shiftRightArithmetic(a_, sa_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::shiftRightArithmetic() a=" << *a << LEND;
    STRACE << "RiscOps::shiftRightArithmetic() sa=" << *sa << LEND;
    STRACE << "RiscOps::shiftRightArithmetic() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::equalToZero(const BaseSValuePtr &a_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::equalToZero(a_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::equalToZero() a=" << *a << LEND;
    STRACE << "RiscOps::equalToZero() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::ite(const BaseSValuePtr &sel_, const BaseSValuePtr &a_,
                                         const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr sel = SymbolicValue::promote(sel_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::ite(sel_, a_, b_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::ite() sel=" << *sel << LEND;
    STRACE << "RiscOps::ite() a=" << *a << LEND;
    STRACE << "RiscOps::ite() b=" << *b << LEND;
    STRACE << "RiscOps::ite() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::unsignedExtend(const BaseSValuePtr &a_, size_t new_width) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::unsignedExtend(a_, new_width));
  if (!omit_cur_insn && retval->get_width() != a->get_width()) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::unsignedExtend() a=" << *a << LEND;
    STRACE << "RiscOps::unsignedExtend() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::signExtend(const BaseSValuePtr &a_, size_t new_width) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::signExtend(a_, new_width));
  if (!omit_cur_insn && retval->get_width() != a->get_width()) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::signExtend() a=" << *a << LEND;
    STRACE << "RiscOps::signExtend() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::add(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::add(a_, b_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::add() a=" << *a << LEND;
    STRACE << "RiscOps::add() b=" << *b << LEND;
    STRACE << "RiscOps::add() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::addWithCarries(
  const BaseSValuePtr &a_, const BaseSValuePtr &b_,
  const BaseSValuePtr &c_, BaseSValuePtr &carry_out)
{
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr c = SymbolicValue::promote(c_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::addWithCarries(a_, b_, c_, carry_out));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::addWithCarries() a=" << *a << LEND;
    STRACE << "RiscOps::addWithCarries() b=" << *b << LEND;
    STRACE << "RiscOps::addWithCarries() c=" << *c << LEND;
    STRACE << "RiscOps::addWithCarries() o=" << *carry_out << LEND;
    STRACE << "RiscOps::addWithCarries() r=" << *retval << LEND;
  }
  return retval;
};

BaseSValuePtr SymbolicRiscOperators::negate(const BaseSValuePtr &a_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::negate(a_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::negate() a=" << *a << LEND;
    STRACE << "RiscOps::negate() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::signedDivide(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::signedDivide(a_, b_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::signedDivide() a=" << *a << LEND;
    STRACE << "RiscOps::signedDivide() b=" << *b << LEND;
    STRACE << "RiscOps::signedDivide() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::signedModulo(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::signedModulo(a_, b_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::signedModulo() a=" << *a << LEND;
    STRACE << "RiscOps::signedModulo() b=" << *b << LEND;
    STRACE << "RiscOps::signedModulo() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::signedMultiply(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::signedMultiply(a_, b_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::signedMultiply() a=" << *a << LEND;
    STRACE << "RiscOps::signedMultiply() b=" << *b << LEND;
    STRACE << "RiscOps::signedMultiply() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::unsignedDivide(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::unsignedDivide(a_, b_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::unsignedDivide() a=" << *a << LEND;
    STRACE << "RiscOps::unsignedDivide() b=" << *b << LEND;
    STRACE << "RiscOps::unsignedDivide() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::unsignedModulo(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::unsignedModulo(a_, b_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::unsignedModulo() a=" << *a << LEND;
    STRACE << "RiscOps::unsignedModulo() b=" << *b << LEND;
    STRACE << "RiscOps::unsignedModulo() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::unsignedMultiply(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(RiscOperators::unsignedMultiply(a_, b_));
  if (!omit_cur_insn) {
    retval->add_modifier(cur_insn);
  }
  if (STRACE) {
    STRACE << "RiscOps::unsignedMultiply() a=" << *a << LEND;
    STRACE << "RiscOps::unsignedMultiply() b=" << *b << LEND;
    STRACE << "RiscOps::unsignedMultiply() r=" << *retval << LEND;
  }
  return retval;
}
#endif

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
