// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include "riscops.hpp"
#include "masm.hpp"
#include "descriptors.hpp"

namespace pharos {

// This global variable gives us a way to read/write memory without having to carry around a
// SymbolicRiscOperatorsPtr everywhere.  And it doesn't consume dozen of gigabytes of RAM. :-)
SymbolicRiscOperatorsPtr global_rops;

SymbolicRiscOperators::SymbolicRiscOperators(
  DescriptorSet const & ds_,
  const SymbolicValuePtr& aprotoval_,
  const SmtSolverPtr & asolver_,
  Callbacks * callbacks_)
  : SymRiscOperators(aprotoval_, asolver_), ds(ds_), callbacks(callbacks_)
{
  name("CERT");
  computingDefiners(TRACK_LATEST_DEFINER);
  computingRegisterWriters(TRACK_LATEST_WRITER);
  computingMemoryWriters(TRACK_LATEST_WRITER);
  EIP = ds.get_ip_reg();
}

// Standard ROSE constructor must take custom types to ensure promotion.
SymbolicRiscOperators::SymbolicRiscOperators(
  DescriptorSet const & ds_,
  const SymbolicStatePtr& state_,
  const SmtSolverPtr & asolver_,
  Callbacks * callbacks_)
  : SymRiscOperators(state_, asolver_), ds(ds_), callbacks(callbacks_)
{
  name("CERT");
  computingDefiners(TRACK_LATEST_DEFINER);
  computingRegisterWriters(TRACK_LATEST_WRITER);
  computingMemoryWriters(TRACK_LATEST_WRITER);
  EIP = ds.get_ip_reg();
}

SymbolicRiscOperatorsPtr SymbolicRiscOperators::instance(
  DescriptorSet const & ds_,
  Callbacks * callbacks_,
  const SmtSolverPtr & solver_) {

  SymbolicValuePtr proto = SymbolicValue::instance();
  const RegisterDictionary& regdict = ds_.get_regdict();
  SymbolicRegisterStatePtr rstate = SymbolicRegisterState::instance(proto, &regdict);
  SymbolicMemoryMapStatePtr mstate = SymbolicMemoryMapState::instance();
  SymbolicStatePtr state = SymbolicState::instance(rstate, mstate);
  return instance(ds_, state, callbacks_, solver_);
}

//==============================================================================================
// Our extensions to the interface
//==============================================================================================

// Things that Cory thinks should be proxied through to the memory and register classes.
SymbolicValuePtr SymbolicRiscOperators::read_register(RegisterDescriptor reg) {
  STRACE << "RiscOps::read_register(): " << LEND;
  return get_sstate()->read_register(reg);
}

//==============================================================================================
// Starting instructions, reading & writing registers (official interface).
//==============================================================================================

// Overridden to clear our abstract access vectors.
void SymbolicRiscOperators::startInstruction(SgAsmInstruction *insn) {
  STRACE << "============================================================================" << LEND;
  STRACE << "RiscOps::startInstruction(): " << debug_instruction(insn) << LEND;
  STRACE << "============================================================================" << LEND;

  // Clear our vectors.
  insn_accesses.clear();

  // Do the standard parent behavior...
  SymRiscOperators::startInstruction(insn);
}

BaseSValuePtr SymbolicRiscOperators::readRegister(
  RegisterDescriptor reg, const BaseSValuePtr & dflt)
{
  STRACE << "RiscOps::readRegister() reg=" << unparseX86Register(reg, NULL) << LEND;

  // Call the standard ROSE implementation of readRegister().
  BaseSValuePtr bv = SymRiscOperators::readRegister(reg, dflt);

  // Create an abstract access recording this register write.  We exclude the EIP register to
  // reduce memory usage, and make it easier to find the significant register reads and writes.
  if (!(reg == EIP)) {

    TreeNodePtr tnp = SymbolicValue::promote(bv)->get_expression();
    if (tnp) {

      TreeNode * t = &*tnp;
      unique_treenodes.emplace(t, tnp);

    }
    // We make a copy because this value isn't supposed to change ever again?  Really needed?
    SymbolicValuePtr svalue = SymbolicValue::promote(bv)->scopy();
    insn_accesses.push_back(AbstractAccess(ds, true, reg, svalue, get_sstate()));
    STRACE << "RiscOps::readRegister() reg=" << unparseX86Register(reg, NULL)
           << " value=" << *svalue << LEND;
  }
  return bv;
}

void SymbolicRiscOperators::writeRegister(RegisterDescriptor reg, const BaseSValuePtr &v) {
  STRACE << "RiscOps::writeRegister() reg=" << unparseX86Register(reg, NULL) << " value=" << *v << LEND;

  // Call the standard ROSE implementation of writeRegister().
  SymRiscOperators::writeRegister(reg, v);

  // Create an abstract access recording this register write.  We exclude the EIP register to
  // reduce memory usage, and make it easier to find the significant register reads and writes.
  if (!(reg == EIP)) {

    TreeNodePtr tnp = SymbolicValue::promote(v)->get_expression();

    if (tnp) {
      TreeNode* t = &*tnp;
      unique_treenodes.emplace(t, tnp);
    }

    // We make a copy because this value isn't supposed to change ever again? Really needed?
    SymbolicValuePtr svalue = SymbolicValue::promote(v)->scopy();
    insn_accesses.push_back(AbstractAccess(ds, false, reg, svalue, get_sstate()));
    STRACE << "RiscOps::writeRegister() reg=" << unparseX86Register(reg, NULL)
           << " value=" << *svalue << LEND;
  }
}

BaseSValuePtr SymbolicRiscOperators::readMemory(RegisterDescriptor segreg,
                                                const BaseSValuePtr &addr,
                                                const BaseSValuePtr &dflt,
                                                const BaseSValuePtr &cond)
{
  SymbolicValuePtr saddr = SymbolicValue::promote(addr)->scopy();
  SymbolicValuePtr retval;

  TreeNodePtr addr_tnp = saddr->get_expression();
  if (addr_tnp) {
    TreeNode *at = &*addr_tnp;
    memory_accesses.emplace(at, addr_tnp);
    unique_treenodes.emplace(at, addr_tnp);
  }

  SymbolicValuePtr sdflt = SymbolicValue::promote(dflt);
  // If the address is invalid, then the memory at that address is invalid.  It's unclear how
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
    TreeNodePtr tn = SymbolicExpr::makeIntegerVariable(nbits, "incomplete_read", INCOMPLETE);
    sdflt->set_expression(tn);
#endif
    SDEBUG << "Marking as incomplete read of incomplete address: " << *saddr
           << " default value: " << *sdflt << LEND;
  }

  if (callbacks) {
    callbacks->readMemory(*this, saddr);
  }

  // Call the standard ROSE implementation of readRegister().
  retval = SymbolicValue::promote(SymRiscOperators::readMemory(segreg, addr, sdflt, cond));

  STRACE << "RiscOps::readMemory() addr=" << *saddr << LEND;
  STRACE << "RiscOps::readMemory() retval=" << *retval << LEND;

  // We make a copy because this value isn't supposed to change ever again?  Really needed?
  SymbolicValuePtr srv = retval->scopy();
  // Create an abstract access recording this memory read.
  size_t nbits = sdflt->get_width();
  insn_accesses.push_back(AbstractAccess(ds, true, saddr, nbits, srv, get_sstate()));

  return retval;
}

void SingleThreadedAnalysisCallbacks::readMemory(
  SymbolicRiscOperators & rops, SymbolicValuePtr saddr)
{
  // Check for reads to constant addresses.  We might want to kludge up several things here,
  // including reads of imports and reads of constant initialized data.  This has to be in
  // RiscOps and not the MemoryState because we want to handle full size (not byte size) reads.
  for (const TreeNodePtr& tn : saddr->get_possible_values()) {
    if (tn->isIntegerConstant() && tn->nBits() <= 64) {
      rose_addr_t known_addr = *tn->toUnsigned();
      ImportDescriptor *id = ds.get_rw_import(known_addr); // Added to CD
      // Handle the special case of reading an import descriptor!  Let's mock this up so that
      // we return the value at the address, we return the address itself.  That's the
      // convention that we use to signal whatever value was filled in by the loader at runtime
      // for address of the imported function.
      if (id != NULL) {
        SDEBUG << "Memory read of " << addr_str(known_addr)
               << " reads import " << id->get_long_name() << LEND;
        if (rops.currentInstruction() != NULL) {
          SDEBUG << "The memory read ocurred in insn: "
                 << debug_instruction(rops.currentInstruction()) << LEND;
          // add_import_target()
          CallDescriptor* cd = ds.get_rw_call(rops.currentInstruction()->get_address());
          if (cd != NULL) {
            SDEBUG << "Added target " << *id << " to " << *cd << LEND;
            cd->add_import_target(id);
          }
        }

        // Initialize the memory state with the fixed variable associated defined by the loader
        // and stored in the import descriptor.
        SDEBUG << "Initialized with " << *(id->get_loader_variable()) << LEND;
        SymbolicValuePtr sv = SymbolicValue::constant_instance(tn->nBits(), known_addr);
        rops.initialize_memory(sv, id->get_loader_variable());
      }
      const GlobalMemoryDescriptor* gmd = ds.get_global(known_addr);
      // this global address is not code (at least not a function)
      if (gmd != NULL) {
        SDEBUG << "Memory read of " << addr_str(known_addr)
               << " reads global " << gmd->address_string() << LEND;

        // Create a new variable for the global value. A new abstract variable is needed
        // because the global can change throughout the program
        SymbolicValuePtr sv = SymbolicValue::constant_instance(tn->nBits(), known_addr);

        // JSG is updating creation of global values to contain a set of values.
        auto global_vals = gmd->get_values();
        for (auto gv : global_vals) {
          rops.initialize_memory(sv, gv);
        }
      }
    }
  }
}

void SymbolicRiscOperators::writeMemory(UNUSED RegisterDescriptor segreg,
                                        const BaseSValuePtr &addr,
                                        const BaseSValuePtr &data,
                                        const BaseSValuePtr &cond) {

  SymbolicValuePtr saddr = SymbolicValue::promote(addr)->scopy();
  SymbolicValuePtr sdata = SymbolicValue::promote(data)->scopy();


  TreeNodePtr addr_tnp = saddr->get_expression();

  if (addr_tnp) {
    TreeNode* at = &*addr_tnp;
    unique_treenodes.emplace(at, addr_tnp);
    memory_accesses.emplace(at, addr_tnp);
  }

  TreeNodePtr data_tnp = sdata->get_expression();
  if (data_tnp) {
    TreeNode *dt = &*data_tnp;
    unique_treenodes.emplace(dt, data_tnp);
  }

  STRACE << "SRiscOp::writeMemory() saddr=" << *saddr << LEND;
  STRACE << "SRiscOp::writeMemory() sdata=" << *sdata << LEND;

  // Tested lightly with the few cases that Cory knew of (which were really not import
  // overwrites).  This makes more sense here, but it might actually be cleaner back in defuse
  // where it was before Cory moved it here.
  for (const TreeNodePtr& tn : saddr->get_possible_values()) {
    if (tn->isIntegerConstant() && tn->nBits() <= 64) {
      rose_addr_t known_addr = *tn->toUnsigned();
      const ImportDescriptor *id = ds.get_import(known_addr);
      if (id != NULL) {
        SWARN << "Instruction " << debug_instruction(currentInstruction())
              << " overwrites import " << id->get_long_name() << " at address "
              << addr_str(known_addr) << LEND;
      }
    }
  }

  // This one line is the call to RiscOperators::writeMemory that we ought to be using...
  SymRiscOperators::writeMemory(segreg, addr, data, cond);

  insn_accesses.push_back(AbstractAccess(ds, false, saddr, data->get_width(), sdata, get_sstate()));
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
  if (nbits % 8 != 0) {
    size_t old_width = nbits;
    nbits = (nbits/8) * 8;
    GERROR << "Unable to initialize " << old_width << " bits of memory correctly, "
           << "initializing " << nbits << " instead." << LEND;
  }
  size_t nbytes = nbits/8;
  SymbolicStatePtr sstate = SymbolicState::promote(currentState());
  BaseMemoryStatePtr mem = sstate->memoryState();
  for (size_t bytenum=0; bytenum<nbits/8; ++bytenum) {
    size_t byteOffset = ByteOrder::ORDER_MSB==mem->get_byteOrder() ? nbytes-(bytenum+1) : bytenum;
    SymbolicValuePtr byte_dflt = SymbolicValue::promote(extract(data, 8*byteOffset, 8*byteOffset+8));
    SymbolicValuePtr byte_addr = SymbolicValue::promote(add(addr, number_(addr->get_width(), bytenum)));
    STRACE << "SymbolicRiscOp::initialize_memory() byte_addr=" << *byte_addr << LEND;
    STRACE << "SymbolicRiscOp::initialize_memory() byte_data=" << *byte_dflt << LEND;
    // Read (and possibly create), but discard return value.
    //SymbolicStatePtr sstate = SymbolicStatePtr::promote(state);
    currentState()->readMemory(byte_addr, byte_dflt, this, this);
  }
}

// CERT needs a rational interface read memory. :-) This API is not called from anywhere in
// Robb's infrastructure, but instead called when the symbolic state computation is complete.
// This routines needs to do the same work for reassembling multiple bytes into a return value,
// but instead of creating new values in the state, it returns an invalid symbolic value to
// indicate that the value doesn't exist.  Yes, this another copy of the code from ROSE.  :-(
// This one is hacked so that we read only _read_ memory without writing to it.
SymbolicValuePtr SymbolicRiscOperators::read_memory(const SymbolicMemoryMapState* mem,
                                                    const SymbolicValuePtr &address,
                                                    const size_t nbits) {
  STRACE << "RiscOps::read_memory(address, " << nbits << "):" << LEND;
  STRACE << "RiscOps::read_memory() address = " << *address << LEND;

  assert(0 == nbits % 8);

  // Read the bytes and concatenate them together. InsnSemanticsExpr will simplify the
  // expression so that reading after writing a multi-byte value will return the original value
  // written rather than a concatenation of byte extractions.

  SymbolicValuePtr retval;
  InsnSet defs;
  // SEI added the mods set.
  InsnSet mods;

  // SEI upgraded to our SymbolicState and SymbolicMemoryMapState here...
  for (size_t bytenum=0; bytenum<nbits/8; ++bytenum) {
    BaseSValuePtr byte_addr = add(address, number_(address->get_width(), bytenum));
    // SEI changed the type of byte_value.
    STRACE << "Reading bytenum: " << bytenum << " at: " << *address << LEND;

    const MemoryCellPtr cell = mem->findCell(SymbolicValue::promote(byte_addr));
    // If we can't find one of the bytes required to assemble the return value, then signal our
    // failure by returning an invalid value.
    if (!cell) return SymbolicValuePtr();
    SymbolicValuePtr byte_value = SymbolicValue::promote(cell->value());
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
    const RoseInsnSet &definers = byte_value->get_defining_instructions();
    defs.insert(definers.begin(), definers.end());
    //const InsnSet &modifiers = byte_value->get_modifiers(); // copying modifiers in read_memory()
    //for (const SgAsmInstruction* i : modifiers) {
    //  STRACE << "Adding modifier: " << debug_instruction(i) << LEND;
    //}
    //mods.insert(modifiers.begin(), modifiers.end());  // in our read_memory implementation!
  }

  assert(retval!=NULL && retval->get_width()==nbits);
  for (SgAsmInstruction* i : defs) {
    retval->add_defining_instructions(i);
  }
  STRACE << "RiscOps::read_memory() retval = " << *retval << LEND;
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::or_(a_, b_));

  // Any register OR'd with 0xFFFFFFFF is really just "mov reg, 0xFFFFFFFF"
  if (a_->is_number()) {
    LeafNodePtr alp = a->get_expression()->isLeafNode();
    if (alp && alp->bits().isAllSet()) {
      retval->set_defining_instructions(a->get_defining_instructions());
    }
  }
  else if (b_->is_number()) {
    LeafNodePtr blp = b->get_expression()->isLeafNode();
    if (blp && blp->bits().isAllSet()) {
      retval->set_defining_instructions(b->get_defining_instructions());
    }
  }

  if (STRACE) {
    STRACE << "RiscOps::or() a=" << *a << LEND;
    STRACE << "RiscOps::or() b=" << *b << LEND;
    STRACE << "RiscOps::or() r=" << *retval << LEND;
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

#if 0
BaseSValuePtr SymbolicRiscOperators::boolean_(bool b) {
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::boolean_(b));
  if (STRACE) {
    STRACE << "RiscOps::boolean_() b=" << b << LEND;
    STRACE << "RiscOps::boolean_() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::number_(size_t nbits, uint64_t value) {
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::number_(nbits, value));
  if (STRACE) {
    STRACE << "RiscOps::number_() n=" << nbits << LEND;
    STRACE << "RiscOps::number_() v=" << value << LEND;
    STRACE << "RiscOps::number_() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::and_(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::and_(a_, b_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::xor_(a_, b_));
  if (STRACE) {
    STRACE << "RiscOps::xor() a=" << *a << LEND;
    STRACE << "RiscOps::xor() b=" << *b << LEND;
    STRACE << "RiscOps::xor() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::invert(const BaseSValuePtr &a_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::invert(a_));
  if (STRACE) {
    STRACE << "RiscOps::invert() a=" << *a << LEND;
    STRACE << "RiscOps::invert() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::concat(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::concat(a_, b_));
  if (STRACE) {
    STRACE << "RiscOps::concat() a=" << *a << LEND;
    STRACE << "RiscOps::concat() b=" << *b << LEND;
    STRACE << "RiscOps::concat() r=" << *retval << LEND;
  }
  return retval;
}
#endif
BaseSValuePtr SymbolicRiscOperators::extract(const BaseSValuePtr &a_, size_t begin_bit, size_t end_bit) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::extract(a_, begin_bit, end_bit));

  // mwd: A hack workaround a bug in ROSE that does not propagate the definers properly when
  // the extracted value is the same size as the value being extracted from.  Remove this once ROSE gets the fix.
  if (a->get_width() == retval->get_width()) {
    retval->add_defining_instructions(a);
  }

  if (STRACE) {
    STRACE << "RiscOps::extract() b=" << begin_bit << " e=" << end_bit << " a=" << *a << LEND;
    STRACE << "RiscOps::extract() r=" << *retval << LEND;
  }
  return retval;
}
#if 0
BaseSValuePtr SymbolicRiscOperators::leastSignificantSetBit(const BaseSValuePtr &a_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::leastSignificantSetBit(a_));
  if (STRACE) {
    STRACE << "RiscOps::leastSignificantBit() a=" << *a << LEND;
    STRACE << "RiscOps::leastSignificantBit() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::mostSignificantSetBit(const BaseSValuePtr &a_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::mostSignificantSetBit(a_));
  if (STRACE) {
    STRACE << "RiscOps::mostSignificantBit() a=" << *a << LEND;
    STRACE << "RiscOps::mostSignificantBit() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::rotateLeft(const BaseSValuePtr &a_, const BaseSValuePtr &sa_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr sa = SymbolicValue::promote(sa_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::rotateLeft(a_, sa_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::rotateRight(a_, sa_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::shiftLeft(a_, sa_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::shiftRight(a_, sa_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::shiftRightArithmetic(a_, sa_));
  if (STRACE) {
    STRACE << "RiscOps::shiftRightArithmetic() a=" << *a << LEND;
    STRACE << "RiscOps::shiftRightArithmetic() sa=" << *sa << LEND;
    STRACE << "RiscOps::shiftRightArithmetic() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::equalToZero(const BaseSValuePtr &a_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::equalToZero(a_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::ite(sel_, a_, b_));
  if (STRACE) {
    STRACE << "RiscOps::ite() sel=" << *sel << LEND;
    STRACE << "RiscOps::ite() a=" << *a << LEND;
    STRACE << "RiscOps::ite() b=" << *b << LEND;
    STRACE << "RiscOps::ite() r=" << *retval << LEND;
  }
  return retval;
}
#endif

#if PHAROS_ROSE_NUMERIC_EXTENSION_HACK
BaseSValuePtr SymbolicRiscOperators::unsignedExtend(const BaseSValuePtr &a_, size_t new_width) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::unsignedExtend(a_, new_width));
  if (!omit_cur_insn
      && (computingDefiners() == TRACK_LATEST_DEFINER) && (retval->nBits() == a->nBits()))
  {
    // Fix ROSE bug when tracking latest definers
    retval->add_defining_instructions(a);
  }
  // if (STRACE) {
  //   STRACE << "RiscOps::unsignedExtend() a=" << *a << LEND;
  //   STRACE << "RiscOps::unsignedExtend() r=" << *retval << LEND;
  // }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::signExtend(const BaseSValuePtr &a_, size_t new_width) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::signExtend(a_, new_width));
  if (!omit_cur_insn
      && (computingDefiners() == TRACK_LATEST_DEFINER) && (retval->nBits() == a->nBits()))
  {
    // Fix ROSE bug when tracking latest definers
    retval->add_defining_instructions(a);
  }
  // if (STRACE) {
  //   STRACE << "RiscOps::signExtend() a=" << *a << LEND;
  //   STRACE << "RiscOps::signExtend() r=" << *retval << LEND;
  // }
  return retval;
}
#endif  // PHAROS_ROSE_NUMERIC_EXTENSION_HACK

#if 0
BaseSValuePtr SymbolicRiscOperators::add(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::add(a_, b_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::addWithCarries(a_, b_, c_, carry_out));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::negate(a_));
  if (STRACE) {
    STRACE << "RiscOps::negate() a=" << *a << LEND;
    STRACE << "RiscOps::negate() r=" << *retval << LEND;
  }
  return retval;
}

BaseSValuePtr SymbolicRiscOperators::signedDivide(const BaseSValuePtr &a_, const BaseSValuePtr &b_) {
  SymbolicValuePtr a = SymbolicValue::promote(a_);
  SymbolicValuePtr b = SymbolicValue::promote(b_);
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::signedDivide(a_, b_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::signedModulo(a_, b_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::signedMultiply(a_, b_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::unsignedDivide(a_, b_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::unsignedModulo(a_, b_));
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
  SymbolicValuePtr retval = SymbolicValue::promote(SymRiscOperators::unsignedMultiply(a_, b_));
  if (STRACE) {
    STRACE << "RiscOps::unsignedMultiply() a=" << *a << LEND;
    STRACE << "RiscOps::unsignedMultiply() b=" << *b << LEND;
    STRACE << "RiscOps::unsignedMultiply() r=" << *retval << LEND;
  }
  return retval;
}
#endif

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
