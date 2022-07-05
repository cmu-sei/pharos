// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include "pdg.hpp"
#include "method.hpp"
#include "vftable.hpp"
#include "masm.hpp"
#include "ooanalyzer.hpp"

namespace pharos {

Member::Member(unsigned int o, unsigned int s, SgAsmX86Instruction* i, bool b) {
  offset = o;
  size = s;

  // Add the instruction to the list of using instructions.
  using_instructions.insert(i);

  base_table = b;
}

// Merge two members.  This method forms the core of our approach to consolidating multiple
// member accesses into a consistent whole.
void Member::merge(Member& m) {
  // Accumulate base table facts, with a preference for true.
  if (m.base_table) base_table = m.base_table;

  // Always merge the using instructions into the current list.  Presumably this is other
  // accesses of the same member discovered from another method on the class.  It's a little
  // unclear whether this should ever happen on the members referenced from a this-pointer
  // usage, or whether this behavior should be restricted to members referenced from a class
  // description, and how we might go about enforcing that restriction.
  using_instructions.insert(m.using_instructions.begin(), m.using_instructions.end());
}

// Order methods by their addresses.
bool ThisCallMethodCompare::operator()(const ThisCallMethod *x, const ThisCallMethod *y) const {
  return (x->get_address() < y->get_address()) ? true : false;
}

// FunctionDescriptor should probably be a reference so that we don't have to keep checking
// it for NULL.
ThisCallMethod::ThisCallMethod(FunctionDescriptor *f) {
  fd = f;
  assert(fd != NULL);

  // New prolog "possible" facts that are not mutually exclusive (and need no confidence)
  // This is the "returns self" test isolated from the ordering test.
  returns_self = false;
  // This is now just the ordering tests (with both true by default).
  no_calls_before = true;
  no_calls_after = true;
  uninitialized_reads = false;

  if (find_this_pointer()) {
    test_for_constructor();
  }
}

void ThisCallMethod::stage2() {
  // Do these really belong here (inside constructor test?) in OOAnalyzer?
  if (returns_self) {
    //analyze_vftables();
    uninitialized_reads = test_for_uninit_reads();
  }
  find_members();
}

void ThisCallMethod::add_data_member(Member m) {
  // Warning here allows us to be more relaxed elsewhere...
  MemberMap::iterator finder = data_members.find(m.offset);
  if (finder != data_members.end()) {
    Member& fm = finder->second;
    fm.merge(m);
  }
  else {
    // This avoids the need for a default constructor on Member...
    data_members.insert(MemberMap::value_type(m.offset, m));
  }
}

// Determine if the provided expression simplifies to our this-pointer plus a constant offset.
// Returns boost::none if a constant offset could not be determined and the offset in all other
// cases.  Having just implemented this, perhaps I should have used the new
// AddConstantExtractor approach.  It's more limiting, but maybe that's a good thing?
boost::optional<int64_t> ThisCallMethod::get_offset(const TreeNodePtr& tn) {
  // If the expression does not reference our this-pointer, fail.
  if (!refs_leaf_ptr(tn)) return boost::none;
  // Then remove our this-pointer from the expression.
  TreeNodePtr offset_tn = remove_this_ptr_expr(tn);
  // If we return a bad expression, fail.
  if (!offset_tn) return boost::none;
  // If the simplified expression wasn't a leaf node, fail.
  LeafNodePtr ln = offset_tn->isLeafNode();
  if (!ln) return boost::none;
  // If the simplified leaf node wasn't a constant, fail.
  if (!ln->isIntegerConstant()) {
    GDEBUG << "Variable offset access into object" << *ln << " in " << *tn << LEND;
    GDEBUG << "This-pointer was: " << *leaf << LEND;
    GDEBUG << "Removed expression was: " << *offset_tn << LEND;
    return boost::none;
  }
  //
  if (ln->nBits() > 64) {
    return boost::none;
  }

  // Otherwise, convert the expression to an int64_t and return it.
  int64_t offset = IntegerOps::signExtend2(*ln->toUnsigned(), ln->nBits(), 8*sizeof(int64_t));
  return offset;
  // TODO: replace with return *ln->toSigned() once that is fixed in Rose
}

bool ThisCallMethod::find_this_pointer()
{
  GTRACE << "ThisCallMethod::find_this_pointer(): " << fd->address_string() << LEND;

  // We've changed our thinking about how to handle thunks at this point in the code several
  // times. :-( The progression has roughly been: 1. No need to follow thunks, we'll just
  // analyze the function they point to.  This was incorrect because multiple thunks
  // representing functions in different classes can jump to the same implementation, which
  // confused the prolog phase.  2.  Realizing that we should do more analysis of thunks,
  // resulting in the exporting of thunk facts, but not being able to complete this particular
  // analysis because of other errors and difficulties in obtaining the pdg cleanly in
  // multi-threaded mode.  3. The current approach, which is to "make-up" a symbolic value for
  // the ECX register just so that we can trigger other downstream processes that require a
  // ThisCallMethod object, such as exporting noCallsBefore and noCallsAfter.  While not
  // perfect, this approach brings us closer to the "right" thing in an increment way.  4? The
  // next evolution is likely to be more sophisticated handling of tail-call optimized
  // thunk-like functions where we need to conduct some proper analysis of this-pointer...
  if (fd->is_thunk()) {
    thisptr = SymbolicValue::incomplete(fd->ds.get_arch_bits());
    leaf = thisptr->get_expression()->isLeafNode();
    return true;
  }

  // We should probably be using a RegisterDescriptor (or an AbstractAccess)
  // to describe the this pointer anyway.  Here we need it to pass to is_reg().
  RegisterDescriptor this_reg = fd->ds.get_arch_reg(THIS_PTR_STR);
  RegisterDescriptor edx = fd->ds.get_arch_reg("edx");

  const PDG* p = fd->get_pdg();
  if (p == NULL) return false;
  //const Addr2DUChainMap& dd = p->get_usedef().get_dependencies();

  // What Cory would like to do here is check fd->calling_convention == ConventionThisCall, and
  // move on.   He tried enabling this code as part of fix while debugging another issue, but
  // this code sadly rejected _many_ functions that really were __thiscall so it had to be disabled.
#if 0
  bool thiscall_cc = false;
  for (const CallingConvention* cc : fd->get_calling_conventions()) {
    if (cc && cc->get_name() == "__thicall") {
      thiscall_cc = true;
      break;
    }
  }

  if (!thiscall_cc) {
    GWARN << "Rejected function " << fd->address_string() << " because it was not __thiscall." << LEND;
    return false;
  }
#endif

  const RegisterUsage& ru = fd->get_register_usage();

  GDEBUG << "ThisCallMethod getting RegisterUsage: " << fd->address_string() << LEND;
  // Display for debugging, should probably be a function of it's own.
  GDEBUG << "Function " << fd->address_string() << " has parameters: ";
  for (const RegisterEvidenceMap::value_type& rpair : ru.parameter_registers) {
    RegisterDescriptor rd = rpair.first;
    GDEBUG << " " << unparseX86Register(rd, NULL);
  }
  GDEBUG << LEND;

  // So this is our ghetto version instead... Currently if we're not using the this_pointer
  // (ECX), there's no point in continuing in ths function.
  if (ru.parameter_registers.find(this_reg) == ru.parameter_registers.end()) {
    return false;
  }

  // Cory would like to enforce that NO other registers except ESP and DF were used, but that's
  // too strict right now because we've got a partitioner bug causing bad stack deltas, which
  // causes saved register detection to fail, which results in extra parameters. :-( In the
  // meantime, let's just exclude EDX, which corrects for almost all of the __fastcall
  // functions that are currently causing the majority of the problems.
  if (ru.parameter_registers.find(edx) != ru.parameter_registers.end()) {
    return false;
  }

  auto & ud = p->get_usedef();

  // Cory's curious if there's a more efficient way to find a particular read...

  // Iterate through basic blocks
  for (const SgAsmStatement* bs : fd->get_func()->get_statementList()) {
    const SgAsmBlock *bb = isSgAsmBlock(bs);
    if (!bb) continue;
    for (SgAsmStatement* is : bb->get_statementList()) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      if (!insn) continue;
      // For each register access...
      for (const AbstractAccess& aa : ud.get_reads(insn->get_address())) {
        // We're looking for an access to the "this-pointer" register.
        if (!aa.is_reg(this_reg)) continue;

        // We're looking for an access to the "this-pointer" register.
        const TreeNodePtr & tnptr = aa.value->get_expression();

        // Cory's insisting that all valid this-pointer accesses be the "correct" size.
        if (aa.size != fd->ds.get_arch_bits()) {
          GDEBUG << "Bad thisptr (size): " << *tnptr << " at " << debug_instruction(insn) << LEND;
          continue;
        }

        // One case is that we're a compound expression.
        InternalNodePtr in = tnptr->isInteriorNode();
        if (in) {
          // We're currently rejecting all pointers that are not leaf pointers.  It's unclear if
          // that's really correct.  For example, (add v? 4) doesn't immediately seem to be
          // incorrect, although (extract 0 8 v?) does seem pretty wrong.  Leave the internal node
          // test in the code because we might want it shortly...
          GDEBUG << "Bad thisptr (not leaf): " << *tnptr << " at " << debug_instruction(insn) << LEND;
          continue;
        }

        // Then we must be a leaf node.
        leaf = tnptr->isLeafNode();
        thisptr = aa.value;

        GDEBUG << "Accepting thisptr=" << *tnptr << " at " << debug_instruction(insn) << LEND;
        return true;
      }
    }
  }

  // If we got to here, we thought we were __thiscall, but couldn't actually find the
  // this-pointer for some reason.  Cory looked at a few cases, and this message was caused by
  // incorrect detections of __thiscall, not a true failure to find the this pointer.  I'm
  // moving it to warning, but it should be moved back to ERROR once our calling convention
  // detection is better.
  GWARN << "Unable to find this-pointer for function at " << fd->address_string() << LEND;
  return false;
}

void ThisCallMethod::test_for_constructor() {
  // This method is a heuristic attempt to determine whether we're a constructor or not.  The
  // rule is that we're not a constructor if we don't return (in EAX) the this-pointer that was
  // passed in ECX.  We originally thought that this rule was flawed, but have subsequently
  // decided that perhaps it's actually a sound rule (for the Visual Studio compiler).

  // See commentary in find_this_pointer() regarding thunks, which are now handled as
  // separately exported facts in Prolog.
  if (fd->is_thunk()) return;

  const PDG* p = fd->get_pdg();
  if (p == NULL) return;
  GDEBUG << "Evaluating constructor candidate " << fd->address_string() << LEND;

  // Get definition and usage analysis, so that we can access in the input and output states.
  const DUAnalysis& du = p->get_usedef();
  // Obtain the final value of eax (the return value).
  RegisterDescriptor eaxrd = fd->ds.get_arch_reg("eax");
  // If we don't have an output state, it's because analysis failed.  Just return that the
  // function is not a constructor in the lack of any better evidence.
  const SymbolicStatePtr output_state = du.get_output_state();
  if (!output_state) return;
  SymbolicValuePtr final_eax = output_state->read_register(eaxrd);
  // And the initial value of ECX (the this pointer).
  RegisterDescriptor ecxrd = fd->ds.get_arch_reg(THIS_PTR_STR);
  // Cory's unsure if it's even possible to be missing an input state, but returning false wil
  // be better than performing an invalid memory dereference.
  const SymbolicStatePtr input_state = du.get_input_state();
  if (!input_state) return;
  SymbolicValuePtr initial_ecx = input_state->read_register(ecxrd);

  // If they can't be equal, then we're going to say that we're not a constructor.  While this
  // is a good general rule, it's not always true.  We could be returning a new instance of the
  // same object that's different than the one we were passed for example.
  if (final_eax->can_be_equal(initial_ecx)) {
    GINFO << "Constructor test succeeded for " << addr_str(get_address()) << LEND;
    returns_self = true;
  }
}

bool
ThisCallMethod::test_for_uninit_reads() const
{
  // This is a new rule for eliminating constructors based on the idea that valid constructors
  // can't be reading values out of the object (before initialization) during construction.

  // See commentary in find_this_pointer() regarding thunks, which are now handled as
  // separately exported facts in Prolog.
  if (fd->is_thunk()) return false;

  const PDG* p = fd->get_pdg();
  if (p == NULL) return false;
  //GDEBUG << "Evaluating constructor candidate " << fd->address_string() << LEND;

  TreeNodePtr tptr = thisptr->get_expression();

  //GDEBUG << " This-pointer is:" << *tptr << LEND;

  const DUAnalysis& du = p->get_usedef();

  // For every memory read in the function...
  for (const AccessMap::value_type& access : du.get_accesses()) {
    SgAsmInstruction* ginsn = fd->ds.get_insn(access.first);
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(ginsn);
    // This algorithm only works for X86 instructions? (Or maybe not?)
    if (!insn) continue;
    // The second entry of the pair is the vector of abstract accesses.
    for (const AbstractAccess& aa : access.second) {
      // We're only interested in reads...
      if (!aa.isRead) continue;

      // We're only interested in memory reads, so get that out of the way first thing.
      if (!aa.is_mem()) continue;

      // We should have a value.   If we don't something went wrong.
      if (aa.value == NULL) continue;

      // If there's a writer, the memory cell was not uninitialized, and we're only looking for
      // uninitialized reads so this method can still be a constructor.
      if (aa.latest_writers.size() != 0) continue;

      // Get the definers for this instruction.
      const RoseInsnSet &definers= aa.value->get_defining_instructions();

      // If there's more than one definer, we're definitely not reading an uninitialized value.
      if (definers.size() > 1) continue;

      // If there's exactly one definer and it's the current instruction that also counts as an
      // uninitialized read.  That's because the instruction that 'created' the memory cell by
      // reading it is in the list of definers.
      if (definers.size() == 1) {
        SgAsmInstruction* first_definer = *(definers.begin());
        if (insn->get_address() != first_definer->get_address()) continue;
      }

      // But if the read turns out to be a "fake" read, then we can still be a constructor.
      if (du.fake_read(insn, aa)) continue;

      // Next we need to check whether we're accessing the object.  In other words, is the
      // memory access an offset into the this-pointer?  The exact test that's really desired
      // here is probably more complicated than this since it should include ITEs and other
      // complex expressions, but since this is a rule that simply eliminates possible
      // constructors, a false negative isn't a super big deal (so far).
      AddConstantExtractor ace = AddConstantExtractor(aa.memory_address->get_expression());
      TreeNodePtr vp = ace.variable_portion();
      // If there's _no_ variable portion, it's definitely not an object reference.
      if (!vp) continue;
      // If the the variable portion is not our this-pointer, this memory read is not relevant.
      if (!(tptr->isEquivalentTo(vp))) continue;

      // An exception needs to be made for reads of virtual base tables.  It's a little unclear
      // why but it appears to have something to do object initialization order.
      int64_t cp = ace.constant_portion();

      //GDEBUG << "Method is accessing object offset " << cp << LEND;

      // Find the member definition for this offset.
      MemberMap::const_iterator existing_member_finder = data_members.find(cp);
      if (existing_member_finder != data_members.end()) {
        const Member& emem = existing_member_finder->second;
        // If the member is a virtual base table pointer, it's exempted from this rule.
        if (emem.base_table) {
          //GDEBUG << "Method " << fd->address_string()
          //       << " was exempted because the read was from a vbtable!" << LEND;
          continue;
        }
      }

      GDEBUG << "Method " << fd->address_string() << " is not a constructor because of "
             << debug_instruction(insn) << " which reads object offset " << cp << "." << LEND;

      // If we've made it this far, we're not a constructor because we're reading members from
      // the object that we have not initialized, and that's not consistent with how
      // constructors operate.
      // constructor = false;
      // We're probably more confident than a guess here, but for right now it doesn't matter.
      // constructor_confidence = ConfidenceGuess;
      // Once we have negative answer, we're done for this entire method.
      return true;
    }
  }
  return false;
}

void ThisCallMethod::find_members() {
  const PDG* p = fd->get_pdg();
  if (p == NULL) return;

  auto & ud = p->get_usedef();

  GTRACE << "Looking for data members in " << address_string() << LEND;

  for (const SgAsmStatement* bs : fd->get_func()->get_statementList()) {
    const SgAsmBlock *bb = isSgAsmBlock(bs);
    if (!bb) continue;
    for (SgAsmStatement* is : bb->get_statementList()) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      if (!insn) continue;
      rose_addr_t iaddr = insn->get_address();

      // NOPs don't result in member accesses.
      if (insn_is_nop(insn)) {
        GDEBUG << "NOP instruction " << debug_instruction(insn)
               << " is not a member access." << LEND;
        continue;
      }

      GTRACE << "Looking for members in: " << debug_instruction(insn) << LEND;

      // Handle LEA instructions specially....
      if (insn->get_kind() == x86_lea) {
        // The address we "accessed" will be in the write (there should be only one).
        for (const AbstractAccess& aa : ud.get_reg_writes(iaddr)) {
          boost::optional<int64_t> offset = get_offset(aa.value->get_expression());
          if (!offset) continue;

          if (*offset >= 0) {
            add_data_member(Member(*offset, aa.get_byte_size(), insn, false));
          }
          else {
            GDEBUG << "Ignoring negative object offset (" << *offset
                   << ") in LEA insn " << debug_instruction(insn) << LEND;
          }
        }
        continue;
      }

      // Look for memory accesses (typically of the form [tptr + offset]).

      for (const AbstractAccess& aa : ud.get_mem_reads(iaddr)) {
        // Assume that the expression is a properly formed offset into our object and attempt
        // to obtain the offset into that object.
        boost::optional<int64_t> offset = get_offset(aa.memory_address->get_expression());
        // We're only interested in memory references to our this-pointer that have properly
        // formed constant offsets.
        if (!offset) continue;

        if (*offset >= 0) {
          // Add the member to the method.  Calling get_byte_size() is more accurate than
          // reading sizes off of the operands (e.g. movsd) which we're probably not handling
          // correctly anyway, but it's also simpler.
          add_data_member(Member(*offset, aa.get_byte_size(), insn, false));
        }
        else {
          GDEBUG << "Ignoring negative object offset (" << *offset
                 << ") read at insn " << debug_instruction(insn) << LEND;
        }
      }

      // Now for writes (same code as reads, but with no comments).  Cory would like to be able
      // to do something witty with a custom iterator here to process both lists with the same
      // block of code to be executed.
      for (const AbstractAccess& aa : ud.get_mem_writes(iaddr)) {
        boost::optional<int64_t> offset = get_offset(aa.memory_address->get_expression());
        if (!offset) continue;

        if (*offset >= 0) {
          add_data_member(Member(*offset, aa.get_byte_size(), insn, false));
        }
        else {
          GDEBUG << "Ignoring negative object offset (" << *offset
                 << ") write at insn " << debug_instruction(insn) << LEND;
        }
      }
    }
  }
}

// This method is called in OOAnalyzer::finish(), not OOAnalyzer::visit().
void ThisCallMethod::find_passed_func_offsets(const OOAnalyzer& ooa)
{
  for (const CallDescriptor* cd : fd->get_outgoing_calls()) {
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(cd->get_insn());
    assert(insn != NULL);

    SymbolicValuePtr tPtr = ooa.get_this_ptr_for_call(cd->get_address());
    // We're only interested in valid pointers.
    if (!tPtr || !(tPtr->is_valid())) continue;

    // Get any offset added to our this-pointer.
    boost::optional<int64_t> offset = get_offset(tPtr->get_expression());
    // We're only interested in pointers that reference our object.
    // First ensure that we got a concerete offset from the expression.
    if (!offset) continue;

    // We could check for offset zero or four here, but that does not seem to be the best
    // approach.  if (*offset != 0) continue;

    for (rose_addr_t saddr : cd->get_targets()) {
      // Since we've changed the way that thunks are being handled, we probably shouldn't
      // be following thunks at all here, but that's not the bug being fixed right now.
      const FunctionDescriptor* tfd = fd->ds.get_func(saddr);
      if (tfd == nullptr) continue;
      bool endless = false;
      rose_addr_t caddr = tfd->follow_thunks(&endless);
      if (endless) continue;

      // If we've already processed this target, continue.
      if (passed_func_offsets.find(caddr) != passed_func_offsets.end()) continue;

      // Adding an entry to passed func offsets here, reading only in main().
      FuncOffset fo(caddr, *offset, insn);
      passed_func_offsets.insert(FuncOffsetMap::value_type(caddr, fo));
    }
  }
}

bool ThisCallMethod::validate_vtable(ConstVirtualTableInstallationPtr install) {
  // Short hand for the variable portion, or the object that the table was installed into.
  TreeNodePtr vp = install->written_to;
  //
  SgAsmInstruction* insn = install->insn;

  GDEBUG << "Validating virtual table found at " << addr_str(install->table_address)
         << " installed by " << addr_str(install->insn->get_address()) << LEND;

  // Neither of these should be possible.
  if (!vp) return false;
  if (!insn) return false;

  // This is the offset into the object where the virtual function table pointer is stored.
  // This should be checked elsewhere.  This messaage was moved to debug because there was
  // little evidence that the result was wrong any appreciable portion of the time.
  if (install->offset < 0) {
    GDEBUG << "Rejected negative virtual function table offset=" << install->offset
           << " at instruction: " << debug_instruction(insn) << LEND;
    return false;
  }

  // If the variable portion is a single variable, it must match the this-pointer.
  if (vp->isLeafNode() != NULL) {
    // The variable portion must actually match the current this-pointer.  This check was
    // not being performed previously because we assumed that vtable writes in the
    // constructor would be to the object for this constructor, but when this constructor
    // embeds another object and the constuctor for the embeded object was inlined into
    // this method, we get misleading results here.
    if (!(vp->isEquivalentTo(leaf))) {

      // 2/16/22: ejs disabled this to see possibleVFTableWrites that were inlined

      // GDEBUG << "Rejected virtual function table write for wrong object " << *vp << " != "
      //        << *leaf << " at instruction: " << debug_instruction(insn) << LEND;
      //return false;
    }
  }

  // There's another crazy possibility caused by virtual base tables (primarily?).  It
  // involves an offset into the object that contains two variable portions.  One is the
  // object pointer, which is truly variable, and the other is a semi-constant that was
  // read out of the virtual base table.  Unfortunately, we don't currently have a good
  // general purpose system for replacing variables with their constant values from the
  // program image, so we're going to hack it up a little bit here and just look for an add
  // operation that contains our this pointer.  Unfortunately the VXTableWrite facts will
  // be incorrect (because they assume the vbtable adjustment was zero) until we
  // reimplement this code more robustly...
  else {
    // We must be an interior node if we weren't a leaf node.
    InternalNodePtr inode = vp->isInteriorNode();
    // In this branch we're not a this-pointer until we find what we're looking for.
    bool found_this_ptr = false;
    // If we're an ADD operation, that's what we're looking for.
    if (inode && inode->getOperator() == Rose::BinaryAnalysis::SymbolicExpr::OP_ADD) {
      // Now go through each node and see if one of them is the object pointer.
      for (const TreeNodePtr & ctp : inode->children()) {
        if (ctp->isEquivalentTo(leaf)) found_this_ptr = true;
      }
    }
    if (found_this_ptr) {
      GDEBUG << "Ignoring unknown virtual base table offset in instruction "
             << debug_instruction(insn) << LEND;
    }
    else {
      GDEBUG << "Rejected virtual function table write for wrong object " << *vp
             << " does not contain thisptr at instruction: " << debug_instruction(insn) << LEND;
      return false;
    }
  }

  GDEBUG << "VTable write: " << *vp << " offset=" << install->offset
         << " <- " << addr_str(install->table_address)
         << " in " << debug_instruction(insn) << LEND;
  GDEBUG << "Possible virtual table found at " << addr_str(install->table_address)
         << " installed by " << addr_str(insn->get_address()) << LEND;
  size_t arch_bytes = fd->ds.get_arch_bytes();

  SgAsmX86Instruction* x86insn = isSgAsmX86Instruction(insn);
  add_data_member(Member(install->offset, arch_bytes, x86insn, install->base_table));
  return true;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
