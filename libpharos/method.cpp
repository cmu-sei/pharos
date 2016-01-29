// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#include "pdg.hpp"
#include "method.hpp"
#include "class.hpp"
#include "vftable.hpp"

// This is newly created global map to track all methods following the "this-call" calling
// convention.  The map itself maps the address of the function to a ThisCallMethod instance.
// Globals that were ok in objdigger.cpp are now a little icky in libpharos.  Perhaps this
// should be moved somewhere else.
ThisCallMethodMap this_call_methods;

// Order methods by their addresses.
bool ThisCallMethodCompare::operator()(const ThisCallMethod *x, const ThisCallMethod *y) const {
  return (x->get_address() < y->get_address()) ? true : false;
}

// Find the value of ECX at the time of the call, by inspecting the state that was saved when
// the call was evaluated.  Perhaps this should be a method on the call descriptor?  It uses
// follow_oo_thunks() which is a messy entanglement.   Needs more cleanup.
SymbolicValuePtr get_this_ptr_for_call(const CallDescriptor* cd) {
  // Try to decide if any of our targets are object oriented.  This should be a shared method
  // somewhere. We've done the same thing while resolving virtual calls.
  bool oo_target = false;
  BOOST_FOREACH(rose_addr_t target, cd->get_targets()) {
    ThisCallMethod* tcm = follow_oo_thunks(target);
    if (tcm != NULL) {
      GDEBUG << "Call at " << cd->address_string() << " calls OO target "
             << tcm->address_string() << LEND;
      oo_target = true;
      break;
    }
  }

  // If we're not an oo method, then we don't have a this pointer...
  if (!oo_target) return SymbolicValue::instance();

  const SymbolicStatePtr state = cd->get_state();
  if (state == NULL) {
    // Moved to warning importance because it appears to be a cascading failure from
    // a function analysis timeout.
    GWARN << "No final state for call at " << cd->address_string() << LEND;
    return SymbolicValue::instance();
  }
  // We should be able to find this globally somehow...
  const RegisterDictionary* regdict = RegisterDictionary::dictionary_pentium4();
  const RegisterDescriptor* this_reg = regdict->lookup(THIS_PTR_STR);
  assert(this_reg != NULL);
  // Read ECX from the state immediately before the call.
  SymbolicValuePtr this_value = state->read_register(*this_reg);
  return this_value;
}

// FunctionDescriptor should probably be a reference so that we don't have to keep checking
// it for NULL.
ThisCallMethod::ThisCallMethod(FunctionDescriptor *f) {
  fd = f;
  assert(fd != NULL);

  constructor = false;
  constructor_confidence = ConfidenceNone;

  destructor = false;
  destructor_confidence = ConfidenceNone;

  deleting_destructor = false;
  deleting_destructor_confidence = ConfidenceNone;

  if (find_this_pointer()) {
    test_for_constructor();
    if (is_constructor()) {
      analyze_vftables();
    }
    find_members();
  }
}

void ThisCallMethod::add_data_member(Member m) {
  // Warning here allows us to be more relaxed elsewhere...
  MemberMap::iterator finder = data_members.find(m.offset);
  if (finder != data_members.end()) {
    Member& fm = finder->second;
    fm.merge(m, get_address());
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
  if (!ln->isNumber()) {
    GDEBUG << "Variable offset access into object" << *ln << " in " << *tn << LEND;
    GDEBUG << "This-pointer was: " << *leaf << LEND;
    GDEBUG << "Removed expression was: " << *offset_tn << LEND;
    return boost::none;
  }

  // Otherwise, convert the expression to an int64_t, and return it.
  int64_t offset = IntegerOps::signExtend2(ln->toInt(), ln->nBits(), 8*sizeof(int64_t));
  return offset;
}

// Mark the method as a destructor (or not) with a specified confidence.
void ThisCallMethod::set_destructor(bool b, GenericConfidence conf) {

  if (b) {
    GDEBUG << "Attempting to set destructor for " << addr_str(get_address()) << LEND;
  }

  // Refuse to downgrade the confidence.  This shouldn't happen, but if it did we'd want to
  // know.
  if (conf < destructor_confidence) {
    GWARN << "Refused to downgrade destructor confidence: " << address_string() << LEND;
    return;
  }

  // Refuse to set the destructor flag inconsistently with a higher confidence constructor
  // flag.
  if (b && constructor && (conf < constructor_confidence)) {
    GWARN << "Refused to override constructor confidence: " << address_string() << LEND;
    return;
  }
  else if (b && deleting_destructor && (conf < deleting_destructor_confidence)) {
    GWARN << "Refused to override deleting destructor confidence: " << address_string() << LEND;
    return;
  }

  // Also warn about turning non-destructors into destructors, since that shouldn't happen
  // either unless we've added some new analysis capability.
  if (b && !destructor) {
    GDEBUG << "Converting method into a destructor: " << address_string() << LEND;
  }

  // Set the destructor boolean whichever way the caller said.
  destructor = b;
  // And update the confidence.
  destructor_confidence = conf;

  // If we know that this method is a destructor with some confidence, we have the same
  // confidence that it is not a constructor. If the confidence on the constructor flag was
  // greater than our new confidence, we wouldn't have reached this code.
  if (destructor) {
    constructor_confidence = destructor_confidence;
    deleting_destructor_confidence = destructor_confidence;

    // Additionaly, since a method can't be both a constructor and a destructor simultaneously,
    // force the constructor field to false, and make a note of that.
    if (constructor || deleting_destructor) {
      // Move to GDEBUG after testing since most destructors start out being incorrectly
      // detected possible constructors.
      GDEBUG << "Destructor " << address_string() << " cannot also be a constructor or deleting destructor." << LEND;
      constructor = false;
      deleting_destructor = false;
    }
  }
}

// Mark the method as a destructor (or not) with a specified confidence.
void ThisCallMethod::set_deleting_destructor(bool b, GenericConfidence conf) {

  if(b) {
    GDEBUG << "Attempting to set deleting destructor for " << addr_str(get_address()) << LEND;
  }

  // Refuse to downgrade the confidence.  This shouldn't happen, but if it did we'd want to
  // know.
  if (conf < deleting_destructor_confidence) {
    GWARN << "Refused to downgrade deleting destructor confidence: " << address_string() << LEND;
    return;
  }

  // Refuse to set the deleting destructor flag inconsistently with a higher confidence constructor
  // flag.
  if (b && constructor && (conf < constructor_confidence)) {
    GWARN << "Refused to override constructor confidence: " << address_string() << LEND;
    return;
  }
  else if (b && destructor && (conf < destructor_confidence)) {
    GWARN << "Refused to override destructor confidence: " << address_string() << LEND;
    return;
  }

  // Also warn about turning non-destructors into destructors, since that shouldn't happen
  // either unless we've added some new analysis capability.
  if (b && !deleting_destructor) {
    GWARN << "Converting method into a deleting_destructor: " << address_string() << LEND;
  }

  // Set the destructor boolean whichever way the caller said.
  deleting_destructor = b;
  // And update the confidence.
  deleting_destructor_confidence = conf;

  // If we know that this method is a deleting destructor with some confidence, we have the same
  // confidence that it is neither a constructor nor destructor. If the confidence on the constructor flag was
  // greater than our new confidence, we wouldn't have reached this code.
  if (deleting_destructor) {
    constructor_confidence = deleting_destructor_confidence;
    destructor_confidence = deleting_destructor_confidence;

    // Additionaly, since a method can't be both a constructor and a destructor simultaneously,
    // force the constructor field to false, and make a note of that.
    if (constructor || destructor) {
      // Move to GDEBUG after testing since most destructors start out being incorrectly
      // detected possible constructors.
      GDEBUG << "Deleting destructor " << address_string() << " cannot also be a constructor or destructor." << LEND;
      constructor = false;
      destructor = false;
    }
  }
}

// Mark the method as a constructor (or not) with a specified confidence.
void ThisCallMethod::set_constructor(bool b, GenericConfidence conf) {

  if (b) {
    GDEBUG << "Attempting to set constructor for " << addr_str(get_address()) << LEND;
  }
  // Refuse to downgrade the confidence.  This shouldn't happen, but if it did we'd want to
  // know.
  if (conf < constructor_confidence) {
    GWARN << "Refused to downgrade constructor confidence: " << address_string() << LEND;
    return;
  }

  if (b && destructor && (conf < destructor_confidence)) {
    GWARN << "Refused to override destructor confidence: " << address_string() << LEND;
    return;
  }
  else if (b && deleting_destructor && (conf < deleting_destructor_confidence)) {
    GWARN << "Refused to override deleting destructor confidence: " << address_string() << LEND;
    return;
  }

  // Also warn about turning non-constructors into destructors, since that shouldn't happen
  // either unless we've added some new analysis capability.
  if (b && !constructor) {
    GWARN << "Converting method into a constructor: " << address_string() << LEND;
  }

  // Set the contructor boolean whichever way the caller said.
  constructor = b;
  // And update the confidence.
  constructor_confidence = conf;

  // If we know that this method is a constructor with some confidence, we have the same
  // confidence that it is not a destructor. If the confidence on the destructor flag was
  // greater than our new confidence, we wouldn't have reached this code.
  if (constructor) {
    destructor_confidence = constructor_confidence;
    deleting_destructor_confidence = constructor_confidence;

    // Additionaly, since a method can't be both a constructor and a destructor simultaneously,
    // force the destructor field to false, and make a note of that.
    if (destructor || deleting_destructor) {
      // This message can probably remain at GWARN, because we should rarely trigger it.
      OINFO << "Constructor " << address_string() << " cannot also be a destructor." << LEND;
      destructor = false;
      deleting_destructor = false;
    }
  }
}

void ThisCallMethod::debug() const {
  GDEBUG << "TCM: " << address_string();
  if (is_constructor()) GDEBUG << " ctor { ";
  else if (is_destructor()) GDEBUG << " dtor { ";
  else GDEBUG << "      { ";
  BOOST_FOREACH(const FuncOffsetMap::value_type& fopair, passed_func_offsets) {
    const FuncOffset& fo = fopair.second;
    GDEBUG << fo.offset << "=" << fo.tcm->address_string() << " ";
  }
  GDEBUG << "}" << std::dec << LEND;

  if (GDEBUG && calling_classes.size() != 1) {
    GDEBUG << "TCM: " << address_string() << " is assigned to "
           << calling_classes.size() << " classes." << LEND;
    BOOST_FOREACH(ClassDescriptor* cls, calling_classes) {
      GDEBUG << "TCM: " << address_string() << " in " << cls->address_string() << LEND;
    }
  }
}

bool ThisCallMethod::find_this_pointer()
{
  GTRACE << "ThisCallMethod::find_this_pointer(): " << fd->address_string() << LEND;

  // We should probably be using a RegisterDescriptor (or an AbstractAccess)
  // to describe the this pointer anyway.  Here we need it to pass to is_reg().
  const RegisterDictionary* regdict = RegisterDictionary::dictionary_pentium4();
  const RegisterDescriptor* this_reg = regdict->lookup(THIS_PTR_STR);
  const RegisterDescriptor* edx = regdict->lookup("edx");

  PDG *p = fd->get_pdg();
  if (p == NULL) return false;
  //const Insn2DUChainMap& dd = p->get_usedef().get_dependencies();

  // What Cory would like to do here is check fd->calling_convention == ConventionThisCall, and
  // move on, but to get there we'll have to define the standard calling conventions correctly,
  // and that's started in convention.hpp but is far from complete.

  const RegisterUsage& ru = fd->get_register_usage();

  GDEBUG << "ThisCallMethod getting RegisterUsage: " << fd->address_string() << LEND;
  // Display for debugging, should probably be a function of it's own.
  GDEBUG << "Function " << fd->address_string() << " has parameters: ";
  BOOST_FOREACH(const RegisterEvidenceMap::value_type& rpair, ru.parameter_registers) {
    const RegisterDescriptor* rd = rpair.first;
    GDEBUG << " " << unparseX86Register(*rd, NULL);
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

  const AccessMap& reads = p->get_usedef().get_reads();

  // Cory's curious if there's a more efficient way to find a particular read...

  // Iterate through basic blocks
  BOOST_FOREACH(SgAsmStatement* bs, fd->get_func()->get_statementList()) {
    SgAsmBlock *bb = isSgAsmBlock(bs);
    if (!bb) continue;
    BOOST_FOREACH(SgAsmStatement* is, bb->get_statementList()) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      if (!insn) continue;
      // If there are no reads just continue.
      if (reads.find(insn) == reads.end()) continue;
      // For each access...
      BOOST_FOREACH(const AbstractAccess& aa, reads.at(insn)) {
        // We're looking for an access to the "this-pointer" register.
        if (!aa.is_reg(this_reg)) continue;

        TreeNodePtr tnptr = aa.value->get_expression();

        // Cory's insisting that all valid this-pointer accesses be the "correct" size.
        if (aa.size != get_arch_bits()) {
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
  // This method is a heuristic attempt to determine whether we're a constructor or not.  It's
  // imperfect, but it's what we're doing currently.

  // It's unclear to Cory if we should still be checking for a thunk here.  I suspect not.  We
  // probably shouldn't be creating ThisCallMethods for the thunks, but that will require more
  // analysis of Wes' code.

  // Check to see if this function is a thunk to another.  Should be calling follow_oo_thunks?
  FunctionDescriptor *this_call_fd = fd->get_jmp_fd();
  // If there's no thunk, just use the FD we were given.
  if (this_call_fd == NULL) this_call_fd = fd;

  PDG* p = this_call_fd->get_pdg();
  if (p == NULL) return;
  GDEBUG << "Evaluating constructor candidate " << this_call_fd->address_string() << LEND;

  // Assume that we're not a constructor if something goes wrong.
  constructor = false;
  constructor_confidence = ConfidenceWrong;

  // Get definition and usage analysis, so that we can access in the input and output states.
  const DUAnalysis& du = p->get_usedef();
  // Obtain the final value of eax (the return value).
  const RegisterDictionary* regdict = RegisterDictionary::dictionary_pentium4();
  const RegisterDescriptor* eaxrd = regdict->lookup("eax");
  // If we don't have an output state, it's because analysis failed.  Just return that the
  // function is not a constructor in the lack of any better evidence.
  const SymbolicStatePtr output_state = du.get_output_state();
  if (!output_state) return;
  SymbolicValuePtr final_eax = output_state->read_register(*eaxrd);
  // And the initial value of ECX (the this pointer).
  const RegisterDescriptor* ecxrd = regdict->lookup(THIS_PTR_STR);
  // Cory's unsure if it's even possible to be missing an input state, but returning false wil
  // be better than performing an invalid memory dereference.
  const SymbolicStatePtr input_state = du.get_input_state();
  if (!input_state) return;
  SymbolicValuePtr initial_ecx = input_state->read_register(*ecxrd);

  // If they can't be equal, then we're going to say that we're not a constructor.  While this
  // is a good general rule, it's not always true.  We could be returning a new instance of the
  // same object that's different than the one we were passed for example.
  if (!(final_eax->can_be_equal(initial_ecx))) {
    GDEBUG << "Constructor test failed for " << this_call_fd->address_string()
           << ": eax=" << *final_eax << " cannot equal ecx=" << *initial_ecx << LEND;

    //GDEBUG << "Initial state " << du.input_state << LEND;
    //GDEBUG << "Final state " << du.output_state << LEND;
    constructor = false;
    constructor_confidence = ConfidenceGuess;
  }
  else {
    GDEBUG << "Constructor test succeeded for " << addr_str(get_address()) << LEND;
    // If they are, then I guess we are a constructor.  Or at least we look a little bit like
    // one.  We should probably
    constructor = true;
    constructor_confidence = ConfidenceGuess;
  }
}

void ThisCallMethod::find_members() {
  PDG* p = fd->get_pdg();
  if (p == NULL) return;
  const AccessMap& reads = p->get_usedef().get_reads();
  const AccessMap& writes = p->get_usedef().get_writes();

  GTRACE << "Looking for data members in " << address_string() << LEND;

  BOOST_FOREACH(SgAsmStatement* bs, fd->get_func()->get_statementList()) {
    SgAsmBlock *bb = isSgAsmBlock(bs);
    if (!bb) continue;
    BOOST_FOREACH(SgAsmStatement* is, bb->get_statementList()) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(is);
      if (!insn) continue;

      GTRACE << "Looking for members in: " << debug_instruction(insn) << LEND;

      // Why are we excluding LEA instructions?
      if (insn->get_kind() == x86_lea) continue;

      // Look for memory accesses (typically of the form [tptr + offset]).

      if (reads.find(insn) != reads.end()) {
        BOOST_FOREACH(const AbstractAccess& aa, reads.at(insn)) {
          // We're only interested in memory accesses...
          if (!aa.is_mem()) continue;

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
            add_data_member(Member(*offset, aa.get_byte_size(), 0, insn, NULL));
          }
          else {
            GDEBUG << "Ignoring negative object offset (" << *offset
                   << ") read at insn " << debug_instruction(insn) << LEND;
          }
        }
      }

      // Now for writes (same code as reads, but with no comments).  Cory would like to be able
      // to do something witty with a custom iterator here to process both lists with the same
      // block of code to be executed.
      if (writes.find(insn) != writes.end()) {
        BOOST_FOREACH(const AbstractAccess& aa, writes.at(insn)) {
          if (!aa.is_mem()) continue;
          boost::optional<int64_t> offset = get_offset(aa.memory_address->get_expression());
          if (!offset) continue;

          if (*offset >= 0) {
            add_data_member(Member(*offset, aa.get_byte_size(), 0, insn, NULL));
          }
          else {
            GDEBUG << "Ignoring negative object offset (" << *offset
                   << ") write at insn " << debug_instruction(insn) << LEND;
          }
        }
      }
    }
  }
}

void ThisCallMethod::find_passed_func_offsets() {
  BOOST_FOREACH(CallDescriptor* cd, fd->get_outgoing_calls()) {
    SgAsmX86Instruction* insn = isSgAsmX86Instruction(cd->get_insn());
    assert(insn != NULL);

    SymbolicValuePtr tPtr = get_this_ptr_for_call(cd);
    // We're only interested in valid pointers.
    if (!(tPtr->is_valid())) continue;

    // Get any offset added to our this-pointer.
    boost::optional<int64_t> offset = get_offset(tPtr->get_expression());
    // We're only interested in pointers that reference our object.
    // First ensure that we got a concerete offset from the expression.
    if (!offset) continue;

    // We could check for offset zero or four here, but that does not seem to be the best
    // approach.  if (*offset != 0) continue;

    BOOST_FOREACH(rose_addr_t saddr, cd->get_targets()) {
      ThisCallMethod* ctcm = follow_oo_thunks(saddr);
      // If the method is not __thiscall, then we don't care about it.  In addition to
      // following thunks, the oo version validates that the target is a member of the global
      // this_call_methods map.  This map needs to have ben populated completely before this
      // function is called so that we don't miss any passed this-pointers.
      if (ctcm == NULL) continue;
      rose_addr_t caddr = ctcm->get_address();

      // If we've already processed this target, continue.
      if (passed_func_offsets.find(caddr) != passed_func_offsets.end()) continue;

      // Adding an entry to passed func offsets here, reading only in main().
      FuncOffset fo(ctcm, *offset, insn);
      passed_func_offsets.insert(FuncOffsetMap::value_type(caddr, fo));

      // If we're passing an offset in the object to other methods, it seems to imply an
      // embedded object (either due to inheritance or traditional embedding).  After
      // considering various ways to represent this it appears that the most convenient way is
      // to declare both kinds of objects "embedded" and rely on virtual function tables to
      // differentiate between inheritance and traditional embedding.  In particular, in the
      // case of multiple inheritance with virtual function tables, we'll have embedded objects
      // for both classes AND virtual function tables for both.  It looks like the most
      // problematic case is inherited versus ordinary embedded objects at offset zero, which
      // it may be impossible to differentiate between without virtual functions anyway.
      GDEBUG << "Embedded object at offset " << *offset << " in method at " << address_string()
             << " is passed to " << addr_str(caddr) << LEND;
      add_data_member(Member(*offset, 0, caddr, insn, NULL));
    }
  }
}

void ThisCallMethod::analyze_vftables() {
  // Analyze the function if we haven't already.
  PDG* p = fd->get_pdg();
  if (p == NULL) return;

  GDEBUG << "Analyzing vftables for " << fd->address_string() << LEND;

  // For every write in the function...
  BOOST_FOREACH(const AccessMap::value_type& access, p->get_usedef().get_writes()) {
    // The second entry of the pair is the vector of abstract accesses.
    BOOST_FOREACH(const AbstractAccess& aa, access.second) {
      // We're only interested in writes that write a constant value to the target.
      // This is a reasonably safe presumption for compiler generated code.
      if (!aa.value->is_number()) continue;

      // I was doubtful about the requirement that the write must be to memory, but after
      // further consideration, I'm fairly certain that even if we moved the constant value
      // into a register, and the register into the object's memory (which is literally
      // required), then we'd detect the memory write on the second instruction.
      if (!aa.is_mem()) continue;

      // We're only interested in constant addresses that are in the memory image.  In some
      // unusual corner cases this might fail, but it should work for compiler generated code.
      rose_addr_t constaddr = aa.value->get_number();
      if (!global_descriptor_set->memory_in_image(constaddr)) continue;

      // We're not interested in writes to fixed memory addresses.  This used to exclude stack
      // addresses, but now it's purpose is a little unclear.  It might prevent vtable updates
      // to global objects while providing no benefit, or it might correctly eliminate many
      // write to fixed memory addresses correctly.  Cory doesn't really know.
      if (aa.memory_address->is_number()) continue;

      // This is the instruction we're talking about.
      SgAsmInstruction* insn = access.first;
      SgAsmX86Instruction* x86insn = isSgAsmX86Instruction(insn);

      // We're not interested in call instructions, which write constant return addresses to
      // the stack.  This is largely duplicative of the test above, but will be needed when
      // the stack memory representation gets fixed to include esp properly.
      if (insn_is_call(x86insn)) continue;

      GDEBUG << "Analyzing vtable access instruction: " << debug_instruction(insn) << LEND;

      // What's left is starting to look a lot like the initialization of a virtual function
      // table pointer.  Let's check to see if we've already analyzed this address.  If so,
      // there's no need to analyze it again, just use the previous results.
      VirtualFunctionTable* vftable = NULL;
      if (global_vtables.find(constaddr) != global_vtables.end()) {
        vftable = global_vtables[constaddr];
      }
      else {
        // This memory is not currently freed anywhere. :-( Sorry 'bout that. -- Cory
        vftable = new VirtualFunctionTable(constaddr);
        vftable->analyze();
        global_vtables[constaddr] = vftable;
      }

      // The address can only truly be a virtual function table if it passes some basic tests,
      // such as having at least one function pointer.
      if (vftable->max_size < 1) {
        // If there were no pointer at all, just reject the table outright.
        if (vftable->non_function == 0) {
          GINFO << "Possible virtual function table at " << addr_str(constaddr)
                << " rejected because no valid pointers were found." << LEND;
          // Don't add the table to the list of tables for the object.
          continue;
        }
        // But if there were valid non-function pointers, let's continue to assume that we've
        // had a disassembly failure, and add the table to the list of tables even though it's
        // obviously broken.
        else {
          GINFO << "Possible virtual function table at " << addr_str(constaddr)
                << " is highly suspicious because no function pointers were found." << LEND;
        }
      }

      // Let's try to extract the object pointer variable, and any offset
      // that's present.
      TreeNodePtr tn = aa.memory_address->get_expression();
      AddConstantExtractor ace(tn);
      // There must be a variable portion.
      if (ace.variable_portion == NULL) {
        GWARN << "Malformed virtual function table initialization: expr=" << *tn
              << " at instruction: " << debug_instruction(insn) << LEND;
        continue;
      }
      // The variable portion must be a single variable.
      if (ace.variable_portion->isLeafNode() == NULL) {
        GWARN << "Malformed virtual function table initialization: expr=" << *tn
              << " at instruction: " << debug_instruction(insn) << LEND;
        continue;
      }

      // The variable portion must actually match the current this-pointer.  This check was not
      // being performed previously because we assumed that vtable writes in the constructor
      // would be to the object for this constructor, but when this constructor embeds another
      // object and the constuctor for the embeded object was inlined into this method, we get
      // misleading results here.
      if (!(ace.variable_portion->isEquivalentTo(leaf))) {
        GWARN << "Rejected virtual function table write for wrong object "
              << *ace.variable_portion << " != " << *leaf
              << " at instruction: " << debug_instruction(insn) << LEND;
        continue;
      }

      // This is the offset into the object where the virtual function table pointer is stored.
      int64_t offset = ace.constant_portion;
      if (offset >= 0) {

        // Check to see if there's already a member at that offset with a different virtual
        // function table pointer.  If there is, that probably means that parent class
        // constructor was inlined into this constructor.  While the overwrite will produce the
        // correct answer for the child class, we'll lose knowledge about the parent class.
        MemberMap::iterator existing_member_finder = data_members.find(offset);
        if (existing_member_finder != data_members.end()) {
          Member& emem = existing_member_finder->second;
          if (GDEBUG) {
            GDEBUG << "VTable overwrites existing member: " << LEND;
            emem.debug();
          }
        }
        GINFO << "VTable write: " << *ace.variable_portion << " offset=" << offset << " <- "
              << addr_str(constaddr) << " in " << debug_instruction(insn) << LEND;
        VFTEvidence ve(insn, fd, vftable);
        add_data_member(Member(offset, get_arch_bytes(), 0, x86insn, &ve));
      }
      else {
        GWARN << "Rejected negative virtual function table offset=" << ace.constant_portion
              << " at instruction: " << debug_instruction(insn) << LEND;
      }

      // In all cases, this loop should continue to the next instruction, since there can be
      // multiple virtual function tables per constructor, and any failures we encountered
      // won't prevent later tables from validating correctly.
    }
  }
}

// A version of follow thunks that returns the final target if and only if it's in
// this_call_methods.
ThisCallMethod* follow_oo_thunks(rose_addr_t addr) {
  // Find the function descriptor for the provided address.
  FunctionDescriptor *fd = global_descriptor_set->get_func(addr);
  if (fd == NULL) return NULL;
  // Follow thunks.
  fd = fd->follow_thunks_fd();
  if (fd == NULL) return NULL;
  // The address of the eventual target.
  rose_addr_t eaddr = fd->get_address();
  // If that's not an OO method, we're not interested.
  if (this_call_methods.find(eaddr) == this_call_methods.end()) return NULL;
  // Get the this-call method reference.
  ThisCallMethod& tcm = this_call_methods.at(eaddr);
  // And return a pointer to it.
  return &tcm;
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
