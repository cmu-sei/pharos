// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/optional.hpp>
#include <boost/property_map/property_map.hpp>

#include <rose.h>
#include <AstTraversal.h>

#include "calls.hpp"
#include "vcall.hpp"

namespace pharos {

template<> char const* EnumStrings<CallType>::data[] = {
  "Immediate",
  "Register",
  "Import",
  "GlobalVariable",
  "VirtualFunction",
  "Unknown",
  "Unspecified"
};

template<> char const* EnumStrings<CallTargetLocation>::data[] = {
  "Internal",
  "External",
  "Unknown",
};

bool CallDescriptorCompare::operator()(const CallDescriptor* x, const CallDescriptor* y) const {
  return (x->get_address() < y->get_address());
}

const LeafNodePtr & CallDescriptor::get_stack_delta_variable() const {
  if (import_descriptor != nullptr) {
    return import_descriptor->get_stack_delta_variable();
  }
  if (function_override != nullptr) {
    return function_override->get_stack_delta_variable();
  }
  if (function_descriptor != nullptr) {
    return function_descriptor->get_stack_delta_variable();
  }
  if (stack_delta_variable == nullptr) {
    size_t arch_bits = global_descriptor_set->get_arch_bits();
    stack_delta_variable = LeafNode::createVariable(arch_bits, "", UNKNOWN_STACK_DELTA);
  }
  return stack_delta_variable;
}

StackDelta CallDescriptor::get_stack_delta() const {
  GDEBUG << "Getting stack delta for " << *this << LEND;

  // Apparently imported descriptor has to be first.  I should be more consistent in describing
  // the contract for which fields are meaningful under what conditions.
  if (import_descriptor != NULL) {
    GDEBUG << "Call descriptor calls " << *import_descriptor << LEND;
    return import_descriptor->get_stack_delta();
  }
  // The cases in which we have a function descriptor are very similar.
  else if (function_override != NULL || function_descriptor != NULL) {
    StackDelta merged;

    // Use the delta for the target if it's defined (or the concensus function descriptor if
    // we've built it).
    if (function_descriptor != NULL) {

      // We were using the more convenient get_jmp_fd() call here, but it's possible that the
      // thunk resolves to a jump to an import, which can only be detected using the
      // get_jmp_addr() API.  The fact that the import isn't already in the import_descriptor
      // field is probably a separate bug, which Cory will try to fix in a minute.  This was
      // further broken by the fact that get_jmp_xxx() wasn't correct.  We really want to use
      // follow_thunks() so that if there's multiple thunks in the chain, we do the correct
      // thing.
      rose_addr_t thunk_addr = function_descriptor->follow_thunks(NULL);
      ImportDescriptor* tid = global_descriptor_set->get_import(thunk_addr);
      if (tid != NULL) {
        GDEBUG << "Call descriptor calls " << tid->get_long_name() << " through missed thunks." << LEND;
        return tid->get_stack_delta();
      }

      // Now see if there's a function at the specified address.
      FunctionDescriptor *thunk_fd = global_descriptor_set->get_func(thunk_addr);
      if (thunk_fd == NULL) {
        GDEBUG << "Call descriptor calls " << *function_descriptor << LEND;
        merged = function_descriptor->get_stack_delta();
      } else {
        GDEBUG << "Got stack delta for thunk target " << *thunk_fd << LEND;
        merged = thunk_fd->get_stack_delta();
      }
    }

    // If some evidence has downgraded our confidence in our call target completeness, that
    // should be reflected in out stack delta confidence, but just because we don't know any of
    // the call targets, it doesn't prevent us from making guesses about the stack delta.  This
    // logic should probably be in the code that merges the targets into the concensus function
    // descriptor. that we just obtained.
    if (confidence < merged.confidence && confidence != ConfidenceNone) {
      merged.confidence = confidence;
    }

    // But if we were overriden by the user, use that instead (without regard to the confidence
    // in the rest of our call descriptor data).
    if (function_override != NULL) {
      GDEBUG << "Call descriptor override " << *function_override << LEND;
      merged = function_override->get_stack_delta();
    }

    // More of the rest of the complex logic should be handlded by the updating of the
    // "concensus" function descriptor in this call descriptor (so it's already built into
    // merged).
    GDEBUG << "Final stack delta according to call_descriptor" << merged << LEND;
    return merged;
  }
  // We've got no idea where the function calls to, and so we have no idea what the stack delta
  // was unless the user (or maybe some future constaint based stack solving) told us.
  else {
    return stack_delta;
  }
}

StackDelta CallDescriptor::get_stack_parameters() const {
  GDEBUG << "Getting stack parameters for " << *this << LEND;

  // Apparently imported descriptor has to be first.  I should be more consistent in describing
  // the contract for which fields are meaningful under what conditions.
  if (import_descriptor != NULL) {
    GDEBUG << "Call descriptor calls " << *import_descriptor << LEND;
    return import_descriptor->get_stack_parameters();
  }
  // The cases in which we have a function descriptor are very similar.
  else if (function_override != NULL || function_descriptor != NULL) {
    // If the user provided a stack parameters override, use it.
    if (function_override != NULL) {
      GDEBUG << "Call descriptor stack parameters overriden " << *function_override << LEND;
      return function_override->get_stack_parameters();
    }
    // Other wise use whatever function descriptor we've got.
    if (function_descriptor != NULL) {
      // Cory's conflicted about whether he should have to be doing this here.  We should
      // probably propograte this information automatically, but we want to do it without
      // destroying the ability to understand the actual thunks as well.
      if (function_descriptor->is_thunk()) {
        rose_addr_t taddr = function_descriptor->follow_thunks(NULL);
        ImportDescriptor* tid = global_descriptor_set->get_import(taddr);
        if (tid != NULL) {
          GDEBUG << "Call at " << address_string() << " gets parameters from import "
                 << *tid << LEND;
          return tid->get_stack_parameters();
        }
        else {
          FunctionDescriptor* tfd = global_descriptor_set->get_func(taddr);
          if (tfd != NULL) {
            GDEBUG << "Call at " << address_string() << " gets parameters from function at "
                   << tfd->address_string() << LEND;
            return tfd->get_stack_parameters();
          }
          else {
            GDEBUG << "Call at " << address_string()
                   << " has bad parameters because it's a thunk to a non-function. " << LEND;
            return function_descriptor->get_stack_parameters();
          }
        }
      }
      else {
        GDEBUG << "Call descriptor calls " << *function_descriptor << LEND;
        return function_descriptor->get_stack_parameters();
      }
    }
  }

  if (stack_delta.confidence == ConfidenceNone) {
    GDEBUG << "Call descriptor has no stack parameter data." << LEND;
  }
  return stack_delta;
}

void CallDescriptor::validate(std::ostream &o, FunctionDescriptorMap& fdmap) {
  if (!insn)
    o << "Uninitialized call descriptor in set." << LEND;
  if (confidence == ConfidenceWrong) o << *this << LEND;
  for (CallTargetSet::iterator tit = targets.begin(); tit != targets.end(); tit++) {
    FunctionDescriptor* fd = fdmap.get_func(*tit);
    if (fd == NULL)  o << "No function description for call target "
                       << std::hex << *tit << " at call instruction "
                       << get_address() << std::dec << LEND;
  }
}

// Cycle through all the register-based calls to determine which are possibly virtual functions
bool CallDescriptor::check_virtual(PDG * pdg) {

  VirtualFunctionCallAnalyzer vcall(isSgAsmX86Instruction(get_insn()), pdg);

  if (vcall.analyze(call_info)) {
    // this is a virtual function.
    return true;
  }
  return false;
}

// Add a new address to the list of targets.  Update the connections after adding the new
// target.  Calling this method is less efficient that populating many target lists and then
// calling update_connections, but we want to discourage leaving things in an inconsistent
// state.
void CallDescriptor::add_target(rose_addr_t taddr) {
  targets.insert(taddr);
  update_connections();
}

// Add the specified import descriptor as a target of this call.  Update the appropriate
// linkages to keep the descriptor set consistent.  Currently, we really only handle calls that
// do or do not go to an import, so if this is update is made to a call descriptor that already
// has targets, we can't handle that properly.  Also, this routine should be kep in sync with
// the analyze() function that also add an import (but before we can call update_connections).
void CallDescriptor::add_import_target(ImportDescriptor* id) {
  // If we've already resolved this call, just return immediately.
  if (import_descriptor == id)
    return;

  // We should also never have calls that go to multiple different imports.  Well, actually it
  // apparently does happen.  Jeff found a file that calls to both CreateSolidBrush and
  // GetSysColorBrush from the same call location.  Both methods return an HBRUSH, and both
  // take a single int argument (the former takes a COLORREF, and the latter a nIndex).  My
  // guess is that eager optimization cause the situation.  In the future, we'll need to
  // support a list of imports, but for now just complain -- it's still really rare.
  if (import_descriptor != NULL) {
    GERROR << "Unexpected second import on call at " << addr_str(address)
           << "old=" << *import_descriptor << " new=" << *id << LEND;
    return;
  }

  // This would be a situation where the call resolves to more than one target but only one is
  // an import.  While peculiar, this error is not fatal, because we may still have a place to
  // record the import, unlike the previous error.  It will however cause the function
  // descriptors to be merged between the import and the other target, which has probably never
  // been tested.
  if (targets.size() != 0) {
    GERROR << "Call at " << addr_str(address) << " resolved to import " << *id
           << " and existing targets." << LEND;
  }

  // It should now be safe to update the call.
  import_descriptor = id;
  // Add the address of the import to the call target list.
  targets.insert(id->get_address());
  // Mark that the call is external to the program.
  call_location = CallExternal;
  // The assumption that imports don't change is a fairly reasonable assumption.
  confidence = ConfidenceConfident;
  // Add the back reference from the import to the caller.
  id->add_caller(address);

  // Enforce consistency with the other function descriptors, import descriptors, etc.
  update_connections();

  GDEBUG << "Resolved call target at " << address_string() << " calls to import "
         << id->get_long_name() << " at address " << id->address_string() << LEND;
}

// This function was originally desgined to be called once on each call descriptor during the
// initial creation of the call descriptors.  It performs the actions that cannot be completed
// until the function descriptors and import descriptors all exist (a chicken-and-the-egg style
// ordering problem).  Because of this, this function updates fields like containing function,
// that really only need to be set once, but there doesn't seem to any harm in calling it
// multiple times.  It has gradually become the "consistency enforcing" function that ensures
// that a call descriptor is kept in a rational state relative to the other descriptors.
void CallDescriptor::update_connections() {
  FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();

  rose_addr_t addr = get_address();
  // We can't update anything if we're not a real descriptor yet.
  if (addr == 0) return;

  // Update our containing function field, by finding the function that this instruction is in.
  assert(insn != NULL);
  const SgAsmFunction *func = insn_get_func(insn);
  assert(func != NULL);
  containing_function = global_descriptor_set->get_func(func->get_entry_va());
  assert(containing_function != NULL);

  containing_function->add_outgoing_call(this);

  // Deallocate the call's function descriptor if one was allocated, since we're about to
  // recompute the value (and possibly allocate a new one).
  if (function_allocated) delete function_descriptor;
  function_allocated = false;
  function_descriptor = NULL;

  // If we have an import descriptor, make sure it knows about us.
  if (import_descriptor != NULL) {
    import_descriptor->add_caller(addr);
    // A tiny bit of const nastiness here.  We need the declaration of function_descriptor to
    // be non-const for the cases wehere we allocate it to merge multiple functions together.
    // But the import descriptor API reasonably considers the function descriptor on it to be
    // const, since nobody else is supposed to be modifying it.  It appears that this
    // assignment doesn't do anything the first time through, because the function descriptors
    // haven't been populated on the import descriptors yet(?), but it will when it's called
    // again later.
    function_descriptor = import_descriptor->get_rw_function_descriptor();

    // No need to add a caller to the function descriptor, we've already added it to the import
    // descriptor.
  }

  // Update the targets list and the function descriptor in both directions.
  if (targets.size() == 1) {
    CallTargetSet::iterator target = targets.begin();
    rose_addr_t target_addr = *target;

    // The target might be the import descriptor target, which doesn't really exist in the
    // function map, so we need to check that the function exists before overwriting the
    FunctionDescriptor *fd = fdmap.get_func(target_addr);
    // If the address resolved to anything at all...
    if (fd != NULL) {
      // Now that we've got more complete information, we can follow thunks appropriately, and
      // decide whether we actually end up at an import.  Cory's not 100% sure that this is the
      // right place to do this, but it seems like a reasonable one at least.
      import_descriptor = fd->follow_thunks_id(NULL);
      // This code is duplicated from just above in part because there's still confusion about
      // how to handle call to multiple targets, one or more of which are to imports.
      if (import_descriptor != NULL) {
        import_descriptor->add_caller(addr);
        function_descriptor = import_descriptor->get_rw_function_descriptor();
        GDEBUG << "Resolved thunked call descriptor " << *this
               << " to import " << *import_descriptor << LEND;
      }
      // Of course the more likely scenario is that we just call to a normal function.
      else {
        function_descriptor = fd;
        function_descriptor->add_caller(addr);
      }
    }
  }
  else if (targets.size() > 1) {
    // Multiple call targets is the most complicated case.
    function_descriptor = new FunctionDescriptor();
    function_allocated = true;
    // Now merge each of the call targets into the merged description.
    for (rose_addr_t t : targets) {
      // This might include bogus addresses for the import descriptors, but that's ok, the test
      // for NULL will cause us to do the right thing.
      FunctionDescriptor* fd = fdmap.get_func(t);
      if (fd != NULL) function_descriptor->merge(fd);
    }
    // Now propgate any discoveries made during merging back to each of the call targets.
    // Also update the function description to record that this call is one of their callers.
    for (rose_addr_t t : targets) {
      FunctionDescriptor* fd = fdmap.get_func(t);
      if (fd != NULL) {
        fd->propagate(function_descriptor);
        fd->add_caller(addr);
      }
    }
  }
}

void CallDescriptor::update_call_type(CallType ct, GenericConfidence conf) {
  call_type = ct;
  confidence = conf;
}

void CallDescriptor::read_config(const boost::property_tree::ptree& tree,
                                 ImportNameMap* import_names) {
  // Address.  I'm somewhat uncertain about when we would need to override this.
  boost::optional<rose_addr_t> addr = tree.get_optional<rose_addr_t>("address");
  if (addr) {
    if (address != 0 && address != *addr) {
      GWARN << "Contradictory address in call " << addr_str(address) << "!=" << addr_str(*addr) << LEND;
    }
    else {
      address = *addr;
    }
  }

  // Call type.
  boost::optional<std::string> typestr = tree.get_optional<std::string>("type");
  if (typestr) {
    call_type = Str2Enum<CallType > (*typestr, CallUnknown);
    // Currently no confidence for type.
  }

  // Call location.
  boost::optional<std::string> locstr = tree.get_optional<std::string>("location");
  if (locstr) {
    call_location = Str2Enum<CallTargetLocation>(*locstr, CallLocationUnknown);
    // Currently no confidence for location.
  }

  // Import
  boost::optional<std::string> impstr = tree.get_optional<std::string>("import");
  if (impstr) {
    std::string lowered = to_lower(*impstr);
    ImportNameMap::iterator ifinder = import_names->find(lowered);
    if (ifinder != import_names->end()) {
      import_descriptor = ifinder->second;
      //GINFO << "Found import descriptor for: " << *impstr << LEND;
    } else {
      GERROR << "Unrecognized import '" << *impstr << "'." << LEND;
    }

    // There's currently no confidence for the import descriptor explicitly.  But the current
    // implementation makes defining an import equaivalent to having an empty target list, and
    // there is a confidence level for the target list which sortof applies to the import.
    confidence = ConfidenceUser;
  }

  // Read the function descriptor from the ptree branch "function".
  boost::optional<const boost::property_tree::ptree&> ftree = tree.get_child_optional("function");
  if (ftree) {
    function_override = new FunctionDescriptor();
    function_override->read_config(ftree.get());
  }

  // Targets needs to be copied from function callers.
  read_config_addr_set("targets", tree, targets);
}

void CallDescriptor::write_config(boost::property_tree::ptree* tree) {
  tree->put("address", address_string());
  tree->put("type", Enum2Str(call_type));
  tree->put("location", Enum2Str(call_location));

  write_config_addr_set("targets", tree, targets);

  if (function_allocated) {
    boost::property_tree::ptree ftree;
    function_descriptor->write_config(&ftree);
    tree->add_child("function", ftree);
  }

  if (import_descriptor != NULL) {
    tree->put("import", import_descriptor->get_long_name());
  }
}

void CallDescriptor::print(std::ostream &o) const {
  if (insn != NULL) {
    o << "Call: insn=" << debug_instruction(insn, 7);
  }
  else {
    o << "Call: insn=(NOT SET!) address=" << address_string();
  }

  o << " type=" << Enum2Str(call_type) << " conf=" << Enum2Str(confidence);
  if (import_descriptor != NULL) {
    o << " import=" << import_descriptor->get_long_name();
  }
  if (function_override != NULL) {
    o << " override=[" << function_override->debug_deltas() << " ]";
  }
  if (function_descriptor != NULL) {
    o << " func=[" << function_descriptor->debug_deltas() << " ]";
  }
  o << " targets=[" << std::hex;
  for (CallTargetSet::iterator it = targets.begin(); it != targets.end(); it++) {
    o << " " << *it;
  }
  o << " ]" << std::dec;
}

void CallDescriptor::analyze() {
  if (!insn) return;
  address = insn->get_address();
  bool complete;
  CallTargetSet successors;
  targets = insn->getSuccessors(&complete);
  GDEBUG << "CALL: " << debug_instruction(insn) << LEND;

  SgAsmOperandList *oplist = insn->get_operandList();
  SgAsmExpressionPtrList& elist = oplist->get_operands();
  //assert(elist.size() == 1);
  // note, a far call could actually have 2 operands, a segment and the
  // address, but let's just ignore that for now:
  if (elist.size() != 1) {
    GWARN << "Call descriptor at " << addr_str(address) << " has "
          << elist.size() << " parameters, skipping" << LEND;
    return;
  }

  SgAsmExpression* expr = elist[0];
  switch (expr->variantT()) {
    case V_SgAsmMemoryReferenceExpression: {
      SgAsmMemoryReferenceExpression* mr = isSgAsmMemoryReferenceExpression(expr);
      SgAsmExpression *addr_expr = mr->get_address();
      SgAsmIntegerValueExpression* addr_value = isSgAsmIntegerValueExpression(addr_expr);
      if (addr_value != NULL) {
        uint64_t v = addr_value->get_absoluteValue();
        ImportDescriptor *id = global_descriptor_set->get_import(v);
        if (id) {
          // We'd like to call add_import_target() here, but it calls update_connections, which
          // we're not ready for yet. Try to keep this in sync with add_import_target() :-(
          confidence = ConfidenceConfident;
          call_location = CallExternal;
          call_type = CallImport;
          import_descriptor = id;
          targets.insert(id->get_address());
        } else
          call_type = CallGlobalVariable;
      } else
        call_type = CallUnknown;
      break;
    }
    case V_SgAsmDirectRegisterExpression: {
      call_type = CallRegister;
      break;
    }
    case V_SgAsmIntegerValueExpression: {
      size_t arch_bits = global_descriptor_set->get_arch_bits();
      SgAsmIntegerValueExpression* int_expr = isSgAsmIntegerValueExpression(expr);
      if (int_expr->get_significantBits() != arch_bits) {
        GWARN << "Unexpected size for fixed call target address at" << address_string() << LEND;
      }
      confidence = ConfidenceCertain;
      call_location = CallExternal;
      call_type = CallImmediate;
      break;
    }
    default: {
      call_type = CallUnknown;
      GERROR << "Unexpected operand type in: " << debug_instruction(insn) << LEND;
      break;
    }
  }
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
