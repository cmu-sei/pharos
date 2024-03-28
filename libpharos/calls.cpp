// Copyright 2015-2024 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/optional.hpp>
#include <boost/property_map/property_map.hpp>

#include "rose.hpp"
#include <AstTraversal.h>

#include "calls.hpp"
#include "masm.hpp"
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

LeafNodePtr CallDescriptor::get_stack_delta_variable() const {
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
    size_t arch_bits = ds.get_arch_bits();
    stack_delta_variable = SymbolicExpr::makeIntegerVariable(
      arch_bits, "", UNKNOWN_STACK_DELTA);
  }
  return stack_delta_variable;
}

StackDelta CallDescriptor::get_stack_delta() const {
  GTRACE << "Getting stack delta for " << *this << LEND;

  // Apparently imported descriptor has to be first.  I should be more consistent in describing
  // the contract for which fields are meaningful under what conditions.
  if (import_descriptor != NULL) {
    GTRACE << "Call descriptor calls " << *import_descriptor << LEND;
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
      const ImportDescriptor* tid = ds.get_import(thunk_addr);
      if (tid != NULL) {
        GTRACE << "Call descriptor calls " << tid->get_long_name() << " through missed thunks." << LEND;
        return tid->get_stack_delta();
      }

      // Now see if there's a function at the specified address.
      const FunctionDescriptor *thunk_fd = ds.get_func(thunk_addr);
      if (thunk_fd == NULL) {
        GTRACE << "Call descriptor calls " << *function_descriptor << LEND;
        merged = function_descriptor->get_stack_delta();
      } else {
        GTRACE << "Got stack delta for thunk target " << *thunk_fd << LEND;
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
      GTRACE << "Call descriptor override " << *function_override << LEND;
      merged = function_override->get_stack_delta();
    }

    // More of the rest of the complex logic should be handlded by the updating of the
    // "concensus" function descriptor in this call descriptor (so it's already built into
    // merged).
    GTRACE << "Final stack delta according to call_descriptor" << merged << LEND;
    return merged;
  }
  // We've got no idea where the function calls to, and so we have no idea what the stack delta
  // was unless the user (or maybe some future constaint based stack solving) told us.
  else {
    return stack_delta;
  }
}

StackDelta CallDescriptor::get_stack_parameters() const {
  GTRACE << "Getting stack parameters for " << *this << LEND;

  // Apparently imported descriptor has to be first.  I should be more consistent in describing
  // the contract for which fields are meaningful under what conditions.
  if (import_descriptor != NULL) {
    GTRACE << "Call descriptor calls " << *import_descriptor << LEND;
    return import_descriptor->get_stack_parameters();
  }
  // The cases in which we have a function descriptor are very similar.
  else if (function_override != NULL || function_descriptor != NULL) {
    // If the user provided a stack parameters override, use it.
    if (function_override != NULL) {
      GTRACE << "Call descriptor stack parameters overriden " << *function_override << LEND;
      return function_override->get_stack_parameters();
    }
    // Other wise use whatever function descriptor we've got.
    if (function_descriptor != NULL) {
      // Cory's conflicted about whether he should have to be doing this here.  We should
      // probably propograte this information automatically, but we want to do it without
      // destroying the ability to understand the actual thunks as well.
      if (function_descriptor->is_thunk()) {
        rose_addr_t taddr = function_descriptor->follow_thunks(NULL);
        const ImportDescriptor* tid = ds.get_import(taddr);
        if (tid != NULL) {
          GTRACE << "Call at " << address_string() << " gets parameters from import "
                 << *tid << LEND;
          return tid->get_stack_parameters();
        }
        else {
          const FunctionDescriptor* tfd = ds.get_func(taddr);
          if (tfd != NULL) {
            GTRACE << "Call at " << address_string() << " gets parameters from function at "
                   << tfd->address_string() << LEND;
            return tfd->get_stack_parameters();
          }
          else {
            GTRACE << "Call at " << address_string()
                   << " has bad parameters because it's a thunk to a non-function. " << LEND;
            return function_descriptor->get_stack_parameters();
          }
        }
      }
      else {
        GTRACE << "Call descriptor calls " << *function_descriptor << LEND;
        return function_descriptor->get_stack_parameters();
      }
    }
  }

  if (stack_delta.confidence == ConfidenceNone) {
    GTRACE << "Call descriptor has no stack parameter data." << LEND;
  }
  return stack_delta;
}

void CallDescriptor::validate(std::ostream &o, const FunctionDescriptorMap& fdmap) const {
  if (!insn)
    o << "Uninitialized call descriptor in set." << LEND;
  if (confidence == ConfidenceWrong) o << *this << LEND;
  for (auto & tit : targets.values()) {
    const FunctionDescriptor* fd = fdmap.get_func(tit);
    if (fd == NULL)  o << "No function description for call target "
                       << std::hex << tit << " at call instruction "
                       << get_address() << std::dec << LEND;
  }
}

// Add a new address to the list of targets.  Update the connections after adding the new
// target.  Calling this method is less efficient that populating many target lists and then
// calling update_connections, but we want to discourage leaving things in an inconsistent
// state.
void CallDescriptor::add_target(rose_addr_t taddr) {
  write_guard<decltype(mutex)> guard{mutex};
  if (!targets.exists(taddr)) {
    targets.insert(taddr);
    _update_connections();
  }
}

bool CallDescriptor::get_never_returns() const {
  // If we have no idea about the call targets, assume that the call returns.
  if (targets.size() == 0) return false;

  // For each call target, if that target returns, then the call returns.
  for (rose_addr_t target : targets.values()) {
    const FunctionDescriptor* cfd = ds.get_func(target);
    if (cfd) {
      //OINFO << "Call " << address_string() << " calls " << cfd->address_string()
      //      << " which returns = " << cfd->get_never_returns() << LEND;
      if (! cfd->get_never_returns()) return false;
    }
#if 0
    // We should get the never returns status from the import database!
    else {
      const ImportDescriptor* cid = ds.get_import(target);
      if (cid) {
        OINFO << "Call " << address_string() << " calls " << cid->address_string()
              << " which is " << cid->get_long_name() << LEND;
      }
    }
#endif
  }
  // If none of the targets ever return, the call does not return.
  return true;
}

// Add the specified import descriptor as a target of this call.  Update the appropriate
// linkages to keep the descriptor set consistent.  Currently, we really only handle calls that
// do or do not go to an import, so if this is update is made to a call descriptor that already
// has targets, we can't handle that properly.  Also, this routine should be kep in sync with
// the analyze() function that also add an import (but before we can call update_connections).
void CallDescriptor::add_import_target(ImportDescriptor* id) {
  write_guard<decltype(mutex)> guard{mutex};

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
  _update_connections();

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
void CallDescriptor::_update_connections() {
  // We can't update anything if we're not a real descriptor yet.
  if (address == 0) {
    GERROR << "Updating connections for NULL call descriptor!" << LEND;
    return;
  }

  // Update our containing function field, by finding the function that this instruction is in.
  assert(insn != NULL);
  for (FunctionDescriptor *cfd : ds.get_rw_funcs_containing_address(address)) {
    cfd->add_outgoing_call(this);
    containing_function = cfd;
  }

  // Deallocate the call's function descriptor if one was allocated, since we're about to
  // recompute the value (and possibly allocate a new one).
  function_descriptor = nullptr;
  owned_function_descriptor.reset();

  // If we have an import descriptor, make sure it knows about us.
  if (import_descriptor != NULL) {
    import_descriptor->add_caller(address);
    // A tiny bit of const nastiness here.  We need the declaration of function_descriptor to
    // be non-const for the cases wehere we allocate it to merge multiple functions together.
    // But the import descriptor API reasonably considers the function descriptor on it to be
    // const, since nobody else is supposed to be modifying it.  It appears that this
    // assignment doesn't do anything the first time through, because the function descriptors
    // haven't been populated on the import descriptors yet(?), but it will when it's called
    // again later.
    function_descriptor = import_descriptor->get_rw_function_descriptor(); // in update_connections()

    // No need to add a caller to the function descriptor, we've already added it to the import
    // descriptor.
  }

  // Update the targets list and the function descriptor in both directions.
  if (targets.size() == 1) {
    rose_addr_t target_addr = targets.least();

    // The target might be the import descriptor target, which doesn't really exist in the
    // function map, so we need to check that the function exists before overwriting the
    FunctionDescriptor *fd = ds.get_rw_func(target_addr); // in update_connections()
    // If the address resolved to anything at all...
    if (fd != NULL) {
      // Now that we've got more complete information, we can follow thunks appropriately, and
      // decide whether we actually end up at an import.  Cory's not 100% sure that this is the
      // right place to do this, but it seems like a reasonable one at least.

      bool endless = false;
      rose_addr_t fdtarget = fd->follow_thunks(&endless);
      import_descriptor = ds.get_rw_import(fdtarget); // in update_connections()
      // This code is duplicated from just above in part because there's still confusion about
      // how to handle call to multiple targets, one or more of which are to imports.
      if (import_descriptor != NULL) {
        import_descriptor->add_caller(address);
        function_descriptor = import_descriptor->get_rw_function_descriptor(); // in update_connections()
        // While this message is usually fairly harmless, in some files, the import descriptor
        // contains a very large list of call targets, making this message rather more annoying
        // than helpful unless you're explicitly debugging a call descriptor problem.
        //GTRACE << "Resolved thunked call descriptor " << self{*this}
        //       << " to import " << *import_descriptor << LEND;
      }
      // Of course the more likely scenario is that we just call to a normal function.
      else {
        function_descriptor = fd;
        function_descriptor->add_caller(address);
      }
    }
  }
  else if (targets.size() > 1) {
    // Multiple call targets is the most complicated case.
    owned_function_descriptor = std::make_unique<FunctionDescriptor>(ds);
    function_descriptor = owned_function_descriptor.get();
    // Now merge each of the call targets into the merged description.
    for (rose_addr_t t : targets.values()) {
      // This might include bogus addresses for the import descriptors, but that's ok, the test
      // for NULL will cause us to do the right thing.
      const FunctionDescriptor* fd = ds.get_func(t);
      if (fd != NULL) function_descriptor->merge(fd);
    }
    // Now propgate any discoveries made during merging back to each of the call targets.
    // Also update the function description to record that this call is one of their callers.
    for (rose_addr_t t : targets.values()) {
      FunctionDescriptor* fd = ds.get_rw_func(t); // in update_connections()
      if (fd != NULL) {
        fd->propagate(function_descriptor);
        fd->add_caller(address);
      }
    }
  }
}

void CallDescriptor::update_call_type(CallType ct, GenericConfidence conf) {
  write_guard<decltype(mutex)> guard{mutex};
  call_type = ct;
  confidence = conf;
}

void
CallDescriptor::add_virtual_resolution(
  VirtualFunctionCallInformation& vci,
  GenericConfidence conf)
{
  write_guard<decltype(mutex)> guard{mutex};
  // Begin by marking the call as a virtual function call.
  call_type = CallVirtualFunction;
  confidence = conf;
  // Add the virtual call information to the descriptor.
  virtual_calls.push_back(vci);
}

void CallDescriptor::_print(std::ostream &o) const {

  if (insn != NULL) {
    o << "Call: insn=" << debug_instruction(insn, 7);
  }
  else {
    o << "Call: insn=(NOT SET!) address=" << address_string();
  }

  o << " loc=" << Enum2Str(call_location);
  o << " type=" << Enum2Str(call_type) << " conf=" << Enum2Str(confidence);
  if (import_descriptor != NULL) {
    o << " import=" << import_descriptor->get_long_name();
  }
  if (function_override != NULL) {
    o << " override=[" << function_override->address_string()
      << " " << function_override->debug_deltas() << " ]";
  }
  if (function_descriptor != NULL) {
    o << " func=[" << function_descriptor->address_string()
      << " " << function_descriptor->debug_deltas() << " ]";
  }
  o << " targets=[" << std::hex;
  for (auto & t : targets.values()) {
    o << " " << t;
  }
  o << " ]" << std::dec;
}

void CallDescriptor::analyze() {
  assert(insn != NULL);
  address = insn->get_address();
  bool complete;
  CallTargetSet successors;
  targets = insn->architecture()->getSuccessors(insn, complete);
  //GTRACE << "CALL: " << debug_instruction(insn) << LEND;

  SgAsmOperandList *oplist = insn->get_operandList();
  SgAsmExpressionPtrList& elist = oplist->get_operands();
  //assert(elist.size() == 1);
  // note, a far call could actually have 2 operands, a segment and the
  // address, but let's just ignore that for now:
  if (elist.size() != 1) {
    GWARN << "Call descriptor at " << debug_instruction(insn) << " has "
          << elist.size() << " operands, skipping" << LEND;
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
       ImportDescriptor *id = ds.get_rw_import(v); // Set in CD
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
     size_t arch_bits = ds.get_arch_bits();
     SgAsmIntegerValueExpression* int_expr = isSgAsmIntegerValueExpression(expr);
     if (int_expr->get_significantBits() != arch_bits) {
       GWARN << "Unexpected size for fixed call target address at" << address_string() << LEND;
     }
     confidence = ConfidenceCertain;
     call_location = CallInternal;
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

CallParamInfo CallParamInfoBuilder::create(CallDescriptor const & cd) const {
  ValueList values;
  for (auto & param : cd.get_parameters().get_params()) {
    auto value = param.get_value();
    auto & type = param.get_type();
    auto tref = type.empty() ? std::make_shared<typedb::UnknownType>("<unknown>")
                : db.lookup(type);
    values.push_back(tref->get_value(value, memory, &*cd.get_state()));
  }
  return CallParamInfo(cd, std::move(values));
}


} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
