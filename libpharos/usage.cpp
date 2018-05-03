// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/graph/visitors.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/filtered_graph.hpp>

#include <rose.h>

#include "misc.hpp"
#include "masm.hpp"
#include "pdg.hpp"
#include "usage.hpp"
#include "method.hpp"
#include "cdg.hpp"

namespace pharos {

template<> char const* EnumStrings<AllocType>::data[] = {
  "Unknown",
  "Stack",
  "Heap",
  "Global",
  "Param",
};


using Rose::BinaryAnalysis::SymbolicExpr::OP_ITE;

// A hacked up routine to pick the correct object pointer from an ITE expression.  There's much
// better ways to implement this, but none that will be as easy for demonstrating that this is
// not a major architectural problem with the ITE expressions.  More NEWWAY fixes are required.
// Additionally, this function is currently only used in this file, but it might be useful
// elsewhere as well.
SymbolicValuePtr pick_this_ptr(SymbolicValuePtr& sv) {
  InternalNodePtr in = sv->get_expression()->isInteriorNode();
  if (in && in->getOperator() == OP_ITE) {
    // For right now, make a complete copy of the symbolic value, maintaining definers and so
    // forth.  Set the expression to just the half that we're interested in.
    SymbolicValuePtr newsv = sv->scopy();
    newsv->set_expression(in->child(1));
    return newsv;
  }
  else {
    return sv;
  }
}

ThisPtrUsage::ThisPtrUsage(FunctionDescriptor* f, SymbolicValuePtr tptr,
                           ThisCallMethod* tcm, SgAsmInstruction* call_insn) {
  assert(tptr);
  this_ptr = tptr;

  fd = f;
  assert(fd != NULL);

  // We don't know anything about our allocation yet.
  alloc_type = AllocUnknown;
  alloc_size = 0;
  alloc_insn = NULL;

  add_method(tcm, call_insn);
  analyze_alloc();
}

// Analyze the allocation type and location of this-pointers.
void ThisPtrUsage::analyze_alloc() {
  // Set the allocation type to unknown by default.
  alloc_type = AllocUnknown;

  // Use the type returned from get_memory_type() to determine our allocation type.  Perhaps in
  // the future thse can be fully combined, but this was what was required to support non-zero
  // ESP initialization.
  MemoryType type = this_ptr->get_memory_type();
  if (type == StackMemLocalVariable) {
    alloc_type = AllocLocalStack;
  }
  else if (type == StackMemParameter) {
    alloc_type = AllocParameter;
  }
  else if (type == UnknownMem) {
    // This code is really a function of get_memory_type() still being broken.
    // If we're not a constant address (global), skip this function.
    if (!this_ptr->is_number() || this_ptr->get_width() > 64) return;
    // This is a bit hackish, but also reject obviously invalid constants.
    size_t num = this_ptr->get_number();
    // Here's a place where we're having the age old debate about how to tell what is an
    // address with absolutely no context.  Cory still likes consistency.  Others have
    // suggested that we should be using the memory map despite all of it's flaws...
    // if (!global_descriptor_set->memory_in_image(num)) return;
    if (num < 0x10000 || num > 0x7FFFFFFF) return;
    // Otherwise, we look like a legit global address?
    alloc_type = AllocGlobal;
  }
  else {
    return;
  }

  // It's not actually clear why we're looking for the allocation instruction.  Perhaps we
  // should quit doing this and just use the tests above.  At least for now though, looking for
  // the common pattern allows us to detect some unusual situations.  Wes' previous logic also
  // filtered by requiring LEA instructions, so we're preserving that limit.

  // This code previously relied on the first-creator-of-read feature of modifiers, which we're
  // retiring.  Even though it's not clear that this code is required, I've updated it to use
  // latest definers in place of modifiers, only we haven't switch to just using the _latest_
  // definers yet so it needed some additional filtering to determine which definer to use.
  PDG* pdg = fd->get_pdg();
  // Shouldn't happen.
  if (!pdg) return;
  const DUAnalysis& du = pdg->get_usedef();

  // This is hackish too.  We need it for debugging so that we have some way of reporting which
  // instructions are involved in the confusion.
  SgAsmInstruction* first_insn = NULL;
  for (SgAsmInstruction *ginsn : this_ptr->get_defining_instructions()) {
    // For debugging so that we have an address.
    if (first_insn == NULL) first_insn = ginsn;

    SgAsmX86Instruction *insn = isSgAsmX86Instruction(ginsn);
    if (insn == NULL) continue;

    // Since definers isn't the "latest" definer just yet, filter our subsequent analysis to
    // the one that wrote the this-ptr value.  This is hackish and wrong because we shouldn't
    // have to filter.  But maybe once we can upgrade , this code can go away...
    auto writes = du.get_writes(insn);
    bool found_write = false;
    for (const AbstractAccess& aa : writes) {
      if (aa.value->get_expression()->isEquivalentTo(this_ptr->get_expression())) {
        found_write = true;
        break;
      }
    }
    // If this instruction didn't write the this-ptr, it's not the one that we're looking for.
    if (!found_write) continue;
    // If we're here, this should be the instruction that defined the this-pointer.

    // If we're a local variable and we've found an LEA instruction, that's probably the one
    // we're looking for.
    if (alloc_type == AllocLocalStack && insn->get_kind() == x86_lea) {
      alloc_insn = ginsn;
      GDEBUG << "Stack allocated object: " << *(this_ptr->get_expression()) << " at "
             << debug_instruction(alloc_insn) << LEND;
      return;
    }
    // For global variables, the typical cases are move or push instructions.
    else if (alloc_type == AllocGlobal &&
             (insn->get_kind() == x86_mov || insn->get_kind() == x86_push)) {
      alloc_insn = ginsn;
      GDEBUG << "Global static object: " << *(this_ptr->get_expression()) << " at "
             << debug_instruction(alloc_insn) << LEND;
      return;
    }
    // For passed parameters, we should probably be looking for the instruction that reads the
    // undefined this-pointer value.  This code was sufficient at the time...
    else if (alloc_type == AllocParameter) {
      GDEBUG << "Passed object: " << *(this_ptr->get_expression()) << LEND;
      return;
    }
  }

  if (first_insn == NULL) {
    GDEBUG << "No allocation instruction found for " << *(this_ptr->get_expression())
           << " alloc_type=" << Enum2Str(alloc_type) << LEND;
  }
  else {
    GDEBUG << "No allocation instruction found for " << *(this_ptr->get_expression())
           << " alloc_type=" << Enum2Str(alloc_type) << " at " << debug_instruction(first_insn) << LEND;
  }

  // Based on evaluation of the test suite, if we've reached this point, something's gone
  // wrong, and it's very unclear if we're really the allocation type we thought we were.
  // Perhaps it's better to be cautious and retract our allocation type claims.  We could also
  // choose to return the best guess of our type here, by removing this line.
  //alloc_type = AllocUnknown;
  return;
}

ObjectUse::ObjectUse(FunctionDescriptor* f) {
  fd = f;
  assert(fd != NULL);
  analyze_object_uses();
}

using VertexFound = std::runtime_error;

// Use a fancy std bidirectional thingie instead?
typedef std::map<SgAsmInstruction*, CFGVertex> InsnVertexMap;
typedef std::map<CFGVertex, SgAsmInstruction*> VertexInsnMap;

class CallOrderVisitor: public boost::default_bfs_visitor {
 public:
  InsnVertexMap call2vertex;
  VertexInsnMap vertex2call;
  // The current start vertex (so we don't match ourself).
  CFGVertex current;
  CallOrderVisitor() { }
  template < typename Graph >
  void discover_vertex(CFGVertex v, const Graph & g UNUSED) const {
    // Don't match ourself.
    if (v == current) {
      //const SgAsmInstruction* i = vertex2call.at(v);
      //OINFO << "Instruction " << addr_str(i->get_address()) << " ignored." << LEND;
      return;
    }
    // But if we match one of the other call instructions, we're done, so throw!
    if (vertex2call.find(v) != vertex2call.end()) {
      const SgAsmInstruction* call_insn = vertex2call.at(v);
      const SgAsmInstruction* curr_insn = vertex2call.at(current);
      GDEBUG << "Address " << addr_str(curr_insn->get_address())
             << " was disproven by address " << addr_str(call_insn->get_address()) << LEND;
      throw VertexFound("found");
    }
  }
  // Add an instruction to the bidirectional map.
  void add(SgAsmInstruction* i, CFGVertex v) {
    call2vertex[i] = v;
    vertex2call[v] = i;
  }
};

class NonReturningCFGFilter {
 public:
  std::set<CFGEdge> non_returning_edges;
  template <typename Graph>
  void add_vertex(Graph& cfg, CFGVertex v) {
    for (const CFGEdge& e: cfg_out_edges(cfg, v)) {
      non_returning_edges.insert(e);
    }
  }
  bool operator()(const CFGEdge& e) const {
    return(non_returning_edges.find(e) == non_returning_edges.end());
  }
};

void ObjectUse::update_ctor_dtor() const {
  // For each this-pointer... (since there can be multiple objects in a single function)
  for (const ThisPtrUsage& tpu : boost::adaptors::values(references)) {
    // A this-pointer usage (tpu) describes a particular object instance, including which
    // methods are called using the this pointer.
    tpu.update_ctor_dtor();
  }
}

// A new Prolog mode method to update the constructor/destructor booleans in the ThisCallMethod
// based on whether there are other function calls that come before or after the method.
void ThisPtrUsage::update_ctor_dtor() const {
  // =====================================================================================
  // Step 1. The key of the method evidence map is the call instruction that called the
  // method on the this-pointer.  Look through the CFG finding the vertex numbers for each of
  // the calls and add them to the CallOrderVisitor.

  NonReturningCFGFilter nrf;
  CallOrderVisitor cov;

  // How many more vertices do we need to find?
  size_t remaining = method_evidence.size();
  // If there are no method calls to find, we're done.
  if (remaining == 0) return;

  // Get the control flow graph.
  CFG& cfg = fd->get_rose_cfg();

  // For each vertex in the control flow graph.
  for (const CFGVertex& vertex : cfg_vertices(cfg)) {
    // Get the last instruction in the basic block.
    SgAsmBlock *bb = get(boost::vertex_name, cfg, vertex);
    const SgAsmInstruction* lastinsn = last_insn_in_block(bb);
    const SgAsmx86Instruction* lastxinsn = isSgAsmX86Instruction(lastinsn);

    // If the instruction is a call
    if (lastxinsn && insn_is_call(lastxinsn)) {
      // Get the call descriptor
      const CallDescriptor* cd = global_descriptor_set->get_call(lastinsn->get_address());
      // If the call never returns, add it to the list of non-returning vertices.
      if (cd && cd->get_never_returns()) {
        //OINFO << "Adding vertex to non-returning hash list..." << LEND;
        nrf.add_vertex(cfg, vertex);
      }
    }

    // See if it's one of the methods that we're looking for.
    for (const MethodEvidenceMap::value_type& mpair : method_evidence) {
      SgAsmInstruction* callinsn = mpair.first;
      if (lastinsn == callinsn) {
        //OINFO << "Adding insn to map: " << addr_str(callinsn->get_address()) << LEND;
        // Add the vertex to the vector of interesting call vertices.
        cov.add(callinsn, vertex);
        // We've found another...
        remaining--;
        // There's no point in looking through more method evidence since we found it.
        break;
      }
    }

    // If we've found them all we're done.
    if (remaining == 0) break;
  }

  // If we didn't find them all, that's very unexpected.
  if (remaining != 0) {
    GERROR << "We did not find all the CFG vertices in " << fd->address_string() << LEND;
  }

  // =====================================================================================
  // Step 2. For each method called update the constructor/destructor facts.

  // For each call instruction...
  for (const MethodEvidenceMap::value_type& mpair : method_evidence) {
    SgAsmInstruction* callinsn = mpair.first;
    CFGVertex s = cov.call2vertex[callinsn];
    //OINFO << "Considering call insn: " << addr_str(callinsn->get_address()) << LEND;
    // For each method called by that instruction... (usually just one)
    for (ThisCallMethod* tcm : mpair.second) {
      //OINFO << "Considering method: " << tcm->address_string() << LEND;
      // If we still think that we're possibly a constructor...
      if (tcm->no_calls_before) {
        //OINFO << "Method " << tcm->address_string() << " is a possible constructor." << LEND;
        try {
          // Mark our starting vertex and then do a breadth first search for one of the other
          // calls.  Reverse the graph because we want to search backwards in the CFG.
          cov.current = s;
          boost::filtered_graph<CFG, NonReturningCFGFilter> filtered_graph(cfg, nrf);
          auto reversed_graph = boost::make_reverse_graph(filtered_graph);
          boost::breadth_first_search(reversed_graph, s, visitor(cov));
        }
        // If the search threw VertexFound, there's another call before this method, so we're
        // not a constructor.   Update the ThisCallMethod to reflect this.
        catch (VertexFound) {
          GINFO << "Method " << tcm->address_string() << " is NOT a constructor because "
                << "of the call at " << addr_str(callinsn->get_address()) << LEND;
          // Mark the method as not a constructor.
          tcm->no_calls_before = false;
        }
      }

      // If we still think that we're possibly a destructor...
      if (tcm->no_calls_after) {
        //OINFO << "Method " << tcm->address_string() << " is a possible destructor." << LEND;
        try {
          // Mark our starting vertex and then do a breadth first search for one of the other
          cov.current = s;
          boost::filtered_graph<CFG, NonReturningCFGFilter> filtered_graph(cfg, nrf);
          boost::breadth_first_search(filtered_graph, s, visitor(cov));
        }
        // If the search threw VertexFound, there's another call after this method, so we're
        // not a destructor.   Update the ThisCallMethod to reflect this.
        catch (VertexFound) {
          GINFO << "Method " << tcm->address_string() << " is NOT a destructor because "
                << "of the call at " << addr_str(callinsn->get_address()) << LEND;
          // Mark the method as not a destructor.
          tcm->no_calls_after = false;
        }
      }
    }
  }
}

// Analyze the function and populate the references member with information about each
// this-pointer use in the function.  The approach is to use our knowledge about which methods
// are object oriented, by calling follow_oo_thunks(), which requires that we've set the
// oo_properties member on the function descriptor already.
void ObjectUse::analyze_object_uses() {
  for (CallDescriptor* cd : fd->get_outgoing_calls()) {
    // The the value in the this-pointer location (ECX) before the call.
    SymbolicValuePtr this_ptr = get_this_ptr_for_call(cd);
    GDEBUG << "This-Ptr for call at " << cd->address_string() <<  " is " << *this_ptr << LEND;
    // We're only interested in valid pointers.
    if (!(this_ptr->is_valid())) continue;
    // If the symbolic value is an ITE expression, pick the meaningful one.
    this_ptr = pick_this_ptr(this_ptr);
    GDEBUG << "Updated This-Ptr for call at " << cd->address_string()
           <<  " is " << *this_ptr << LEND;
    // Get the string representation of the this-pointer.
    SVHash hash = this_ptr->get_hash();

    // Go through each of the possible targets looking for OO methods.
    for (rose_addr_t target : cd->get_targets()) {
      // If we're not an OO method, we're not interested.
      ThisCallMethod* tcm = follow_oo_thunks(target);
      if (tcm == NULL) continue;

      // Do we already have any entry for this this-pointer?
      ThisPtrUsageMap::iterator finder = references.find(hash);
      // If we don't create a new entry for the this-pointer.
      if (finder == references.end()) {
        GDEBUG << "Adding ref this_ptr=" << *this_ptr << LEND;
        references.insert(ThisPtrUsageMap::value_type(hash,
          ThisPtrUsage(fd, this_ptr, tcm, cd->get_insn())));
      }
      // Otherwise, add this method to the existing list of methods.
      else {
        GDEBUG << "Adding method this_ptr=" << *this_ptr << LEND;
        finder->second.add_method(tcm, cd->get_insn());
      }
    }
  }
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
