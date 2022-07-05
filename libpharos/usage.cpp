// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/graph/visitors.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/filtered_graph.hpp>

#include "misc.hpp"
#include "masm.hpp"
#include "pdg.hpp"
#include "usage.hpp"
#include "method.hpp"
#include "cdg.hpp"
#include "ooanalyzer.hpp"

namespace pharos {

template<> char const* EnumStrings<AllocType>::data[] = {
  "Unknown",
  "Stack",
  "Heap",
  "Global",
  "Param",
};
template std::string Enum2Str<AllocType>(AllocType);

using Rose::BinaryAnalysis::SymbolicExpr::OP_ITE;

// A hacked up routine to pick the correct object pointer from an ITE expression.  There's much
// better ways to implement this, but none that will be as easy for demonstrating that this is
// not a major architectural problem with the ITE expressions.  More NEWWAY fixes are required.
SymbolicValuePtr pick_this_ptr(const SymbolicValuePtr& sv) {
  TreeNodePtr oldexpr = sv->get_expression();
  TreeNodePtr newexpr = pick_non_null_expr(oldexpr);
  if (newexpr == oldexpr) {
    return sv;
  }
  else {
    // Make a complete copy of the symbolic value, maintaining definers and so forth.  Set the
    // expression to just the half that we're interested in.
    SymbolicValuePtr newsv = sv->scopy();
    newsv->set_expression(newexpr);
    return newsv;
  }
}

TreeNodePtr pick_non_null_expr(const TreeNodePtr& expr) {
  using Rose::BinaryAnalysis::SymbolicExpr::OP_ITE;
  InternalNodePtr in = expr->isInteriorNode();
  if (in && in->getOperator() == OP_ITE) {
    // Check whether the parameter was of the form "ite(cond value 0)", if it is, just return
    // the hash of value so that it matches unconditional uses of the value, since our
    // primary goal in the OO analysis is to match-up OO pointers, and testing for NULL right
    // after allocation is a _very_ common paradigm.  We could do better here by exporting
    // facts for all possible values or something like that.

    // The expression is a conditional, first check for the NULL in child(2).
    if (in->child(2)->isIntegerConstant() &&
        in->child(2)->toUnsigned() && *in->child(2)->toUnsigned() == 0) {
      return in->child(1);
    }
    // and then in child(1).
    else if (in->child(1)->isIntegerConstant()
             && in->child(1)->toUnsigned() && *in->child(1)->toUnsigned() == 0) {
      return in->child(2);
    }
  }
  return expr;
}

ThisPtrUsage::ThisPtrUsage(const FunctionDescriptor* f, SymbolicValuePtr tptr,
                           const ThisCallMethod* tcm, SgAsmInstruction* call_insn) : fd(f) {
  assert(tptr);
  this_ptr = tptr;

  assert(fd != NULL);

  expanded_this_ptr = expand_thisptr (fd, call_insn, this_ptr);

  // We don't know anything about our allocation yet.
  alloc_type = AllocUnknown;
  alloc_size = 0;
  alloc_insn = NULL;

  add_method(tcm, call_insn);
  analyze_alloc();
}

// This method takes a thisptr as input, and tries to replace variable references for unknown
// memory reads with the corresponding read expression.
TreeNodePtr ThisPtrUsage::expand_thisptr(const FunctionDescriptor *fd, SgAsmInstruction* insn, const SymbolicValuePtr this_ptr_in) {

  auto thisptr = this_ptr_in->get_expression ();

  // Check for more than one definer?
  if (this_ptr_in->get_defining_instructions ().size () > 1) {
    GDEBUG << "expand_thisptr: Ignoring expression with more than one defining instruction: " << *this_ptr_in << LEND;
    return thisptr;
  }

  const auto &du = fd->get_pdg()->get_usedef();

  auto deps = du.get_dependencies(insn->get_address());

  if (!deps) {
    // No dependencies
    return thisptr;
  }

  std::set<RegisterDescriptor> seen_rds;

  // Look for multiple abstract accesses for the same operand
  for (const auto & dep : *deps) {
    const auto aa = dep.access;
    assert (aa.value);
    if (!aa.is_mem()) {
      if (seen_rds.count (aa.register_descriptor)) {
        GDEBUG << "Multiple dependencies of register " << aa.str () << " detected, bailing out." << aa.str () << LEND;
        return thisptr;
      }
      seen_rds.insert (aa.register_descriptor);
    }
  }

  for (const auto & dep : *deps) {
    const auto aa = dep.access;
    assert (aa.value);

    // If aa.value is not in the thisptr expression, we can skip it to save time.
    if (!has_subexp (thisptr, aa.value->get_expression ()))
      continue;

    if (dep.definer) {
      // Ok, let's see if we can expand aa.value
      const auto expanded = expand_thisptr (fd, dep.definer, aa.value);
      thisptr = thisptr->substitute (aa.value->get_expression (), expanded);
    } else {
      // Dependency has no definer.  Hopefully it's a memory read
      if (aa.is_mem () && aa.memory_address && aa.isRead) {
        GDEBUG << "Address: " << *aa.memory_address << LEND;
        GDEBUG << "Value: " << *aa.value << LEND;
        // Create a mem variable for each bitwidth
        const auto get_mem_for_bits = [fd] (const unsigned bits) {
          static std::map<unsigned, TreeNodePtr> m;

          if (!m.count (bits))
            m [bits] = SymbolicExpr::makeMemoryVariable (fd->ds.get_arch_bits(), bits, "Mem");

          return m.at (bits);
        };
        const auto mem = get_mem_for_bits (aa.value->get_expression()->nBits());
        const auto expanded = SymbolicExpr::makeRead (mem, aa.memory_address->get_expression ());
        thisptr = thisptr->substitute (aa.value->get_expression (), expanded);
      }
    }
  }

  return thisptr;
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
    if (!this_ptr->isConcrete() || this_ptr->get_width() > 64) return;
    // This is a bit hackish, but also reject obviously invalid constants.
    size_t num = *this_ptr->toUnsigned();
    // Here's a place where we're having the age old debate about how to tell what is an
    // address with absolutely no context.  Cory still likes consistency.  Others have
    // suggested that we should be using the memory map despite all of it's flaws...
    // if (!ds->memory_in_image(num)) return;
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
  const PDG* pdg = fd->get_pdg();
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
    auto writes = du.get_writes(insn->get_address());
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

ObjectUse::ObjectUse(OOAnalyzer& ooa, const FunctionDescriptor* f) {
  fd = f;
  assert(fd != NULL);
  analyze_object_uses(ooa);
}

struct VertexFound : public std::runtime_error {
  using std::runtime_error::runtime_error;
};
struct Aborted : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

// Use a fancy std bidirectional thingie instead?
using InsnVertexMap = std::map<SgAsmInstruction*, CFGVertex>;
using VertexInsnMap = std::map<CFGVertex, SgAsmInstruction*>;

// XXX: Should just pass a pointer to ThisCallPtr to cov
class CallOrderVisitor: public boost::default_bfs_visitor {
 public:
  InsnVertexMap call2vertex;
  VertexInsnMap vertex2call;
  SymbolicValuePtr this_ptr;
  const MethodEvidenceMap &method_evidence;
  const OOAnalyzer &ooa;
  const FunctionDescriptor *fd;
  bool constructor = true;
  // The current start vertex (so we don't match ourself).
  CFGVertex current;

  // This is pretty hacky.  If tcm is non-NULL, then we are searching for a call to tcm.
  // Otherwise we are looking normally.  If Ed was non-lazy, he would create a separate visitor
  // for this.
  ThisCallMethod *tcm;

  CallOrderVisitor(const MethodEvidenceMap &method_evidence_,
                   const OOAnalyzer &ooa_,
                   const FunctionDescriptor *fd_)
    : method_evidence (method_evidence_),
      ooa (ooa_),
      fd (fd_)
  { }
  template < typename Graph >
  void discover_vertex(CFGVertex v, const Graph & g) const {

    if (constructor) {
      // When traversing dataflow backwards, we should stop if we hit a call to new.  This
      // isn't quite correct because we are doing BFS, and there could be another path.  But
      // that is probably pathological, and not enough to merit doing a full dataflow analysis
      // here.
      auto bb = get(boost::vertex_name, g, v);
      assert (bb);
      auto stmts = bb->get_statementList ();

      auto calls_new = [&] (const SgAsmStatement* insn) {
        assert (insn);

        auto cd = fd->ds.get_call (insn->get_address ());
        // Is this a call?
        if (!cd) return false;

        // Is this a call to new?
        auto call_targets = cd->get_targets ();
        auto is_new = [&] (const auto &addr) { return ooa.is_new_method (addr); };
        if (boost::find_if (call_targets, is_new) == call_targets.end ()) return false;
        // Ok, it's a call to new.  Does it return our this pointer?
        auto return_value = cd->get_return_value ();
        if (!return_value) return false;
        return return_value->get_expression()->isEquivalentTo (this_ptr->get_expression());
      };

      // Does this BB have any calls to new for the current thisptr?
      if (boost::find_if (stmts, calls_new) != stmts.end ()) {
        throw Aborted ("aborted");
      }
    }

    // Don't match ourself.
    if (v == current) {
      //rose_addr_t a = vertex2call.at(v);
      //OINFO << "Instruction " << addr_str(a) << " ignored." << LEND;
      return;
    }
    // But if we match one of the other call instructions, we're done, so throw!
    if (vertex2call.find(v) != vertex2call.end()) {
      SgAsmInstruction* callinsn = vertex2call.at (v);
      SgAsmInstruction* currinsn = vertex2call.at (current);

      if (!constructor) {
        // When looking to disprove destructors, we should stop if hit delete.  The same caveat
        // holds are for constructors above that this may stop the search prematurely.  The
        // check is here because delete looks like a method call on the thisptr, so it will be
        // present in vertex2call.
        auto call_targets = method_evidence.find (callinsn)->second;
        auto is_delete = [&] (const ThisCallMethod* target) {
          return ooa.is_candidate_delete_method (target->get_address ()); };

        if (boost::find_if (call_targets, is_delete) != call_targets.end ()) {
          throw Aborted ("aborted");
        }
      }


      // If tcm is set, then we're searching for a call to tcm specifically. Otherwise we're
      // searching for any other method call.
      if (tcm) {
        auto is_tcm = [&] (const ThisCallMethod *target) {
          return target == tcm;
        };

        auto call_targets = method_evidence.find (callinsn)->second;
        if (boost::find_if (call_targets, is_tcm) != call_targets.end ()) {
          // We found a call to tcm
          GDEBUG << "A call to constructor/destructor candidate at address " << addr_str(currinsn->get_address ())
                 << " was also found at an earlier/later address " << addr_str(callinsn->get_address ())
                 << " and therefore we will not analyze this callsite." << LEND;
          throw VertexFound ("tcm");
        }
      } else {
        GDEBUG << "The call to constructor/destructor candidate at address " << addr_str(currinsn->get_address ())
               << " was disproven by the earlier/later call at address " << addr_str(callinsn->get_address ()) << LEND;
        throw VertexFound ("vertexfound");
      }
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

void ObjectUse::update_ctor_dtor(OOAnalyzer& ooa) const {
  // For each this-pointer... (since there can be multiple objects in a single function)
  for (const ThisPtrUsage& tpu : boost::adaptors::values(references)) {
    // A this-pointer usage (tpu) describes a particular object instance, including which
    // methods are called using the this pointer.
    tpu.update_ctor_dtor(ooa);
  }
}

// A new Prolog mode method to update the constructor/destructor booleans in the ThisCallMethod
// based on whether there are other function calls that come before or after the method.
void ThisPtrUsage::update_ctor_dtor(OOAnalyzer& ooa) const {
  // =====================================================================================
  // Step 1. The key of the method evidence map is the call instruction that called the
  // method on the this-pointer.  Look through the CFG finding the vertex numbers for each of
  // the calls and add them to the CallOrderVisitor.

  NonReturningCFGFilter nrf;
  CallOrderVisitor cov (method_evidence, ooa, fd);

  // How many more vertices do we need to find?
  size_t remaining = method_evidence.size();
  // If there are no method calls to find, we're done.
  if (remaining == 0) return;

  // Get the control flow graph.
  CFG cfg = fd->get_rose_cfg();

  // Remove cycles from the graph.  Generally speaking, we assume that all operations on the
  // same thisptr occur on the same object.  But in rare occasions, the same memory may be used
  // for distinct objects.  In these cases, the object will be destructed and constructed more
  // than once.  But at this point, we do not know what methods are constructors and
  // destructors, so we may not be able to tell where this happens.  This is particularly
  // problematic in loops, because the backedge of the loop may allow a method to appear to be
  // called before the constructor, but in reality that can never happen because the object
  // will always be destructed before exiting the loop.  By removing the backedges from the
  // graph, we prevent this from happening.  Ed believes there is no negative consequence of
  // doing this, or if there is, it's very contrived and rare.  Basically, this change says
  // that when looking for constructors and destructors, we only look at object instances that
  // originate outside of the loop; we do not examine objects coming from a previous loop
  // iteration.
  std::vector<CFGEdge> back_edges;

  depth_first_search (cfg,
                      boost::visitor(boost::make_dfs_visitor (boost::write_property (boost::typed_identity_property_map<CFGEdge> (),
                                                                                     std::back_inserter (back_edges),
                                                                                     boost::on_back_edge ()))).
                      root_vertex (fd->get_entry_vertex ()));

  for (const CFGEdge &e : back_edges) {
    boost::remove_edge (e, cfg);
  }

  // For each vertex in the control flow graph.
  for (const CFGVertex& vertex : cfg_vertices(cfg)) {
    // Get the last instruction in the basic block.
    SgAsmBlock *bb = get(boost::vertex_name, cfg, vertex);
    const SgAsmInstruction* lastinsn = last_insn_in_block(bb);
    const SgAsmX86Instruction* lastxinsn = isSgAsmX86Instruction(lastinsn);

    // If the instruction is a call
    if (lastxinsn && insn_is_call(lastxinsn)) {
      // Get the call descriptor
      const CallDescriptor* cd = fd->ds.get_call(lastinsn->get_address());
      // If the call never returns, add it to the list of non-returning vertices.
      if (cd && cd->get_never_returns()) {
        //OINFO << "Adding vertex to non-returning hash list..." << LEND;
        nrf.add_vertex(cfg, vertex);
      }
    }

    // See if it's one of the methods that we're looking for.
    for (const MethodEvidenceMap::value_type& mpair : method_evidence) {
      SgAsmInstruction* callinsn = mpair.first;
      if (lastinsn->get_address() == callinsn->get_address()) {
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
    rose_addr_t caddr = callinsn->get_address();
    auto s_found = cov.call2vertex.find(callinsn);
    if (s_found == cov.call2vertex.end()) {
      GERROR << "Unable to find " << addr_str(caddr) << " in " << " call order visitor." << LEND;
      continue;
    }
    CFGVertex s = s_found->second;
    //OINFO << "Considering call insn: " << addr_str(caddr) << LEND;
    // For each method called by that instruction... (usually just one)
    for (const ThisCallMethod* tcm : mpair.second) {
      // Convert const tcm to non-const wtcm, so we can update the properties.
      ThisCallMethod* wtcm = ooa.get_method_rw(tcm->get_address());

      //OINFO << "Considering method: " << wtcm->address_string() << LEND;
      // If we still think that we're possibly a constructor...
      if (wtcm->no_calls_before) {
        GDEBUG << "Method " << wtcm->address_string() << " is a possible constructor." << LEND;

        bool is_first_call_of_tcm = true;

        try {

          // First, check to see if this is the "first call to wtcm" on this ptr.

          cov.current = s;
          cov.constructor = true;
          cov.this_ptr = this_ptr;
          cov.tcm = wtcm;
          boost::filtered_graph<CFG, NonReturningCFGFilter> filtered_graph(cfg, nrf);
          auto reversed_graph = boost::make_reverse_graph(filtered_graph);
          boost::breadth_first_search(reversed_graph, s, visitor(cov));
          // We are okay to continue
          is_first_call_of_tcm = true;
        }
        catch (VertexFound&) {
          // We found an earlier call of tcm
          is_first_call_of_tcm = false;
          GDEBUG << addr_str(caddr) << " is not the first call of method " << wtcm->address_string () << " on thisptr.  Skipping analysis of callsite." << LEND;
        }
        catch (Aborted&) {
          // We found a new or delete.  Continue with the normal search.
          is_first_call_of_tcm = true;
        }


        if (is_first_call_of_tcm) {
          try {
            // Mark our starting vertex and then do a breadth first search for one of the other
            // calls.  Reverse the graph because we want to search backwards in the CFG.
            cov.current = s;
            cov.constructor = true;
            cov.this_ptr = this_ptr;
            cov.tcm = NULL;
            boost::filtered_graph<CFG, NonReturningCFGFilter> filtered_graph(cfg, nrf);
            auto reversed_graph = boost::make_reverse_graph(filtered_graph);
            boost::breadth_first_search(reversed_graph, s, visitor(cov));
          }
          // If the search threw VertexFound, there's another call before this method, so we're
          // not a constructor.   Update the ThisCallMethod to reflect this.
          catch (VertexFound&) {
            GINFO << "Method " << wtcm->address_string() << " is NOT a constructor because "
                  << "of the call at " << addr_str(caddr) << LEND;
            // Mark the method as not a constructor.
            wtcm->no_calls_before = false;
          }
          catch (Aborted&) {
            GDEBUG << "Search to disprove method " << wtcm->address_string() << " is a constructor aborted when examining the call to "
                   << addr_str(caddr) <<  " because a call to new/delete was reached" << LEND;
          }
        }
      }

      // If we still think that we're possibly a destructor...
      if (wtcm->no_calls_after) {

        bool is_last_call_of_tcm = true;

        try {
          // Check to see if this is the last call to this method
          cov.current = s;
          cov.constructor = false;
          cov.this_ptr = this_ptr;
          cov.tcm = wtcm;
          boost::filtered_graph<CFG, NonReturningCFGFilter> filtered_graph(cfg, nrf);
          boost::breadth_first_search(filtered_graph, s, visitor(cov));

          is_last_call_of_tcm = true;
        }
        catch (VertexFound&) {
          // We found a later call of tcm
          GDEBUG << addr_str(caddr) << " is not the last call of method " << wtcm->address_string () << " on thisptr.  Skipping analysis of callsite." << LEND;
          is_last_call_of_tcm = false;
        }
        catch (Aborted&) {
          // We found a new or delete.  Continue with the normal search.
          is_last_call_of_tcm = true;
        }

        if (is_last_call_of_tcm) {
          GDEBUG << "Method " << wtcm->address_string() << " is a possible destructor." << LEND;
          try {
            // Mark our starting vertex and then do a breadth first search for one of the other
            cov.current = s;
            cov.constructor = false;
            cov.this_ptr = this_ptr;
            cov.tcm = NULL;
            boost::filtered_graph<CFG, NonReturningCFGFilter> filtered_graph(cfg, nrf);
            boost::breadth_first_search(filtered_graph, s, visitor(cov));
          }
          // If the search threw VertexFound, there's another call after this method, so we're
          // not a destructor.   Update the ThisCallMethod to reflect this.
          catch (VertexFound&) {
            GINFO << "Method " << wtcm->address_string() << " is NOT a destructor because "
                  << "of the call at " << addr_str(caddr) << LEND;
            // Mark the method as not a destructor.
            wtcm->no_calls_after = false;
          }
          catch (Aborted&) {
            GDEBUG << "Search to disprove method " << wtcm->address_string () << " is a destructor aborted when examining the call to "
                   << addr_str(caddr) << " because a call to new/delete was reached" << LEND;
          }
        }
      }
    }
  }
}


// Find the value of ECX at the time of the call, by inspecting the state that was saved when
// the call was evaluated.  Previously in method.cpp, and noew use here only in
// analyze_object_uses() immediately below.
SymbolicValuePtr get_this_ptr_for_call(const CallDescriptor* cd) {
  const SymbolicStatePtr state = cd->get_state();
  if (state == NULL) {
    // Customize this message a little to account for known failure modes.,
    if (cd->is_tail_call()) {
      GINFO << "Tail call at " << cd->address_string() << " was not analyzed correctly for OO this-pointers." << LEND;
    }
    else {
      GINFO << "Call at " << cd->address_string() << " was not analyzed correctly for OO this-pointers." << LEND;
    }
    return SymbolicValue::instance();
  }
  // We should be able to find this globally somehow...
  RegisterDescriptor this_reg = cd->ds.get_arch_reg(THIS_PTR_STR);
  assert(this_reg.is_valid());
  // Read ECX from the state immediately before the call.
  SymbolicValuePtr this_value = state->read_register(this_reg);
  return this_value;
}

// Analyze the function and populate the references member with information about each
// this-pointer use in the function.  We were filtering based on which methods were known to be
// object oriented by calling follow thunks, but that's heavily dependent on the order in which
// the functions are analyzed.
void ObjectUse::analyze_object_uses(OOAnalyzer const & ooa) {
  for (const CallDescriptor* cd : fd->get_outgoing_calls()) {
    // The the value in the this-pointer location (ECX) before the call.
    SymbolicValuePtr this_ptr = get_this_ptr_for_call(cd);
    // We're only interested in valid pointers.
    if (!(this_ptr->is_valid())) continue;
    GTRACE << "This-Ptr for call at " << cd->address_string() <<  " is " << *this_ptr << LEND;
    // If the symbolic value is an ITE expression, pick the meaningful one.
    this_ptr = pick_this_ptr(this_ptr);
    GTRACE << "Updated This-Ptr for call at " << cd->address_string()
           <<  " is " << *this_ptr << LEND;
    // Get the string representation of the this-pointer.
    SVHash hash = this_ptr->get_hash();

    // Go through each of the possible targets looking for OO methods.
    for (rose_addr_t target : cd->get_targets()) {
      // If we're not an OO method, we're not interested.
      // We can't tell properly right now anyway because we're being called from visit()!!!
      const ThisCallMethod* tcm = ooa.follow_thunks(target);
      if (tcm == nullptr) continue;

      // Do we already have any entry for this this-pointer?
      ThisPtrUsageMap::iterator finder = references.find(hash);
      // If we don't create a new entry for the this-pointer.
      if (finder == references.end()) {
        GTRACE << "Adding ref this_ptr=" << *this_ptr << LEND;
        references.insert(ThisPtrUsageMap::value_type(
                            hash, ThisPtrUsage(fd, this_ptr, tcm, cd->get_insn())));
      }
      // Otherwise, add this method to the existing list of methods.
      else {
        GTRACE << "Adding method this_ptr=" << *this_ptr << LEND;
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
