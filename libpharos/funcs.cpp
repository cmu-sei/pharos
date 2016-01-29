// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>
#include <boost/foreach.hpp>
#include <boost/optional.hpp>
#include <boost/property_tree/ptree.hpp>

#include <rose.h>
#include <AstTraversal.h>
// For isNOP().
#include <sageInterfaceAsm.h>

#include "funcs.hpp"
#include "delta.hpp"
#include "sptrack.hpp"
#include "pdg.hpp"
#include "util.hpp"
#include "misc.hpp"

typedef boost::graph_traits<CFG>::vertex_descriptor CFGVertex;

template<> char const* EnumStrings<GenericConfidence>::data[] = {
  "None",
  "Wrong",
  "Guess",
  "Confident",
  "User",
  "Certain",
};

// This class handles translating between rose_addr_t and std::string when reading and writing
// boost::property_tree objects.
class RoseAddrTranslator
{
public:
  typedef std::string  internal_type;
  typedef rose_addr_t  external_type;

  RoseAddrTranslator() { }
  boost::optional<external_type> get_value(internal_type const& v) {
    external_type addr = parse_number(v);
    return addr;
  }
  boost::optional<internal_type> put_value(external_type const& v) {
    return str(boost::format("0x%08X") % v);
  }
};

// This registers the translator class with the property tree class so that it knows how to do
// the translation automatically.
namespace boost{ namespace property_tree {
    template<>
    struct translator_between<std::string, rose_addr_t>
    { typedef RoseAddrTranslator type; };
  }
}

bool FunctionDescriptorCompare::operator()(const FunctionDescriptor* x,
                                           const FunctionDescriptor* y) const {
  return (x->get_address() < y->get_address());
}

void read_config_addr_set(std::string key, const boost::property_tree::ptree& tree,
                          CallTargetSet &tset) {
  if (tree.count(key) > 0) {
    const boost::property_tree::ptree& ktree = tree.get_child(key);
    // Did the user ask to reset the caller list?  Always pull this entry out of the list
    // first, regardless of it's order.
    boost::optional<bool> reset = ktree.get_optional<bool>("empty");
    // If the option was present and its value was true, then reset the list.
    if (reset && *reset) {
      STRACE << "Clearing the set!" << LEND;
      tset.clear();
    }

    // Now step through each of the children (additions and deletions)
    BOOST_FOREACH(const boost::property_tree::ptree::value_type &v, ktree) {
      STRACE << "Caller 1st:" << v.first.data() << " 2nd:" << v.second.data() << LEND;
      if (v.first.data() == std::string("add")) {
        rose_addr_t caddr = v.second.get_value<rose_addr_t>();
        tset.insert(caddr);
      }
      else if (v.first.data() == std::string("delete")) {
        rose_addr_t caddr = v.second.get_value<rose_addr_t>();
        tset.erase(caddr);
      }
    }
  }
}

void write_config_addr_set(std::string key, boost::property_tree::ptree* tree,
                           CallTargetSet &tset) {
  if (tset.size() < 1) return;
  boost::property_tree::ptree stree;
  stree.add("empty", true);
  for (CallTargetSet::iterator it = tset.begin(); it != tset.end(); it++) {
    stree.add("add", *it);
  }
  tree->add_child(key, stree);
}

// We should have comment explaining why this constructor is required...
FunctionDescriptor::FunctionDescriptor() {
  address = 0;
  pdg = NULL;
  func = NULL;
  stack_delta = StackDelta(0, ConfidenceNone);
  stack_parameters = StackDelta(0, ConfidenceNone);
  returns_this_pointer = false;
  returns_eax = false;
  never_returns = false;
  target_func = NULL;
  target_address = 0;
  new_method = false;
  delete_method = false;
  excluded = false;
  hash = "";
  stack_analysis_failures = 0;

  // We'll build these when they're needed.
  control_flow_graph_cached = false;
  return_blocks_cached = false;
  pdg_cached = false;
}

FunctionDescriptor::FunctionDescriptor(SgAsmFunction* f) {
  // should really check for NULL pointer here
  if (f)
    address = f->get_entry_va();
  else
    address = 0;
  pdg = NULL;
  func = f;
  target_func = NULL;
  target_address = 0;
  new_method = false;
  delete_method = false;
  stack_delta = StackDelta(0, ConfidenceNone);
  stack_parameters = StackDelta(0, ConfidenceNone);
  returns_this_pointer = false;
  returns_eax = false;
  never_returns = false;
  excluded = false;
  hash = "";
  analyze();
  stack_analysis_failures = 0;

  // We'll build these when they're needed.
  control_flow_graph_cached = false;
  return_blocks_cached = false;
  pdg_cached = false;
}

FunctionDescriptor::~FunctionDescriptor() {
  if (pdg != NULL) {
    SCRAZY << "Destructing FunctionDescriptor (with PDG)!" << LEND;
    delete pdg;
    pdg = NULL;
    pdg_cached = false;
  }

  // free the list of stack variables
  for (StackVariableList::iterator it = stack_vars.begin() ; it != stack_vars.end(); ++it) {
     delete *it;
     *it = NULL;
  }
  stack_vars.clear();
}

// add a new stack variable to the list
void FunctionDescriptor::add_stack_variable(SgAsmX86Instruction *i, int64_t off, TreeNodePtr tnp) {

   StackVariable *var = new StackVariable(off,tnp);
   if (var != NULL) {
      if (i != NULL) {
         var->add_usage(i); // save the usage instruction for this variable
      }
      stack_vars.push_back(var);
   }
}

// Lookup a stack variable by its offset
StackVariable* FunctionDescriptor::get_stack_variable(int64_t offset) const {

   unsigned int i = 0;
   while (i < stack_vars.size()) {
      StackVariable *sv = stack_vars.at(i);

      // JSG think that looking up by offset is sufficient
      if (offset == sv->get_offset()) {
         return sv;
      }
      ++i;
   }
   return NULL;
}

// Get the name of the function.
std::string FunctionDescriptor::get_name() const {
  if (func == NULL) return std::string("<none>");

  std::string rose_name = func->get_name();
  if (rose_name != "") return rose_name;

  return boost::str(boost::format("sub_%x") % address);
}

// Set the name of the function.
void FunctionDescriptor::set_name(std::string name) {
  if (func != NULL) {
    func->set_name(name);
  }
  else {
    SERROR << "Tried to set the name of a NULL function!" << LEND;
  }
}

void FunctionDescriptor::read_config(const boost::property_tree::ptree& tree) {
  // Address.  I'm somewhat uncertain about when we would need to override this.
  boost::optional<rose_addr_t> addr = tree.get_optional<rose_addr_t>("address");
  if (addr) {
    if (address != 0 && address != *addr) {
      SERROR << "Warning: Contradictory address in function "
             <<  addr_str(address) << "!=" << addr_str(*addr) << LEND;
    }
    else {
      address = *addr;
    }
  }
  // Stack delta.
  boost::optional<int64_t> delta = tree.get_optional<int64_t>("delta");
  if (delta) {
    stack_delta = StackDelta(*delta, ConfidenceUser);
  }

  const CallingConvention* cc = NULL;
  // Calling convention.
  boost::optional<std::string> convstr = tree.get_optional<std::string>("convention");
  if (convstr) {
    // We used to look up the string in an enum.  Since we don't really understand how this
    // part of the code works right now, Cory's going to try and kludge things up a little to
    // keep them somewhat consistent.

    // Some inconsistency on whether we're using leading underscores...
    std::string ucc = "__" + *convstr;
    // Is it safe to access this already?
    const CallingConventionMatcher& matcher = global_descriptor_set->get_calling_conventions();
    // Find the calling convention, which is presumably __stdcall in practice?
    cc = matcher.find(32, ucc);
    // If we found one, add it to the calling conventions.
    if (cc != NULL) {
      calling_conventions.push_back(cc);
    }
  }

  // Stack parameters
  boost::optional<uint64_t> params = tree.get_optional<uint64_t>("parameter");
  if (params) {
    stack_parameters = StackDelta(*params, ConfidenceUser);
  }
  // This is one of the very few places we were using the value from the JSON file.
  else if (convstr && (*convstr).compare("stdcall") == 0) {
    // This is really quite wrong here.  I think you should probably have to specify the
    // stack parameters explicitly in every case.
    stack_parameters = StackDelta(stack_delta.delta, ConfidenceUser);
  }

  // Read the detailed parameter description from the JSON file.  This call shouldn't really
  // use the delta at all, but right now that's all we've got.  It needs to be invoked
  // conditionally here so that we're sure that we actually have a delta.  It's unclear to Cory
  // how this relates to importing the calling convention.  Obviously they're related somehow.
  // This used to be tied to the stack delta until Cory realized it was more correctly tied to
  // the usually identical parameters field.
  GTRACE << "Read JSON parameters: " << stack_parameters.delta << LEND;
  parameters.read_config(tree, stack_parameters.delta, cc);

  // Callers.
  read_config_addr_set("callers", tree, callers);

  // Now debug the newly updated function.
  GTRACE << "Read " << *this << LEND;
}

// Merge the important fields from the export descriptor loaded from a DLL config file.
void FunctionDescriptor::merge_export_descriptor(const FunctionDescriptor *dfd) {
  if (stack_delta.confidence <= ConfidenceUser) {
    stack_delta = dfd->get_stack_delta();
    // Stack parameters should perhaps be driven by a separate confidence level?
    stack_parameters = dfd->get_stack_parameters();
    // Copy parameter names and types from entry in the DLL config file.
    parameters = dfd->get_parameters();
    GDEBUG << "Merge imports before=" << dfd->get_parameters().get_params().size()
           << " after=" << parameters.get_params().size() << LEND;
  }
}

void FunctionDescriptor::write_config(boost::property_tree::ptree* tree) {
  if (address != 0) tree->put("address", address_string());
  tree->put("delta", stack_delta.delta);
  // What do when writing out the convention is more complex now that there's multiple answers.
  //tree->put("convention", Enum2Str(calling_convention));

  write_config_addr_set("callers", tree, callers);

  // Now moved to the register usage class.  We still need to implement writing here, but not
  // until we've finished populating the fields in the new class.
  //BOOST_FOREACH(std::string s, unchanged_state) {
  //  tree->add("unchanged", s);
  //}
  // Not really properly implemented yet.
  //BOOST_FOREACH(std::string p, parameter_state) {
  //  tree->add("parameter", p);
  //}
}

void FunctionDescriptor::merge(FunctionDescriptor *other) {
  // Obviously not implemented yet.  I need to decide how to handle confidence levels.
  STRACE << "Merging call target " << other->address_string()
         << " into function descriptor for " << address_string() << LEND;
  if (other != NULL) return;
  // WRONG WRONG WRONG, but at least it puts something in the current function.
  stack_delta = other->get_stack_delta();
}

void FunctionDescriptor::propagate(FunctionDescriptor *merged) {
  // Obviously not implemented yet.  I need to decide how to handle confidence levels.
  STRACE << "Propagating function descriptor for " << address_string()
         << " back into call target " << address_string() << LEND;
  if (merged != NULL) return;
}

void FunctionDescriptor::print(std::ostream &o) const {
  o << "Func: addr=" << address_string() << " delta=" << stack_delta << " conv=";
  BOOST_FOREACH(const CallingConvention* cc, calling_conventions) {
    o << " " << cc->get_name();
  }
  o << " callers=[";
  for (CallTargetSet::iterator cit = callers.begin(); cit != callers.end(); cit++) {
    o << str(boost::format(" 0x%08X") % *cit);
  }
  o << " ]";
}

std::string FunctionDescriptor::debug_deltas() const {
  std::stringstream s;
  s << " delta=" << stack_delta;
  return s.str();
}

void FunctionDescriptor::update_target_address() {
  // Determine whether we're a thunk, and if we are what address we jump to.

  // We're not a thunk unless this code says we are.
  target_address = 0;
  target_func = NULL;

  if (!func) return;
  SgAsmStatementPtrList& bb_list = func->get_statementList();
  // If there are no blocks in the function, we're very strange, and certainly not a thunk.
  if (bb_list.size() == 0) return;

  // Get the first block.  This might be wrong if the first block is not the entry point block,
  // but that's a more general problem that we're still investigating.
  SgAsmBlock* bblock = isSgAsmBlock(bb_list[0]);

  // If it's not an assembly block, then fail.  This allows other blocks to be present in the
  // function, but not for them to be first.  This might occur if there were data blocks
  // attached to the function.
  if (bblock == NULL) return;

  // Get the statement (instruction) list.
  SgAsmStatementPtrList& inslist = isSgAsmBlock(bb_list[0])->get_statementList();
  // Only permit a single instruction in the basic block.
  if (inslist.size() != 1) return;
  // Get that instruction, and presume that it's an x86 instruction. :-(
  SgAsmX86Instruction *insn = isSgAsmX86Instruction(inslist[0]);
  // There must be an instruction, and it must be a jump.
  if (insn == NULL) return;
  if (insn->get_kind() != x86_jmp && insn->get_kind() != x86_farjmp) return;

  // Get the successors.
  bool ignored = false;
  AddrSet successors = insn->getSuccessors(&ignored);

  // Because there's some difficulties surrounding the interpretation of imports, ROSE didn't
  // create control flow edges for the jumps to the dereferences of the import table.  Assuming
  // that they've been populated with real addreses when they haven't causes bad edges in the
  // control flow graph.  Here's our chance to correct the missing edges.  It's not clear to
  // Cory that this is the best way to do this.  Perhaps the function descriptor should point
  // to the import descriptor somehow, and it's thunkishness should be ignored...
  if (successors.size() == 0) {
    SDEBUG << "Successors for jump at " << address_string() << " is empty." << LEND;
    SgAsmOperandList *oplist = insn->get_operandList();
    SgAsmExpressionPtrList& elist = oplist->get_operands();
    // Jump instructions with with more than one operands are disassembled by ROSE from the
    // "EA" JMP opcode as: farJmp const 1, const2.  The first value apparently comes from a
    // segment register, and the second from a 32-bit register.
    if (elist.size() != 1) {
      SWARN << "JMP has " << elist.size() << " operands: " << debug_instruction(insn, 7) << LEND;
      return;
    }

    SgAsmExpression* expr = elist[0];
    SgAsmMemoryReferenceExpression* mr = isSgAsmMemoryReferenceExpression(expr);
    if (mr == NULL) {
      SDEBUG << "JMP at " << address_string() << " is NOT a memory deref." << LEND;
    }
    else {
      SDEBUG << "JMP at " << address_string() << " is a memory deref." << LEND;
      SgAsmExpression *addr_expr = mr->get_address();
      SgAsmIntegerValueExpression* int_expr = isSgAsmIntegerValueExpression(addr_expr);
      // Possible 32-bit architecture specific code?
      if (int_expr != NULL && int_expr->get_significantBits() == 32) {
        target_address = int_expr->get_absoluteValue();
        SDEBUG << "Function " << address_string() << " is a thunk that jumps to ["
               << addr_str(target_address) << "]." << LEND;
      }
    }
    // Don't fall through and allow our possibly updated target address to be overwritten.
    return;
  }

  // Anything other than one successor is highly unsuspected.
  if (successors.size() != 1) return;

  // Set the target address to the destination of the jump instruction.
  target_address = *(successors.begin());

  SDEBUG << "Function " << address_string() << " is a thunk that jumps to "
         << addr_str(target_address) << "." << LEND;

  // This routine leaves target_address and target_func out of sync, which is bad.  But we're
  // being called at the time that the FunctionDescriptor is originally created, meaning that
  // the function being jumped too may not have a function descriptor yet.  That's why this
  // function is private, and not public.  This inconsistency is corrected by calling the
  // update_connections() method below.
}

void FunctionDescriptor::update_connections(FunctionDescriptorMap& fdmap) {
  // Update connections between function descriptors.  Called for each function descriptor.

  if (is_thunk()) {
    // One possibility is that the jump target address is to another function.
    if (fdmap.find(target_address) != fdmap.end()) {
      // First record the matching function descriptor for the thunk address.
      target_func = &(fdmap[target_address]);
      // Then notify the target that we're one of several possible thunks that point to them.
      target_func->add_thunk(this);
    }
    // But the other possibility is that the address points to an import table entry.  Cory
    // thinks that there's growing awareness that the relationship between import descriptors
    // and function descriptors is backward.  This is one example of that, since there's no
    // where good to store the observation about the import case, and it has to be deferred
    // until later.  In this case, target_address and target_func have to be out of sync. :-(
  }
}

// Propagate important parameters to this function (like the return code booleans) if this
// function is a thunk.  While called at the very end of update_connections() in the descriptor
// set, this function is also called (untidily) at the beginning of analyze_return_code.  This
// is because properties like returns_eax could only be computed reliably after the PDG pass.
// A third place we might need to call this is after the calling convention and parameters are
// established in get_pdg().
void FunctionDescriptor::propagate_thunk_info() {
  // Don't require the caller the test whether we're a thunk or not.
  if (!is_thunk()) return;

  bool endless;
  // The address where we eventually end up.
  rose_addr_t taddr = follow_thunks(&endless);
  // Here's at least one case where we can set never returns.
  if (endless) {
    never_returns = true;
    return;
  }
  // Get the import descriptor for that address if there is one.
  ImportDescriptor* id = global_descriptor_set->get_import(taddr);
  if (id != NULL) {
    SDEBUG << "Function: " << address_string() << " is a thunk to an import: "
           << id->get_long_name() << "." << LEND;
    // In general, the best default assumption for an import is to assume that the function
    // does return a value, because most functions do.  In the future we should be
    // propagating return code type information here as well.  By default
    // returns_this_pointer is set to false, and should only be set to true when there's
    // positive evidence of that happening (which there is not here).
    returns_eax = true;

    // Propagate the (currently invented) parameters from the import descriptor to the thunk
    // that calls the import descriptor.
    const FunctionDescriptor* ifd = id->get_function_descriptor();
    parameters = ifd->get_parameters();

    return;
  }

  // Get the function descriptor for that address if there is one.
  FunctionDescriptor* fd = global_descriptor_set->get_func(taddr);
  if (fd != NULL) {
    SDEBUG << "Function: " << address_string() << " is a thunk to another function at "
           << fd->address_string() << "." << LEND;

    // In this case, just propagate the information from the called function onto the thunk.
    returns_this_pointer = fd->get_returns_this_pointer();
    returns_eax = fd->get_returns_eax();
    never_returns = fd->get_never_returns();

    // Parameters as well.
    parameters = fd->get_parameters();

    return;
  }

  // The only remaining case is one worth complaining about -- that we're a thunk to a
  // function that wasn't found during disassembly.  We don't really have any basis for
  // saying whether we return a value or not, but since it's more common to do so than not,
  // just wildly guess that we do.
  SWARN << "Function: " << address_string()
        << " is a thunk that jumps to the non-function address " << addr_str(taddr) << LEND;
  returns_eax = true;
}

void FunctionDescriptor::analyze() {
  if (!func) return;

  // If the func has a chunk w/ a lower address, calling get_address() returns that instead of
  // the entry_va.  We want to explicitly get the entry address.
  address = func->get_entry_va();
  // Determine whether we're a thunk.
  update_target_address();

  STRACE << "Analyzing function descriptor: " << *this << LEND;
  // Report anything odd about the function.
  check_for_disconnected_blocks();
}

void FunctionDescriptor::validate(std::ostream &o) {
  if (callers.size() == 0)
    o << "No callers for function " << address_string() << LEND;
}

void FunctionDescriptor::update_stack_delta(StackDelta sd) {
  if (sd.confidence < stack_delta.confidence) return;
  if (sd.confidence <= stack_delta.confidence && sd.delta != stack_delta.delta) {
    SERROR << "Attempt to change function stack delta without changing confidence for function: "
           << address_string() << " old=" << stack_delta << " new=" << sd << LEND;
    return;
  }
  STRACE << "Setting stack delta for " << address_string() << " to " << sd << LEND;
  stack_delta.delta = sd.delta;
  stack_delta.confidence = sd.confidence;
}

// Find the stack variables for this function. The algorithm to find the stack
// variables is one of elimination. First, get the initial stack pointer value
// by looking up the symbolic value for ESP (yes, I know this binds the code to
// 32bit x86 architectures). For each instruction in the function, check if that
// instruction uses the stack pointer, is not a saved register, and is not a
// function parameter.
//
// Note that this means that this analysis DEPENDS ON parameter analysis and
// saved register analysis!
//
// Also omit control flow instructions, because they cannot use the stack
// directly. The remainning instructions use the stack and are likely stack
// variables.
void FunctionDescriptor::update_stack_variables() {
   analyze_stack_variables(this);

}

// How many bytes of the previous stack frame did we access as parameters?  This function has
// had a longer and complicated evolution, and it's still not correct, but it's getting closer.
// It used to be in def use analysis before coming to funcs.cpp, and it may move again into
// RegisterUsage.  It may need additional cleanup since the code has changed so many times.
// Most recently, Cory has observed that we're not utilizing the fields populated in the
// calling convention object but rather hard-coding a bunch of them here and in get_pdg().  For
// example, should be using the param_order member (left-to-right versus right-to-left) to
// determine what order to to create the parameters in, but we just assume right-to-left.
void FunctionDescriptor::update_stack_parameters() {
  // The thing we're primarily looking for right now is the number of stack parameters.
  StackDelta sd = get_stack_delta();
  StackDelta maxparam = StackDelta(0, sd.confidence);

  // Get the PDG object...
  PDG* p = get_pdg();
  // And the UseDef object...
  const DUAnalysis& du = p->get_usedef();

  // For each instruction in the function in address order.  It might be more correct to use
  // some kind of flow order here, but that's not as convenient right now.
  BOOST_FOREACH(SgAsmX86Instruction* insn, get_insns_addr_order()) {
    // LEA's reference memory but do not "read" them... Therefore, let's determine if the value
    // being moved into the register could reference a function parameter.  This is old Wes
    // code, and Cory has cleaned it up some, but it's still a bit hackish.
    if (insn->get_kind() == x86_lea) {
      // Get the writes for this LEA instruction.
      const AbstractAccessVector* writes = du.get_writes(insn);
      // Shouldn't happen, but continuing prevents crashes.
      if (writes == NULL) continue;
      // Look for writes (to some register, but where the value is from a stack memory address.
      BOOST_FOREACH(const AbstractAccess& ac, *writes) {
        if (ac.value->get_memory_type() == StackMemParameter) {
          // Convert the "address" to a signed stack delta.
          //int32_t stack_addr = (int32_t)ac.value->get_number(); // replace get_stack_const()
          boost::optional<int64_t> osdelta = ac.value->get_stack_const();
          int64_t stack_addr = *osdelta;
          SDEBUG << "Found LEA that references a potential function parameter "
                 << debug_instruction(insn) << " stack_addr=" << stack_addr << LEND;
          // Strictly speaking, Chuck points out that we should be confirming that the register
          // that we wrote the value to is actually being used elsewhere, but this code is a bit
          // of a hack anyway.
          if (stack_addr > maxparam.delta) {
            maxparam.delta = stack_addr;
          }
        }
      }
    }

    // Get the dependencies for this instruction.  If there are none, then we're done.  The
    // primary cause of this appears to be instructions without semantics.
    const DUChain* deps = du.get_dependencies(insn);
    if (deps == NULL) {
      SDEBUG << "No depends_on entry for instruction: " << debug_instruction(insn) << LEND;
      continue;
    }

    // Now consider all of the definitions (d) that the instruction depends on.
    BOOST_FOREACH(const Definition& d, *deps) {
      // We're only interested in instructions with NULL definers for this analysis.
      if (d.definer != NULL) continue;
      // We're also only interested in memory accesses (specifically stack memory accesses).
      if (!d.access.is_mem()) continue;

      // Determine the type of the memory access, and possibly the stack delta as well.
      SymbolicValuePtr saddr = d.access.memory_address;
      MemoryType type = saddr->get_memory_type();
      boost::optional<int64_t> opt_stack_addr = saddr->get_stack_const();

      // Now handle each memory access type.  Most are just warnings or errors, but the case
      // for stack memory parameters is the one we're looking for...
      if (type == StackMemReturnAddress) {
        // Return instructions are supposed to access stack delta zero (the return address).
        if (insn->get_kind() == x86_ret) continue;

        // All other cases are deeply suspicious.  It appears that when these occur they are
        // generally the result of failed stack delta analysis, in other words the
        // instruction doesn't really access the return address, we just have the wrong value
        // for ESP.  Perhaps we should downgrade the confidence, and do something to
        // discourage propagating more errors?
        SWARN << "Suspicious access of stack return address by instruction: "
              << debug_instruction(insn) << LEND;
        // There's nothing to do with these except complain, so let go the next dependency...
        continue;
      }
      else if (type == StackMemParameter) {
        int64_t stack_addr = *opt_stack_addr;

        SDEBUG << "Parameters: " << debug_instruction(insn) << " sa=" << stack_addr << LEND;

        // This is the real case we've beeen narrowing in on.
        if (stack_addr < ARBITRARY_PARAM_LIMIT) {
          SDEBUG << "Found reference to a stack parameter at offset " << stack_addr
                 << ", creating needed parameter definition." << LEND;
          // Ensure that the parameter definition exists.  We don't have any details about
          // this parameter's name or type right now, so just use default values.  The minus
          // four is a 32-bit specific adjustment for the size of the return address. :-(
          ParameterDefinition* param = parameters.create_stack_parameter(stack_addr - 4);
          if (param == NULL) {
            // The call above should have created the value and returned it, but it is
            // possible for the call above to return NULL in exceptional circumstances.
            GWARN << "Unable to find parameter at stack delta " << stack_addr << "." << LEND;
          }
          else {
            // The pointed_to field in the input state is probably always NULL presently, but
            // this serves as a useful way to document how it might be populated from here more
            // robustly.
            const SymbolicStatePtr input_state = du.get_input_state();
            SymbolicValuePtr pointed_to = input_state->read_memory(d.access.value, get_arch_bits());
            param->set_stack_attributes(d.access.value, saddr, insn, pointed_to);
          }
        }

        SDEBUG << "No defining instruction for memory read of stack parameter at offset: "
               << stack_addr << " in: " << debug_instruction(insn) << LEND;
        if (stack_addr > maxparam.delta)
          maxparam.delta = stack_addr;
      }
      else if (type == StackMemLocalVariable) {
        // This case would represent program bugs accessing uninitialized variables, or more
        // likely stack delta analysis failures.
        int64_t stack_addr = *opt_stack_addr;
        SDEBUG << "No defining instruction for memory read of local stack variable at offset: "
               << stack_addr << " in: " << debug_instruction(insn) << LEND;
        continue;
      }
      else {
        SDEBUG << "No defining instruction for memory read of unknown address: "
               << *saddr << " in: " << debug_instruction(insn) << LEND;
        // I don't know what else to do with these right now, so ignore them.
        continue;
      }
    }
  }

  if (SDEBUG) {
    SDEBUG << "Parameters for function " << address_string() << " is "
           << maxparam << " bytes of stack space." << LEND;
    SDEBUG << "Parameters for function " << address_string() << " are: ";
    parameters.debug();
  }

  if (sd.delta != 0 && sd.delta != maxparam.delta) {
    // This error frequently occurs in conjunction with stack delta analysis failures, but
    // there's at most one message per function, so it doesn't necessarily need to be
    // downgraded to from WARN in order to reduce spew.  On the other hand it could if desired.
    SWARN << "Counted stack parameters for function " << address_string()
          << " do not match the non-zero stack delta." << LEND;
  }
  else if (!is_thunk()){
    // If our analysis of how many parameters we read is obviously wrong, don't propagate
    // information that will cause yet more failures.
    if (maxparam.delta >= ARBITRARY_PARAM_LIMIT) {
      // This error frequently occurs in conjunction with stack delta analysis failures, but
      // there's at most one message per function.  When it became one of the last frequent
      // messages at ERROR importance, Cory downgraded it to WARN.  We should move it back once
      // stack delta analysis is more robust.
      SWARN << "Too many parameters (" << maxparam.delta << ") for "
            << address_string() << " setting to zero." << LEND;
      // Overwrite the values in maxparam, with something less harmful.
      maxparam.delta = 0;
      maxparam.confidence = ConfidenceWrong;
    }

    set_stack_parameters(maxparam);
    // Do I have any thunks (that jump to me)?  If so update them with my stack parameters.
    BOOST_FOREACH(FunctionDescriptor *thunkfd, get_thunks()) {
      SDEBUG << "Updating max params for thunk at 0x" << thunkfd->address_string()
             << " with " << maxparam << LEND;
      thunkfd->set_stack_parameters(maxparam);
    }
  }
  else if (is_thunk()) {
    SDEBUG << "Deferring parameter update to thunk target " << LEND;
  }
}

// The purpose of this function is put the parameters passed in registers into the parameter
// list in the order specified by the calling convention.  If we didn't match a calling
// convention, the just push the parameters into the list in an arbitrary order, to maintain
// some consistency in the API.  It's possible to have registers in the calling convention that
// weren't actually used, but not to have parameters that aren't listed in the convention (if
// there were, then we wouldn't have matched the calling convention).
void FunctionDescriptor::update_register_parameters() {
  const DUAnalysis& du = pdg->get_usedef();
  // A handle to the input state for the function.
  const SymbolicStatePtr input_state = du.get_input_state();

  // Get the calling convention that we decided was most likely.
  const CallingConvention* cc = parameters.get_calling_convention();

  // If we didn't identify a calling convention, simply push the used parameter registers into
  // the parameter list in an arbitrary order.  This should probably at least be deterministic,
  // rather than based on pointer order, but sadly, that's inconvenient in C++. :-(
  if (cc == NULL) {
    BOOST_FOREACH(const RegisterEvidenceMap::value_type& rpair, register_usage.parameter_registers) {
      const RegisterDescriptor* rd = rpair.first;
      // Read the symbolic value for the specified register from input state.
      SymbolicValuePtr rpsv = input_state->read_register(*rd);
      GDEBUG << "Adding reg parameter '" << unparseX86Register(*rd, NULL)
             << "' to unknown convention for " << address_string() << " sv=" << *rpsv << LEND;
      // The pointed_to field is probably always NULL for our current system, but there might
      // be a situation in which we would start populating these fields based on types in the
      // future...
      SymbolicValuePtr pointed_to = input_state->read_memory(rpsv, get_arch_bits());
      parameters.create_reg_parameter(rd, rpsv, rpair.second, pointed_to);
    }
    // And we're done.
    return;
  }

  // For cases in which we know the calling convention, the source code order matters, so
  // process the parameters in the order specified in the calling convention.
  BOOST_FOREACH(const RegisterDescriptor* rd, cc->get_reg_params()) {
    RegisterEvidenceMap::iterator reg_finder = register_usage.parameter_registers.find(rd);
    if (reg_finder == register_usage.parameter_registers.end()) {
      GDEBUG << "But the register wasn't actually used by the function." << LEND;
      // It's unclear to Cory whether we really have to create a parameter here or not.  The
      // situation is that the calling convention says that there's a parameter, but we haven't
      // actually used it.
      // parameters.create_reg_parameter(rd, rpsv, NULL);
      GDEBUG << "Unused reg parameter '" << unparseX86Register(*rd, NULL)
             << "' to convention " << cc->get_name() << " for " << address_string() << LEND;
    }
    else {
      SymbolicValuePtr rpsv = input_state->read_register(*rd);

      GDEBUG << "Adding reg parameter '" << unparseX86Register(*rd, NULL) << "' to convention "
             << cc->get_name() << " for " << address_string() << " sv=" << *rpsv << LEND;
      const SgAsmInstruction* insn = reg_finder->second;
      // Same pointed_to behavior as mentioned above.
      SymbolicValuePtr pointed_to = input_state->read_memory(rpsv, get_arch_bits());
      parameters.create_reg_parameter(rd, rpsv, insn, pointed_to);
    }
  }
}

// Add the register identified in the calling convention to the returns parameter definition
// list.  If the calling convention is unrecognized, we currently do nothing, but we probably
// ought to put all of the modified registers into the list.  Also we don't currently support
// calling conventions that return a value in more than one register (e.g. certain large return
// values in EAX and EDX), nor do we support return values on the stack (non existent on X86
// architectures?)
void FunctionDescriptor::update_return_values() {
  // Functions that never return have no return value.
  if (never_returns) return;

  // Right now, we only support returning values in EAX, so if we don't return EAX, we're done.
  // Cory has commented this out, because we ought to be able to reach the same conclusion in a
  // better (?) way...
  // if (!returns_eax) return;

  // In other cases, we're going to look at the output state to get our symbolic values.
  const DUAnalysis& du = pdg->get_usedef();
  // A handle to the input state for the function.
  const SymbolicStatePtr output_state = du.get_output_state();

  // Get the calling convention that we decided was most likely.
  const CallingConvention* cc = parameters.get_calling_convention();

  // If we didn't identify a calling convention, simply push the modified registers into the
  // return value list in an arbitrary order.  This should probably at least be deterministic,
  // rather than based on pointer order, but sadly, that's inconvenient in C++. :-(
  if (cc == NULL) {
    // Not implemented.
    // OINFO << "Skipping creating return parameters for unrecognized calling convention." << LEND;
  }
  else {
    const RegisterDescriptor* retval_reg = cc->get_retval_register();
    if (retval_reg == NULL) {
      GERROR << "Calling conventions that don't return in registers is unsupported." << LEND;
      return;
    }

    SymbolicValuePtr retval = output_state->read_register(*retval_reg);
    if (!retval) {
      GERROR << "No value for return register in output state?" << LEND;
      return;
    }

    ParameterDefinition* pd = parameters.create_return_reg(retval_reg, retval);
    if (pd != NULL) {
      if (GDEBUG) {
        GDEBUG << "The return value for " << address_string() << " is: " << LEND;
        pd->debug();
      }
    }
  }
}

PDG * FunctionDescriptor::get_pdg(spTracker *sp) {
  if (pdg_cached) return pdg;
  // If we're an excluded function, don't try to compute the PDG.
  if (excluded) return NULL;

  if (sp == NULL) {
    sp = global_descriptor_set->get_spTracker();
  }
  // Set our stack delta analysis failures to zero, and reset the stack tracker.
  stack_analysis_failures = 0;
  sp->reset_recent_failures();
  GDEBUG << "Computing PDG for function " << address_string() << LEND;
  try {
    pdg = new PDG(this, sp);
  } catch(...) {
    GERROR << "Error building PDG (caught exception)" << LEND;
  }

  // How many stack delta analysis failures did we have?
  stack_analysis_failures = sp->get_recent_failures();
  if (stack_analysis_failures > 0) {
    // This is the primary place that we report stack delta analysis filaures right now.
    SWARN << "There were " << stack_analysis_failures
          << " stack delta analysis failures in function " << address_string() << LEND;
  }
  pdg_cached = true;

  // Analyze our calling convention.  Must be AFTER we've marked the PDG as cached, because
  // analyzing the calling convention will attempt to recurse into get_pdg().
  register_usage.analyze(this);

  // Curiously, we never seem to have thought too much about what this routine was doing for
  // thunks and other "lightwight" functions.  For thunks, we probably should NOT be setting
  // calling conventions and parameters from the analysis that we just completed, but instead
  // propagating information from where we jump to, which should now be processed since we're
  // typically calling get_pdg in bottom up order.
  if (is_thunk()) {
    GDEBUG << "Propagating parameters from thunk for " << address_string() << LEND;
    propagate_thunk_info();
  }
  else {
    // Now that we know what our register usage was, determine our calling conventions.
    const CallingConventionMatcher& matcher = global_descriptor_set->get_calling_conventions();
    calling_conventions = matcher.match(this);

    // Pick the most appropriate calling convention (the first one), and set it in the
    // ParameterList object.  If we didn't match any calling conventions, leave the convention
    // field set to NULL, which means that the calling convention is unrecognized, and that
    // the parameters and return values will contain all inputs and output of the function.
    if (calling_conventions.size() != 0) {
      // Get the first matching calling convention.  They should all be valid interpretations for
      // this function, and we've ordered the calling conventions such that the more useful or
      // interesting ones preceed the less useful ones.
      const CallingConvention* cc = *(calling_conventions.begin());

      // This is the only place we should be calling set_calling_convention().
      parameters.set_calling_convention(cc);
    }

    // Assume that registers always preceed all parameters (always true on Intel platforms?), and
    // create the register parameters.
    update_register_parameters();

    // Now create stack parameters based on how many bytes of the previous frame we accessed.
    update_stack_parameters();


    // Create the set of stack variables
    update_stack_variables();

    // Use the calling convention to determine which changed registers were intentionally changed
    // (return values) and which were just scratch registers.  If no calling convention has been
    // set, add all changed registers as return values.
    update_return_values();
  }

  return pdg;
}

// Get the PDG hash for the function.  This turns out to be really expensive -- like half the
// cost of the entire analysis of an OO program expensive... :-( The API for this is messy now
// because Cory was trying to keep from using the global descriptor set or it's members in
// these routines to avoid cyclical includes and other problems. But to be honest, passing the
// stack tracker here is probably worse, so maybe it's time to just give in declare
// global_descriptor_set as an extern.
std::string FunctionDescriptor::get_pdg_hash(unsigned int num_hash_funcs) {
  if (hash.size() != 0) return hash;
  PDG* p = get_pdg();
  if (p == NULL) return "";
  hash = p->getWeightedMaxHash(num_hash_funcs);
  return hash;
}

// For identifying address terms in the pic hash like routine below.
bool is_mem(const SgAsmExpression *exp) {
  extern DescriptorSet* global_descriptor_set;
  if (isSgAsmIntegerValueExpression(exp)) {
    uint64_t v = isSgAsmIntegerValueExpression(exp)->get_absoluteValue();
    return global_descriptor_set->memory_in_image(v);
  }
  else if (isSgAsmMemoryReferenceExpression(exp))
    return is_mem(isSgAsmMemoryReferenceExpression(exp)->get_address());
  else if (isSgAsmBinaryAdd(exp))
    return (is_mem(isSgAsmBinaryAdd(exp)->get_lhs()) ||
            is_mem(isSgAsmBinaryAdd(exp)->get_rhs()));
  else if (isSgAsmBinaryMultiply(exp))
    return (is_mem(isSgAsmBinaryMultiply(exp)->get_lhs()) ||
            is_mem(isSgAsmBinaryMultiply(exp)->get_rhs()));
  else if (isSgAsmBinarySubtract(exp))
    return (is_mem(isSgAsmBinarySubtract(exp)->get_lhs()) ||
            is_mem(isSgAsmBinarySubtract(exp)->get_rhs()));
  else if (isSgAsmBinaryDivide(exp))
    return (is_mem(isSgAsmBinaryDivide(exp)->get_lhs()) ||
            is_mem(isSgAsmBinaryDivide(exp)->get_rhs()));
  else if (isSgAsmBinaryMod(exp))
    return (is_mem(isSgAsmBinaryMod(exp)->get_lhs()) ||
            is_mem(isSgAsmBinaryMod(exp)->get_rhs()));
  else return false;
}

// This is NOT a PIC hash we've traditionally defined it.  For each instruction, this code does
// one of two things: it includes the only first opcode byte if there are "addresses" in the
// instruction, or it includes all of the opcode bytes.  It does not replace the address
// components of the instructions with zeros as the original algorithm did.  It also doesn't
// enforce address order as rigidly, excludes data, etc.  It was included in the current state
// simply because it was an attractive alternative to the PDG hash implementation above.
void FunctionDescriptor::compute_function_bytes() {
  // Clear any existing values in the strings.
  exact_bytes.clear();
  pic_bytes.clear();

  // For each block and instruction...
  SgAsmStatementPtrList& bb_list = func->get_statementList();
  for (size_t x = 0; x < bb_list.size(); x++) {
    SgAsmBlock *block = isSgAsmBlock(bb_list[x]);
    if (!block) continue;
    SgAsmStatementPtrList & ins_list = block->get_statementList();
    for (size_t y = 0; y < ins_list.size(); y++) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(ins_list[y]);
      if (!insn) continue;

      // Get the raw bytes...
      SgUnsignedCharList bytes = insn->get_raw_bytes();
      if (bytes.size() == 0) continue;

      // Just append all of the bytes to exact_bytes.
      BOOST_FOREACH(unsigned char c, bytes) exact_bytes.push_back(c);

      // For the PIC bytes, it's more complicated...

      // Whether we've found address bytes...
      bool possibleAddress = false;

      // Examine the operands.
      SgAsmExpressionPtrList &ops = insn->get_operandList()->get_operands();
      for (unsigned int z = 0; z < ops.size(); z++) {
        if (is_mem(ops[z])) {
          possibleAddress = true;
          break;
        }
      }

      // If we've found addresses, only include the first byte, because that's easy.  We
      // should really be doing somethign very different here.
      if (possibleAddress) {
        pic_bytes.push_back(bytes[0]);
        STRACE << "ADDR: " << debug_instruction(insn) << LEND;
      }
      // If there were no addreses, it's safe to append all of the instruction bytes.
      else {
        BOOST_FOREACH(unsigned char c, bytes) pic_bytes.push_back(c);
      }
    }
  }
}

const std::string& FunctionDescriptor::get_exact_bytes() {
  // If the bytes haven't been computed already, do so now.
  if (exact_bytes.size() == 0) compute_function_bytes();
  return exact_bytes;
}

const std::string& FunctionDescriptor::get_exact_hash() {
  // If the bytes haven't been computed already, do so now.
  if (exact_bytes.size() == 0) compute_function_bytes();
  // If the bytes haven't been hashed already, so so now.
  if (exact_hash.size() == 0) exact_hash = md5_hash(exact_bytes);
  return exact_hash;
}

const std::string& FunctionDescriptor::get_pic_bytes() {
  // If the bytes haven't been computed already, do so now.
  if (pic_bytes.size() == 0) compute_function_bytes();
  return pic_bytes;
}

const std::string& FunctionDescriptor::get_pic_hash() {
  // If the bytes haven't been computed already, do so now.
  if (pic_bytes.size() == 0) compute_function_bytes();
  // If the bytes haven't been hashed already, so so now.
  if (pic_hash.size() == 0) pic_hash = md5_hash(pic_bytes);
  return pic_hash;
}

CFG& FunctionDescriptor::get_cfg() {
  // If we've already done the work, just return the answer.
  if (control_flow_graph_cached) return control_flow_graph;
  // Otherwise, we have to do it now.
  rose::BinaryAnalysis::ControlFlow cfg_analyzer;
  control_flow_graph = cfg_analyzer.build_block_cfg_from_ast<CFG>(func);
  control_flow_graph_cached = true;
  return control_flow_graph;
}

// There may be a better way to do this, but if you have the address and want the instruction,
// this is the only way Cory is currently aware of.
SgAsmInstruction* FunctionDescriptor::get_insn(const rose_addr_t addr) const {
  // Iterate through basic blocks.
  SgAsmStatementPtrList & bb_list = func->get_statementList();
  for (size_t x = 0; x < bb_list.size(); x++) {
    SgAsmBlock *bb = isSgAsmBlock(bb_list[x]);
    if (bb == NULL) continue;
    SgAsmStatementPtrList & insns = bb->get_statementList();

    // Iterate through instructions
    for (size_t y = 0; y < insns.size(); y++) {
      SgAsmInstruction *insn = isSgAsmInstruction(insns[y]);
      if (insn == NULL) continue;
      if (insn->get_address() == addr) return insn;
    }
  }
  return NULL;
}

// I think this is adress order, but is it really?
X86InsnVector FunctionDescriptor::get_insns_addr_order() const {
  X86InsnVector result;
  // No function means no instructions.
  if (!func) return result;

  // Iterate through basic blocks.
  SgAsmStatementPtrList & bb_list = func->get_statementList();
  for (size_t x = 0; x < bb_list.size(); x++) {
    SgAsmBlock *bb = isSgAsmBlock(bb_list[x]);
    if (bb == NULL) continue;
    SgAsmStatementPtrList & insns = bb->get_statementList();

    // Iterate through instructions
    for (size_t y = 0; y < insns.size(); y++) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(insns[y]);
      if (insn != NULL) result.push_back(insn);
    }
  }

  return result;
}

// There's probably a better way to do this.  I'm specifically looking for all addresses in the
// function, not just those in the control flow graph, because among other purposes, I'm using
// this to reason about broken control flow in unusual corner cases.
// NOTE: SgAsmFunction::get_extent() looks to return a map of Extents that should be able to be
// used to check if addr is "in" a function (although not if it maps to an instruction exactly).
bool FunctionDescriptor::contains_addr(rose_addr_t addr) {
  // No function means no addresses.
  if (!func) return false;

  // Iterate through basic blocks.
  SgAsmStatementPtrList & bb_list = func->get_statementList();
  for (size_t x = 0; x < bb_list.size(); x++) {
    SgAsmBlock *bb = isSgAsmBlock(bb_list[x]);
    if (bb == NULL) continue;
    SgAsmStatementPtrList & insns = bb->get_statementList();

    // Iterate through instructions
    for (size_t y = 0; y < insns.size(); y++) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(insns[y]);
      if (insn == NULL) continue;
      if (insn->get_address() == addr) return true;
    }
  }

  return false;
}

BlockSet& FunctionDescriptor::get_return_blocks() {
  // If we've already done the work, just return the answer.
  if (return_blocks_cached) return return_blocks;
  // Otherwise, we have to do it now.
  CFG& cfg = get_cfg();

  std::vector<CFGVertex> retblocks = rose::BinaryAnalysis::ControlFlow().return_blocks(cfg, 0);
  for (size_t x = 0; x < retblocks.size(); x++) {
    SgAsmBlock *bb = get(boost::vertex_name, cfg, retblocks[x]);
    if (bb) return_blocks.insert(bb);
  }
  return return_blocks;
}

// A little helper function used below.
bool is_nop_block(SgAsmBlock* bb) {
  // Iterate through instructions, returning false on the first non-NOP instruction.
  SgAsmStatementPtrList & insns = bb->get_statementList();
  for (size_t y = 0; y < insns.size(); y++) {
    SgAsmX86Instruction *insn = isSgAsmX86Instruction(insns[y]);
    // We're hoping that we've already made instructions out of all the NOPs.
    if (insn == NULL) return false;

    // INT3 instructions are commonly used as padding.  I'm not sure if this should really be
    // here, but there should certainly be some code somewhere to accept INT3 as padding.
    if (insn->get_kind() == x86_int3) continue;

    // If there's an instruction and it's NOT a NOP, we're not a NOP block.
    // Say that fast three times. :-)
    if (SageInterface::isNOP(insn) != true) return false;
  }
  return true;
}

bool FunctionDescriptor::check_for_disconnected_blocks() {
  bool result = false;
  BlockSet blocks;

  STRACE << "Validating block connectivity in function: " << address_string() << LEND;

  // Iterate through basic blocks, adding them to the blocks list.
  SgAsmStatementPtrList & bblist = func->get_statementList();
  for (size_t x = 0; x < bblist.size(); x++) {
    SgAsmBlock *bb = isSgAsmBlock(bblist[x]);
    // Warn about non-code blocks?
    if (bb == NULL) {
      // Is this even possible?
      SWARN << "CFB Non-code basic block found in function: " << address_string()
            << " type is: " << bblist[x]->sage_class_name() << LEND;
      result = true;
    }
    else {
      blocks.insert(bb);
    }
  }

  // Now let's look at the blocks that are in the control flow.  Hmm... bummer.  It appears
  // that I can't use my get_cfg() call because I need a handle to the actual analyzer?
  // Really?

  rose::BinaryAnalysis::ControlFlow cfg_analyzer;
  CFG cfg = cfg_analyzer.build_block_cfg_from_ast<CFG>(func);
  CFGVertex entry_vertex = 0;
  std::vector<CFGVertex> cfgblocks = cfg_analyzer.flow_order(cfg, entry_vertex);

  SgAsmBlock *funceb = func->get_entry_block();
  SgAsmBlock *cfgeb = get(boost::vertex_name, cfg, cfgblocks[entry_vertex]);
  if (funceb == NULL) {
    SWARN << "CFB No entry block in function: " << address_string() << LEND;
  }

  if (funceb != cfgeb) {
    SWARN << "CFB Entry blocks do not match! 0x" << std::hex << funceb->get_address() << "!=0x"
          << cfgeb->get_address() << std::dec << " in function: " << address_string() << LEND;
    result = true;
  }

  for (size_t x = 0; x < cfgblocks.size(); x++) {
    SgAsmBlock *bb = get(boost::vertex_name, cfg, cfgblocks[x]);
    if (bb == NULL) {
      // Is this even possible?
      SWARN << "CFB Non-code basic block found in control flow for function: "
            << address_string() << " type is: " << bblist[x]->sage_class_name() << LEND;
      result = true;
    }
    else {
      BlockSet::iterator finder = blocks.find(bb);
      if (finder == blocks.end()) {
        SWARN << "CFB Block 0x" << std::hex << bb->get_address() << std::dec
              << " in control flow, not in statement list for function: " << address_string() << LEND;
        result = true;
      }
      else {
        blocks.erase(bb);
      }
    }
  }

  // Finally, see what's left in the list of blocks from the statement list that weren't in the
  // control flow.
  BOOST_FOREACH(SgAsmBlock* bb, blocks) {
    // Why was this basic block in function?
    unsigned int reason = bb->get_reason();
    // If the only reason the block wasn't in the control flow graph was because it was
    // padding, then that's ok.  Don't complain.
    if (reason == SgAsmBlock::BLK_PADDING) continue;

    // It's perfectly normal for jump tables to not appear in the control flow.  They're not
    // instructions, and so they shouldn't.
    if (reason == SgAsmBlock::BLK_JUMPTABLE) continue;

    // There are some problems detecting NOP block following jmp instructions.  Hopefully we'll
    // fix this in the disassembler, but in the mean time, don't complain too much about NOP
    // blocks that are not marked as NOP blocks just because they're not in the flow control.
    if (is_nop_block(bb)) {
      SWARN << "Ignoring non-control-flow NOP block in function: " << address_string() << LEND;
      continue;
    }

    SINFO << "CFB Block 0x" << std::hex << bb->get_address() << std::dec
          << " reason=" << bb->reason_str("", reason)
          << " in function: " << address_string() << " but not in control flow!" << LEND;
    result = true;
  }

  // The reason key is overwhelming if we print it every time, so here it is once:
  // L = left over blocks    N = NOP/zero padding     F = fragment
  // J = jump table          E = Function entry
  // H = CFG head            U = user-def reason      M = miscellaneous
  // 1 = first CFG traversal 2 = second CFG traversal 3 = third CFG traversal

  return result;
}

// The implementation of how to follow thunks is complicated because it has multiple corner
// conditions.  One is that the chain of thunk loops back on itself, and so we need to keep a
// visited list.  Another possibility is that at some point we reach an address that is not a
// function.  Presumably this was caused by a disassembly failure, but there might be other
// causes as well.  In this case we're not able to return a function descriptor, because there
// isn't one.  Another case is that the end of the thunk chain points to an import.  In this
// case, the only function descriptor is the one on the import, which can't be easily
// distinguished from a normal function descriptor

// The optimal API appears to be an implementation that returns addresses rather higher level
// constructs like function descriptors or import descriptors. It's easy to wrap the returned
// address in a call to get a function descriptor or an import descriptor if desired.

rose_addr_t FunctionDescriptor::follow_thunks(bool* endless) {
  // We've always got to returna value in endless if the caller requested one.
  if (endless != NULL) *endless = false;
  // A short circuit for the most common scenario (no thunks at all).
  if (!is_thunk()) return get_address();

  // Start with an empty list of visited addresses.
  AddrSet visited;
  // Start with this function.
  FunctionDescriptor* fd = this;
  // No follow thunk until we're done.
  while (true) {
    // Get the address of the current function.
    rose_addr_t faddr = fd->get_address();
    // If we've already visited this address, there's a loop.
    if (visited.find(faddr) != visited.end()) {
      // If the caller is interested in testing for endless loops, they will have passed a
      // pointer to a boolean for that purpose, if not, the boolean pointer defaults to
      // NULL.  Most callers don't care and can ignore this parameter.
      if (endless != NULL) {
        *endless = true;
      }
      // Log a warning, since endless loops in programs are always suspicious.
      SWARN << "Endless loop of thunks detected at " << address_string() << LEND;
      return faddr;
    }
    // Add this address to the list of visited addresses.
    visited.insert(faddr);
    // Get the next function descriptor in the chain if there is one.
    FunctionDescriptor* next_fd = fd->get_jmp_fd();
    // If there is a function descriptor, just follow it to the next function.
    if (next_fd != NULL) {
      fd = next_fd;
      continue;
    }

    // But if there wasn't a function descriptor we're at the end of the chain.  First check to
    // see if there was an address, but just no function descriptor to go with it.
    rose_addr_t next_addr = fd->get_jmp_addr();
    // If the target address is zero, then we're not a thunk at all.  That makes the current
    // function the end of the chain, and that address is in faddr.  Return it now.
    if (next_addr == 0) return faddr;
    // Regardless of whether the end of the chain is an import descriptor or a disassembly
    // failure, the correct answer is in next_addr.  Return it now.
    return next_addr;
  }
}

// Forces the address returned from follow_thunks into a function descriptor or NULL.
FunctionDescriptor* FunctionDescriptor::follow_thunks_fd(bool* endless) {
  rose_addr_t target = follow_thunks(endless);
  return global_descriptor_set->get_func(target);
}

// Forces the address returned from follow_thunks into an import descriptor or NULL.
ImportDescriptor* FunctionDescriptor::follow_thunks_id(bool* endless) {
  rose_addr_t target = follow_thunks(endless);
  return global_descriptor_set->get_import(target);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
