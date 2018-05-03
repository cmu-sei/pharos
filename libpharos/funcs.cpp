// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>
#include <boost/optional.hpp>
#include <boost/property_tree/ptree.hpp>

#include <rose.h>
#include <AstTraversal.h>
// For isNOP().
#include <sageInterfaceAsm.h>

#include <BinaryUnparser.h>
#include <BinaryUnparserBase.h>

#include "funcs.hpp"
#include "delta.hpp"
#include "sptrack.hpp"
#include "pdg.hpp"
#include "util.hpp"
#include "misc.hpp"
#include "stkvar.hpp"
#include "method.hpp"
#include "masm.hpp"

#include <boost/graph/iteration_macros.hpp>

namespace P2 = Rose::BinaryAnalysis::Partitioner2;
namespace BA = Rose::BinaryAnalysis;

namespace pharos {

typedef boost::graph_traits<CFG>::vertex_descriptor CFGVertex;

template<> char const* EnumStrings<GenericConfidence>::data[] = {
  "None",
  "Wrong",
  "Guess",
  "Missing",
  "Confident",
  "User",
  "Certain",
  "Unspecified"
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

} // namespace pharos

// This registers the translator class with the property tree class so that it knows how to do
// the translation automatically.
namespace boost{ namespace property_tree {
    template<>
    struct translator_between<std::string, rose_addr_t>
    { typedef pharos::RoseAddrTranslator type; };
  }
}

namespace pharos {

bool FunctionDescriptorCompare::operator()(const FunctionDescriptor* x,
                                           const FunctionDescriptor* y) const {
  return (x->get_address() < y->get_address());
}

void read_config_addr_set(const std::string & key, const boost::property_tree::ptree& tree,
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
    for (const boost::property_tree::ptree::value_type &v : ktree) {
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

void write_config_addr_set(const std::string & key, boost::property_tree::ptree* tree,
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
// (yeah, I'm kind of wondering because there doesn't appear to be a setter for func)
FunctionDescriptor::FunctionDescriptor() {
  address = 0;
  pdg = NULL;
  oo_properties = NULL;
  func = NULL;
  // p2func, how to properly initialize a "NULL" one?
  stack_delta = StackDelta(0, ConfidenceNone);
  stack_parameters = StackDelta(0, ConfidenceNone);
  returns_this_pointer = false;
  never_returns = false;
  target_func = NULL;
  target_address = 0;
  new_method = false;
  delete_method = false;
  purecall_method = false;
  excluded = false;
  pdg_hash = "";
  stack_analysis_failures = 0;

  // We'll build these when they're needed.
  control_flow_graph_cached = false;
  return_blocks_cached = false;
  hashes_calculated = false;
  num_blocks = 0;
  num_blocks_in_cfg = 0;
  num_instructions = 0;
  num_bytes = 0;
  pdg_cached = false;
}

FunctionDescriptor::FunctionDescriptor(SgAsmFunction* f) : func(f) {
  // should really check for NULL pointer here
  if (f)
  {
    set_address(f->get_entry_va());
    // set address_intervals (effectively an analogue to IDA Function Chunks concept).  We
    // don't really want the function padding to show up in the extents, however, so I modified
    // the sample code in the ROSE docs on SgAsmFunction::get_extent() to avoid those "better":
    class NotPadding: public SgAsmFunction::NodeSelector {
    public:
      virtual bool operator()(SgNode *node) {
        SgAsmStaticData *data = isSgAsmStaticData(node);
        SgAsmBlock *block = SageInterface::getEnclosingNode<SgAsmBlock>(data);
        // the way partitioner2 is adding padding blocks (both stock & our overridden way)
        // doesn't mark the block reason w/ BLK_PADDING?  So here's a little hack for now that
        // takes a peek at the bytes at the start of the block:
        bool looks_like_padding(false);
        if (data)
        {
          SgUnsignedCharList dbytes(data->get_raw_bytes()); // no const ref accessor?
          if (dbytes.size() > 0 && (dbytes[0] == 0x90 || dbytes[0] == 0xCC))
            looks_like_padding = true;
        }
        //return !data || !block || block->get_reason()!=SgAsmBlock::BLK_PADDING;
        return !data || !block || !looks_like_padding;
      }
    } notPadding;
    f->get_extent(&address_intervals,NULL,NULL,&notPadding);
    SDEBUG << address_string() << " function chunks: " << address_intervals << LEND;
    p2func = global_descriptor_set->get_partitioner().functionExists(address);
    // not sure if this can ever occur, I wouldn't think so, but I want to see the error message if so:
    if (! p2func)
      SFATAL << "No Partitioner2 Function object for " << address_string() << LEND;
  }
  else {
    address = 0;
  }
  pdg = NULL;
  oo_properties = NULL;
  target_func = NULL;
  target_address = 0;
  new_method = false;
  delete_method = false;
  purecall_method = false;
  stack_delta = StackDelta(0, ConfidenceNone);
  stack_parameters = StackDelta(0, ConfidenceNone);
  returns_this_pointer = false;
  never_returns = false;
  excluded = false;
  pdg_hash = "";
  stack_analysis_failures = 0;
  analyze();

  // We'll build these when they're needed.
  control_flow_graph_cached = false;
  return_blocks_cached = false;
  hashes_calculated = false;
  num_blocks = 0;
  num_blocks_in_cfg = 0;
  num_instructions = 0;
  num_bytes = 0;
  pdg_cached = false;
}

FunctionDescriptor::~FunctionDescriptor() {
  if (pdg != NULL) {
    SCRAZY << "Destructing FunctionDescriptor (with PDG)!" << LEND;
    delete pdg;
    pdg = NULL;
    pdg_cached = false;
  }

  // Free the oo_properties (ThisCallMethod) data structure.
  if (oo_properties != NULL) {
    delete oo_properties;
  }

  // free the list of stack variables
  for (StackVariablePtrList::iterator it = stack_vars.begin() ; it != stack_vars.end(); ++it) {
     delete *it;
     *it = NULL;
  }
  stack_vars.clear();
}

void FunctionDescriptor::set_address(rose_addr_t addr)
{
  auto old_addr = addr;
  address = addr;
  std::ostringstream os("sub_");
  os << std::hex;
  if (address != 0 && !display_name.empty()) {
    os << old_addr;
    if (display_name != os.str()) {
      return;
    }
    os.str("sub_");
  }
  os << address;
  display_name = os.str();
  if (func && func->get_name().empty()) {
    func->set_name(display_name);
  }
}


// Get the name of the function.
std::string FunctionDescriptor::get_name() const {
  if (func == NULL) {
    if (display_name.empty()) {
      return std::string("<none>");
    }
    return display_name;
  }

  std::string rose_name = func->get_name();
  if (!rose_name.empty())
    return rose_name;
  if (display_name.empty()) {
    return boost::str(boost::format("sub_%x") % address);
  }
  return display_name;
}

// Set the name of the function.
void FunctionDescriptor::set_name(const std::string& name) {
  if (func != NULL) {
    func->set_name(name);
  }
  display_name = name;
}

void FunctionDescriptor::set_api(const APIDefinition& fdata) {
  stack_delta = StackDelta(fdata.stackdelta, ConfidenceUser);
  // Get the calling convention from the API database.
  std::string convention;
  if (fdata.calling_convention.empty()) {
    // This is a hack.  The ApiDB should probably never have an empty calling convention.
    convention = "__stdcall";
  } else {
    convention = "__" + fdata.calling_convention;
  }
  const CallingConventionMatcher& matcher = global_descriptor_set->get_calling_conventions();
  size_t arch_bits = global_descriptor_set->get_arch_bits();
  const CallingConvention* cc = matcher.find(arch_bits, convention);
  // If we found one, add it to the calling conventions.
  if (cc != NULL) {
    calling_conventions.push_back(cc);
  }
  // #var is a calling convention that marks global variables. Don't complain about it.
  else if (fdata.calling_convention != "#var") {
    GWARN << "Unrecognized " << arch_bits << "-bit calling convention: " << convention
          << " for function " << fdata.display_name << LEND;
  }

  // Now fill in the parameters dta structure.
  parameters.set_calling_convention(cc);

  // Just wildly assume that EAX/RAX was the return the value. We can do better. :-(
  RegisterDescriptor eax = global_descriptor_set->get_arch_reg("eax");

  // We can now detect whether the API intends to return a value, and what type of that return
  // value is.  The EAX register is still a scratch register regardless of whether there's a
  // type here.  In the future, we should transition to a more active representation of a void
  // return value (type void?), but for now that's signalled as an emtpty string.  Sadly, this
  // may include a small number of cases where we failed to parse the return type as well.
  if (to_lower(fdata.return_type) != "void") {
    // Use a NULL pointer to represent a NULL value?  The goal here is to signal to the user of
    // this field that if they're trying to match this against some other symbolic value in the
    // analysis, that they're doing it wrong.  This value is by definition outside the scope of
    // our analysis.
    SymbolicValuePtr null_ptr;
    ParameterDefinition* rpd = parameters.create_return_reg(eax, null_ptr);
    rpd->name = "retval";
    rpd->type = fdata.return_type;
    rpd->direction = ParameterDefinition::DIRECTION_OUT;
  }

  // Handle the "this" pointer for the __thiscall convention
  if (cc && convention == "__thiscall") {
    auto thisreg = cc->get_this_register();
    auto thisparam = parameters.create_reg_parameter(
      thisreg, SymbolicValuePtr(), nullptr, SymbolicValuePtr());
    thisparam->name = "this";
  }

  // Create some arbitrary stack parameters.
  size_t arch_bytes = global_descriptor_set->get_arch_bytes();
  size_t delta = fdata.parameters.size() * arch_bytes;
  assert(delta % arch_bytes == 0);

  stack_parameters = StackDelta(delta, ConfidenceUser);
  if (cc && cc->get_stack_cleanup() == CallingConvention::CLEANUP_CALLEE) {
    stack_delta = stack_parameters;
  }
  else {
    stack_delta = StackDelta(0, ConfidenceUser);
  }

  delta = 0;
  // Now fill in the additional details on each parameter.
  for (const APIParam& ap : fdata.parameters) {
    ParameterDefinition* pd = parameters.create_stack_parameter(delta);
    assert(pd);
    if (!ap.name.empty()) {
      pd->name = ap.name;
    }
    if (!ap.type.empty()) {
      pd->type = ap.type;
    }
    pd->direction = (ParameterDefinition::DirectionEnum)ap.direction;
    delta += arch_bytes;
  }

  if (!fdata.display_name.empty()) {
    set_name(fdata.display_name);
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
      set_address(*addr);
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
    size_t arch_bits = global_descriptor_set->get_arch_bits();
    cc = matcher.find(arch_bits, ucc);
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
  //for (std::string s : unchanged_state) {
  //  tree->add("unchanged", s);
  //}
  // Not really properly implemented yet.
  //for (std::string p : parameter_state) {
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
  for (const CallingConvention* cc : calling_conventions) {
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
  // Determine whether we're a thunk, and if we are, what address we jump to.

  // We're not a thunk unless this code says we are.
  target_address = 0;
  target_func = NULL;

  // Shouldn't happen, but don't crash regardless.
  if (!func) return;
  SgAsmStatementPtrList& bb_list = func->get_statementList();
  // If there are no blocks in the function, it's something strange, but it's not a thunk.
  if (bb_list.size() == 0) return;

  // This will be the entry point block when we find it.
  SgAsmBlock* bblock = NULL;

  // Consider every block in the function since we don't conveniently know which block is the
  // entry block without obtaining the control flow graph, and we don't want to do that yet.
  for (SgAsmStatement* stmt : bb_list) {
    // If we're not a real assembly block, we can't be the entry point block.
    bblock = isSgAsmBlock(stmt);
    if (bblock == NULL) continue;
    // If this block has the function entry point address, it's the one we're looking for.
    if (bblock->get_address() == func->get_entry_va()) break;
  }

  // If we didn't find the entry point block, that's unexpected and we can't continue.
  if (bblock == NULL) {
    GERROR << "Unable to find entry point block " << addr_str(func->get_entry_va())
           << " in function " << address_string() << LEND;
    return;
  }

  // Now that we've found the entry point block we can get on with deciding whether we're a
  // thunk or not.  Begin by obtaining the statement (instruction) list.
  SgAsmStatementPtrList& insns = bblock->get_statementList();
  // We're a thunk only if there's a single instruction in the block.
  if (insns.size() != 1) return;

  // Get that instruction, and presume that it's an x86 instruction. :-(
  SgAsmX86Instruction* insn = isSgAsmX86Instruction(insns[0]);
  // There must be an instruction, and it must be a jump.
  if (insn == NULL) return;
  if (insn->get_kind() != x86_jmp && insn->get_kind() != x86_farjmp) return;

  // Get the successors.  getSuccessors is apparently incorrectly(?) non-const... :-(
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
    // segment register, and the second from an architecture sized register.
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
      size_t arch_bits = global_descriptor_set->get_arch_bits();
      if (int_expr != NULL && int_expr->get_significantBits() == arch_bits) {
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
// is because calling convention could only be computed reliably after the PDG pass, where it's
// also called from.
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

  // The EAX register is still kind of magical in this code. :-(
  RegisterDescriptor eaxrd = global_descriptor_set->get_arch_reg("eax");

  // Get the import descriptor for that address if there is one.
  ImportDescriptor* id = global_descriptor_set->get_import(taddr);
  if (id != NULL) {
    SDEBUG << "Function: " << address_string() << " is a thunk to an import: "
           << id->get_long_name() << "." << LEND;

    // Propagate the (currently invented) parameters from the import descriptor to the thunk
    // that calls the import descriptor.
    const FunctionDescriptor* ifd = id->get_function_descriptor();
    parameters = ifd->get_parameters();

    // In general, the best default assumption for an import is to assume that the function
    // does return a value, because most functions do.  Just forcing a return code of EAX here
    // is pretty bad, but Cory doesn't know right now what the right thing to do would even be.
    // Perhaps our code should do different things for imports where ever the parameters are
    // needed.  If we stick with a strategy that says consult the actual changed registers, we
    // should at least populate the changed register set more thoroughly from the calling
    // convention, but there's no calling convention that doesn't just return eax right now, so
    // there's not way to test that anayway.  This seems good enough for now.
    register_usage.changed_registers.insert(eaxrd);

    return;
  }

  // Get the function descriptor for that address if there is one.
  FunctionDescriptor* fd = global_descriptor_set->get_func(taddr);
  if (fd != NULL) {
    SDEBUG << "Function: " << address_string() << " is a thunk to another function at "
           << fd->address_string() << "." << LEND;

    // In this case, just propagate the information from the called function onto the thunk.
    // These are the "old style" properties, and should probably be phased out.
    returns_this_pointer = fd->get_returns_this_pointer();
    never_returns = fd->get_never_returns();

    // Propagate parameters and register usage from the new style approach as well.
    parameters = fd->get_parameters();
    // Register usage is an embedded object with sets of registers and this makes a copy...  Is
    // that what we wanted?  Should we make thunks point to the functions they reference?
    register_usage = fd->get_register_usage();

    return;
  }

  // The only remaining case is one worth complaining about -- that we're a thunk to a
  // function that wasn't found during disassembly.  We don't really have any basis for
  // saying whether we return a value or not, but since it's more common to do so than not,
  // just wildly guess that we do.
  SWARN << "Function: " << address_string()
        << " is a thunk that jumps to the non-function address " << addr_str(taddr) << LEND;
  register_usage.changed_registers.insert(eaxrd);
}

void FunctionDescriptor::analyze() {
  if (!func) return;

  // If the func has a chunk w/ a lower address, calling get_address() returns that instead of
  // the entry_va.  We want to explicitly get the entry address.
  set_address(func->get_entry_va());
  // Determine whether we're a thunk.
  update_target_address();

  STRACE << "Analyzing function descriptor: " << *this << LEND;
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
  if (sd.confidence == ConfidenceMissing && !stack_delta_variable) {
    size_t arch_bits = global_descriptor_set->get_arch_bits();
    stack_delta_variable = LeafNode::createVariable(arch_bits, "", UNKNOWN_STACK_DELTA);
  } else {
    stack_delta_variable = LeafNodePtr();
  }
}

// Find the stack variables for this function. The algorithm to find the stack variables is one
// of elimination. First, get the initial stack pointer value by looking up the symbolic value
// for ESP. For each instruction in the function, check if that instruction uses the stack
// pointer, is not a saved register, and is not a function parameter.
//
// Note that this means that this analysis DEPENDS ON parameter analysis and saved register
// analysis!
//
// Also omit control flow instructions, because they cannot use the stack directly. The
// remainning instructions use the stack and are likely stack variables.
void FunctionDescriptor::update_stack_variables() {
  StackVariableAnalyzer stkvar_analyzer(this);
  stack_vars = stkvar_analyzer.analyze();
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

  size_t arch_bytes = global_descriptor_set->get_arch_bytes();

  // For each instruction in the function in address order.  It might be more correct to use
  // some kind of flow order here, but that's not as convenient right now.
  for (SgAsmX86Instruction* insn : get_insns_addr_order()) {
    // LEA's reference memory but do not "read" them... Therefore, let's determine if the value
    // being moved into the register could reference a function parameter.  This is old Wes
    // code, and Cory has cleaned it up some, but it's still a bit hackish.
    if (insn->get_kind() == x86_lea) {
      // Get the writes for this LEA instruction.
      auto writes = du.get_writes(insn);
      // Shouldn't happen, but continuing prevents crashes.
      if (std::begin(writes) == std::end(writes)) continue;
      // Look for writes (to some register, but where the value is from a stack memory address.
      for (const AbstractAccess& ac : writes) {
        if (ac.value->get_memory_type() == StackMemParameter) {
          // Convert the "address" to a signed stack delta.
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
    for (const Definition& d : *deps) {
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
        // The stack address must also be not be negative for the conversion to size_t in
        // create_stack_parameter call later.
        if (stack_addr < int(arch_bytes) || (stack_addr % arch_bytes != 0)) {
          SWARN << "Unexpected stack address (" << stack_addr << ") for parameter ignored at: "
                << debug_instruction(insn) << LEND;
          continue;
        }

        SDEBUG << "Parameters: " << debug_instruction(insn) << " sa=" << stack_addr << LEND;

        // This is the real case we've beeen narrowing in on.
        if (stack_addr < ARBITRARY_PARAM_LIMIT) {
          SDEBUG << "Found reference to a stack parameter at offset " << stack_addr
                 << ", creating needed parameter definition." << LEND;
          // Ensure that the parameter definition exists.  We don't have any details about
          // this parameter's name or type right now, so just use default values.  The minus
          // adjustment for the size of the return address.
          ParameterDefinition* param = parameters.create_stack_parameter((size_t) stack_addr - arch_bytes);
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
            size_t arch_bits = global_descriptor_set->get_arch_bits();
            SymbolicValuePtr pointed_to = input_state->read_memory(d.access.value, arch_bits);
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
    for (FunctionDescriptor *thunkfd : get_thunks()) {
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
  size_t arch_bits = global_descriptor_set->get_arch_bits();

  // If we didn't identify a calling convention, simply push the used parameter registers into
  // the parameter list in an arbitrary order.  This should probably at least be deterministic,
  // rather than based on pointer order, but sadly, that's inconvenient in C++. :-(
  if (cc == NULL) {
    for (const RegisterEvidenceMap::value_type& rpair : register_usage.parameter_registers) {
      RegisterDescriptor rd = rpair.first;
      // Read the symbolic value for the specified register from input state.
      SymbolicValuePtr rpsv = input_state->read_register(rd);
      GDEBUG << "Adding reg parameter '" << unparseX86Register(rd, NULL)
             << "' to unknown convention for " << address_string() << " sv=" << *rpsv << LEND;
      // The pointed_to field is probably always NULL for our current system, but there might
      // be a situation in which we would start populating these fields based on types in the
      // future...
      SymbolicValuePtr pointed_to = input_state->read_memory(rpsv, arch_bits);
      parameters.create_reg_parameter(rd, rpsv, rpair.second, pointed_to);
    }
    // And we're done.
    return;
  }

  // For cases in which we know the calling convention, the source code order matters, so
  // process the parameters in the order specified in the calling convention.
  for (RegisterDescriptor rd : cc->get_reg_params()) {
    RegisterEvidenceMap::iterator reg_finder = register_usage.parameter_registers.find(rd);
    if (reg_finder == register_usage.parameter_registers.end()) {
      GDEBUG << "But the register wasn't actually used by the function." << LEND;
      // It's unclear to Cory whether we really have to create a parameter here or not.  The
      // situation is that the calling convention says that there's a parameter, but we haven't
      // actually used it.
      // parameters.create_reg_parameter(rd, rpsv, NULL);
      GDEBUG << "Unused reg parameter '" << unparseX86Register(rd, NULL)
             << "' to convention " << cc->get_name() << " for " << address_string() << LEND;
    }
    else {
      SymbolicValuePtr rpsv = input_state->read_register(rd);

      GDEBUG << "Adding reg parameter '" << unparseX86Register(rd, NULL) << "' to convention "
             << cc->get_name() << " for " << address_string() << " sv=" << *rpsv << LEND;
      const SgAsmInstruction* insn = reg_finder->second;
      // Same pointed_to behavior as mentioned above.
      SymbolicValuePtr pointed_to = input_state->read_memory(rpsv, arch_bits);
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
  else if (! output_state)
  {
    GERROR << "update_return_values, no output state for " << address_string() << LEND;
    return;
  }
  else {
    RegisterDescriptor retval_reg = cc->get_retval_register();
    if (!retval_reg.is_valid()) {
      GERROR << "Calling conventions that don't return in registers is unsupported." << LEND;
      return;
    }

    SymbolicValuePtr retval = output_state->read_register(retval_reg);
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


void FunctionDescriptor::analyze_type_information(const DUAnalysis& du) {

  const std::map<TreeNode*, TreeNodePtr>& tree_nodes = du.get_unique_treenodes();
  const std::map<TreeNode*, TreeNodePtr>& mem_accesses = du.get_memaddr_treenodes();

  // TypeSolver generates and analyzes prolog facts for type information. making this static
  // preserves it across functions
  TypeSolver type_solver(du, this);

  // JSG wonders if passing command line arguments this deep in to Pharos is a good idea
  const ProgOptVarMap& vm = global_descriptor_set->get_arguments();
  if (vm.count("type-file")) {
     std::string results_file = vm["type-file"].as<std::string>();
     type_solver.set_output_file(results_file);
  }

  type_solver.generate_type_information(tree_nodes, mem_accesses);

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
  pdg = new PDG(this, sp);

  // How many stack delta analysis failures did we have?
  stack_analysis_failures = sp->get_recent_failures();
  if (stack_analysis_failures > 0) {
    // This is the primary place that we report stack delta analysis filaures right now.
    SWARN << "There were " << stack_analysis_failures
          << " stack delta analysis failures in function " << address_string() << LEND;
  }
  pdg_cached = true;

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
    // This is a pretty horrible hack, but the alternative is to go fix tail call optimization
    // (where calls at the end of the function are replaced by a jump).  And that's a _much_
    // bigger change than I want to tackle right now.  And, I need delete to work properly in
    // the mean time.  This code can probably be remove once we've properly grafted the basic
    // blocks from the jump into the function during analysis.
    if (is_delete_method()) {
      // First force the convention to cdecl...
      const CallingConventionMatcher& matcher = global_descriptor_set->get_calling_conventions();
      size_t arch_bits = global_descriptor_set->get_arch_bits();
      const CallingConvention* cdecl = matcher.find(arch_bits, "__cdecl");
      parameters.set_calling_convention(cdecl);
      // Then force a single stack parameter.
      size_t arch_bytes = global_descriptor_set->get_arch_bytes();
      stack_parameters = StackDelta(arch_bytes, ConfidenceUser);
      ParameterDefinition* pd = parameters.create_stack_parameter(arch_bytes);
      assert(pd);
      pd->name = "p";
      pd->type = "void *";
    }
    else {
      // Analyze our calling convention.  Must be AFTER we've marked the PDG as cached, because
      // analyzing the calling convention will attempt to recurse into get_pdg().
      register_usage.analyze(this);

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
    }

    // Create the set of stack variables
    update_stack_variables();

    // Update the global variables based on accesses in this function
    update_global_variables();

    // Use the calling convention to determine which changed registers were intentionally changed
    // (return values) and which were just scratch registers.  If no calling convention has been
    // set, add all changed registers as return values.
    update_return_values();

    const ProgOptVarMap& vm = global_descriptor_set->get_arguments();
    if (vm.count("analyze-types")) {
      const DUAnalysis& du = pdg->get_usedef();
     // Analyze the types of the treenodes used during function analysis (invokes Prolog).
      analyze_type_information(du);
    }
  }

  return pdg;
}

// Update global variables used in this function
void FunctionDescriptor::update_global_variables() {

  const DUAnalysis& du = pdg->get_usedef();
  for (auto& global_pair : global_descriptor_set->get_global_map())  {

    GlobalMemoryDescriptor& global_var = global_pair.second;
    const std::vector<SymbolicValuePtr>& global_vals = global_var.get_values();

    for (auto global_insn : global_var.get_writes()) {

      access_filters::aa_range global_writes = du.get_mem_writes(isSgAsmX86Instruction(global_insn));
      if (std::begin(global_writes) != std::end(global_writes)) {
        for (const AbstractAccess &global_write_aa : global_writes) {
          if (global_write_aa.value) {

            SymbolicValuePtr gwsv = global_write_aa.value;
            auto gvi = std::find_if(global_vals.begin(),
                                    global_vals.end(),
                                    [gwsv](SymbolicValuePtr sv)
                                    { return sv->can_be_equal(gwsv); });

            if (gvi == global_vals.end()) {
              // when a global is written, add a new symbolic value (if needed)
              global_var.add_value(global_write_aa.value);
            }
            // regardless, add the write
            global_var.add_write(global_insn, global_write_aa.size);
          }
        }
      }

      // Whether or not a read can result in a new symbolic value is unclear
    }
  }
}

void FunctionDescriptor::free_pdg() {
  pdg_cached = false;
  delete pdg;
  pdg = 0;
}

// Get the PDG hash for the function.  This turns out to be really expensive -- like half the
// cost of the entire analysis of an OO program expensive... :-(
std::string FunctionDescriptor::get_pdg_hash(unsigned int num_hash_funcs) {
  if (pdg_hash.size() != 0) return pdg_hash;
  PDG* p = get_pdg();
  if (p == NULL) return "";
  pdg_hash = p->getWeightedMaxHash(num_hash_funcs);
  return pdg_hash;
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

// A function hash variant close to the Uberflirt EHASH/PHASH stuff, plus a new Composite PIC
// hash, and some "extra" hash types if requested.  Here's the basic gist:
//
// iterate over basic blocks in flow order (a consistent logical ordering)
//   iterate over instructions in block
//     add raw bytes to block ebytes
//     if extra
//       save mnemonic & mnemonic category info
//     if jmp/call/ret
//       ignore this completely for CPIC
//     else
//       look for integers operands in program range (more checks?) & replace w/ 00
//     add exact bytes to ebytes
//     add (modified) bytes to pbytes & cpicbytes
//   calc md5 of block cpicbytes
// md5 ebytes & pbytes
// sort all block cpic hash values, concat & hash to generate fn level CPIC
//
// TODO: replace x86 specific stuff w/ code that will work w/ other ISAs, should we ever start supporting those...
void FunctionDescriptor::compute_function_hashes(ExtraFunctionHashData *extra) {
  hashes_calculated = true; // might want to set this first to prevent multiple error messages from the same function when something isn't right?

  // should really do these elsewhere, but this is good for now:
  num_blocks = 0;
  num_blocks_in_cfg = 0;
  num_instructions = 0;
  num_bytes = 0;

  // Should I be using get_pharos_cfg() here to theoretically filter out bad stuff and fixup
  // things?  I suspect "probably" is the answer...and if I do should I also store off the
  // number of basic blocks different too (like I did for the blocks in the cfg vs not)?
  // Not sure yet.
  //CFG cfg = cfg_analyzer.build_block_cfg_from_ast<CFG>(func);
  //CFG cfg = get_pharos_cfg(); // fn2hash doesn't do the pdg building, so this call dies w/ an assert!
  CFG cfg = get_rose_cfg();
  CFGVertex entry_vertex = 0;
  std::vector<CFGVertex> cfgblocks = cfg_analyzer.flow_order(cfg, entry_vertex);
  // ODEBUG produces too much in objdigger test output, so let's use trace for this:
  OTRACE << address_string() << " fn has " << cfgblocks.size() << " basic blocks in control flow" << LEND;

  SgAsmBlock *funceb = func->get_entry_block();
  SgAsmBlock *cfgeb = get(boost::vertex_name, cfg, cfgblocks[entry_vertex]);
  // I don't think this should be possible:
  if (funceb == NULL) {
    OERROR << "CFB No entry block in function: " << address_string() << LEND;
    return;
  }
  if (cfgeb == NULL) {
    OERROR << "CFB No entry block in flow order: " << address_string() << LEND;
    return;
  }
  // and I *really* hope this isn't either:
  if (funceb != cfgeb) {
    OERROR << "CFB Entry blocks do not match! " << addr_str(funceb->get_address()) << "!="
           << addr_str(cfgeb->get_address()) << " in function: " << address_string() << LEND;
  }

  num_blocks = func->get_statementList().size();
  num_blocks_in_cfg = cfgblocks.size();

  //std::set< std::string > bbcpics; // basic block PIC hashes for composite calc (no dupes)
  std::multiset< std::string > bbcpics; // basic block cPIC hashes for fn composite PIC calc (keep dupes)

  // moved these to "extra"
  //std::string mnemonics; // concatenated mnemonics
  //std::string mnemcats; // concatenated mnemonic categories

  // would like to output some debugging disassembly, build up a string that then gets dumped
  // to an appropriate output stream later:
  std::ostringstream dbg_disasm;
  dbg_disasm << "Debug Disassembly of Function " << display_name << " (" << addr_str(address) << ")"
             << std::endl;

  std::vector< rose_addr_t > bbaddrs;

  // iterate over all basic blocks in the function:
  for (size_t x = 0; x < num_blocks_in_cfg; x++) {
    SgAsmBlock *bb = get(boost::vertex_name, cfg, cfgblocks[x]);

    std::string bbcpicbytes; // CPIC bytes (no control flow insns)
    std::string bbpicbytes; // PIC bytes (control flow insns included)
    uint32_t bbicnt = 0; // this basic block instruction count
    std::vector< std::string > bbmnemonics;
    std::vector< std::string > bbmnemcats;

    if (bb == NULL) {
      // Is this even possible?
      OERROR << "CFB NULL basic block found in control flow for function: "
             << address_string() << LEND;
      continue;
    }
    else {
      dbg_disasm << "\t; --- bb start ---" << std::endl; // show start of basic block
      // iterate over the instructions in the basic block:
      SgAsmStatementPtrList & ins_list = bb->get_statementList();
      bbicnt = ins_list.size();
      num_instructions += bbicnt;
      for (size_t y = 0; y < ins_list.size(); y++) {
        SgAsmX86Instruction *insn = isSgAsmX86Instruction(ins_list[y]);
        if (!insn) { // is this possible?
          OERROR << "CFB NULL insn in basic block " << addr_str(bb->get_address()) << LEND;
          continue;
        }

        // Get the raw bytes...
        SgUnsignedCharList bytes = insn->get_raw_bytes();
        num_bytes += bytes.size();
        if (bytes.size() == 0) { // is this possible?
          OERROR << "CFB no raw bytes in instruction at " << addr_str(insn->get_address()) << LEND;
          continue;
        }

        // okay place for debugging dumping the diassembly?  Tried to use ROSE's "unparser" but
        // sadly the convenience unparser is not handling lea instructions correctly, but our
        // debug_instruction code does (will revisit using the paritioner's unparser at some
        // point):
        std::string insnDisasm = debug_instruction(insn,17);
        dbg_disasm
          //<< addr_str(insn->get_address()) << " "
          << insnDisasm
          //<< std::endl
          //<< "\t; EBYTES: " << MyHex(bytes)
          //<< std::endl
          ;

        // Just append all of the bytes to exact_bytes.
        exact_bytes.insert(exact_bytes.end(), bytes.begin(), bytes.end());

        // For the various PIC bytes & hashes, it's more complicated...

        std::vector< bool > wildcard(bytes.size(),false);
        // need to traverse the AST for operands lookng for "appropriate" wilcard candidates:
        struct IntegerOffsetSearcher : public AstSimpleProcessing {
          std::vector< std::pair< uint32_t, uint32_t > > candidates;
          DescriptorSet *program;
          FunctionDescriptor *fd;
          SgAsmInstruction *insn;

          IntegerOffsetSearcher(DescriptorSet *_program, FunctionDescriptor *_fd, SgAsmInstruction *_insn) {
            program = _program;
            fd = _fd;
            insn = _insn;
          }

          void visit(SgNode *node) override {
            const SgAsmIntegerValueExpression *intexp =
              isSgAsmIntegerValueExpression(node);
            if (intexp) {
              uint64_t val = intexp->get_value(); // or get_absoluteValue() ?
              if (program->memory_in_image(rose_addr_t(val))) {
                AddressIntervalSet chunks = fd->get_address_intervals();
                auto chunk1 = chunks.find(insn->get_address());
                auto chunk2 = chunks.find(val);
                // only null out address reference if it leaves the current chunk
                if (chunk1 != chunk2)
                {
                  auto off = intexp->get_bit_offset();
                  auto sz = intexp->get_bit_size();
                  // should always be aligned to byte in x86?
                  if (off % 8 != 0 || sz % 8 != 0)
                  {
                    OERROR << "operand offset, non byte alignment or size found: " << off << " " << sz << LEND;
                    return;
                  }
                  // saw some unusual offsets & sizes during testing,yell if we hit this:
                  auto insnsz = insn->get_raw_bytes().size();
                  if (insnsz > 17) // max intel instruction size (32 bit)?
                  {
                    OERROR << "suspiciously large instruction found @"
                           << addr_str(insn->get_address()) << " : " << insnsz << LEND;
                  }
                  if (off/8 >= insnsz)
                  {
                    OERROR << "operand offset @ " << addr_str(insn->get_address())
                           << " is suspuciously large: " << off << LEND;
                    return;
                  }
                  if (sz/8 >= insnsz)
                  {
                    OERROR << "operand size @ " << addr_str(insn->get_address())
                           << " is suspiciously large: " << sz << LEND;
                    return;
                  }
                  std::pair< uint32_t, uint32_t > pval(off,sz);
                  candidates.push_back(pval);
                }
              }
            }
          }
        };

        IntegerOffsetSearcher searcher(global_descriptor_set,this,insn);
        searcher.traverse(insn, preorder);
        int numnulls = 0;
        for (auto sc = searcher.candidates.begin(); sc != searcher.candidates.end(); ++sc) {
          auto off = sc->first;
          auto sz = sc->second;
          if ((off/8 + sz/8) > wildcard.size()) // I *should* be catching this in the visitor
                                              // above, but I'm paranoid now...
          {
            OERROR << "large offset + size found @ " << addr_str(insn->get_address())
                   << " : " << off/8 + sz/8 << LEND;
            continue;
          }
          // in some samples (82c9e0083bd16284b57c3a375844a0dc5f305ca1cfcfaeff885717aeaa92325a)
          // an addressing scheme like [eax+ecx*2+14h] has some integer value expression (I
          // assume the 14h) where the size comes back as zero???  Need to figure out why at
          // some point, but for now, catch & ignore:
          if (sz <= 0)
          {
            OERROR << "bad operand size found @ " << addr_str(insn->get_address())
                   << " : " << sz << LEND;
            continue;
          }
          do
          {
            wildcard[off/8] = true;
            off += 8;
            sz -= 8;
          } while (sz >= 8);
        }

        // okay, now know what to NULL out, so do it:
        for (size_t i = 0; i < bytes.size(); ++i) {
          if (wildcard[i]) {
            bytes[i] = 0;
            ++numnulls;
            // save offsets so yara gen can use pic_bytes + offsets to wildcard correct bytes
            pic_offsets.push_back(pic_bytes.size() + i);
          }
        }

        std::string pbstr = "(same)";
        if (numnulls)
          pbstr = MyHex(bytes);

        dbg_disasm
          //<< "\t; PBYTES: " << MyHex(bytes)
          << ", PBYTES: " << pbstr
          //<< std::endl
          ;

        // PIC hash is based on same # and order of bytes as EHASH but w/ possible addrs nulled:
        pic_bytes.insert(pic_bytes.end(), bytes.begin(), bytes.end());

        std::string mnemonic = insn->get_mnemonic();
        // need to address some silliness with what ROSE adds to some mnemonics first:
        if (boost::starts_with(mnemonic,"far")) {  // WHY are "farCall" and "farJmp" being output as mnemonics???
          if (mnemonic[3] == 'C')
            mnemonic = "call";
          else
            mnemonic = "jmp";
        }
        // hmm...should I peel off the rep*_ prefix too, or leave it on there.  I think for
        // this part I can leave it on there, but for the category determination I'll strip it
        // out (in insn_get_generic_category).  There may be other prefixes that I should deal
        // with too, but ignoring for now...
        std::string mnemcat = insn_get_generic_category(insn);

        //SDEBUG << addr_str(insn->get_address()) << " " << mnemonic << LEND;
        //dbg_disasm << "\t; MNEMONIC: " << mnemonic;
        dbg_disasm << ", MNEM: " << mnemonic;
        //SDEBUG << addr_str(insn->get_address()) << " " << mnemcat << LEND;
        dbg_disasm << ", CAT: " << mnemcat << std::endl;

        bbmnemonics.push_back(mnemonic);
        bbmnemcats.push_back(mnemcat);
        if (extra) {
          extra->mnemonics += mnemonic;
          if (extra->mnemonic_counts.count(mnemonic) > 0)
            extra->mnemonic_counts[mnemonic] += 1;
          else
            extra->mnemonic_counts[mnemonic] = 1;

          extra->mnemcats += mnemcat;
          if (extra->mnemonic_category_counts.count(mnemcat) > 0)
            extra->mnemonic_category_counts[mnemcat] += 1;
          else
            extra->mnemonic_category_counts[mnemcat] = 1;
        }

        // Composite PIC Hash has no control flow instructions at all, and will be calculated
        // by the hashes of the basic blocks sorted & concatenated, then that value hashed.
        if (!insn_is_control_flow(insn))
        {
          bbcpicbytes.insert(bbcpicbytes.end(),bytes.begin(), bytes.end());
        }
        bbpicbytes.insert(bbpicbytes.end(),bytes.begin(), bytes.end());
        //SDEBUG << dbg_disasm.str() << LEND;
        SINFO << dbg_disasm.str() << LEND;
        dbg_disasm.clear();
        dbg_disasm.str("");
      }
      // bb insns done, calc (c)pic hash(es) for block
      std::string bbcpic = get_string_md5(bbcpicbytes);
      std::string bbpic = get_string_md5(bbpicbytes);
      SDEBUG << "basic block @" << addr_str(bb->get_address()) << " has pic hash " << bbpic
             << " and (c)pic hash " << bbcpic << LEND;
      bbcpics.insert(bbcpic); // used to calc fn cpic later
      if (extra) {
        bbaddrs.push_back(bb->get_address());
        ExtraFunctionHashData::BasicBlockHashData bbdat;
        bbdat.pic = bbpic;
        bbdat.cpic = bbcpic;
        bbdat.mnemonics = bbmnemonics;
        bbdat.mnemonic_categories = bbmnemcats;
        // we only do this once per bb, so it's not in the map yet:
        extra->basic_block_hash_data[bb->get_address()] = bbdat;
        //extra->basic_block_hash_data.insert(std::pair< rose_addr_t, ExtraFunctionHashData::BasicBlockHashData > (bb->get_address(),bbdat));
      }
    }
  }
  // bbs all processed, calc fn hashes
  exact_hash = get_string_md5(exact_bytes);
  pic_hash = get_string_md5(pic_bytes);
  std::string bbcpicsconcat;
  for (auto const& bbcpic: bbcpics) {
    bbcpicsconcat += bbcpic;
  }
  //OINFO << bbcpicsconcat << LEND;
  composite_pic_hash = get_string_md5(bbcpicsconcat);

  if (extra) {
    OTRACE << "calculating 'extra' hashes" << LEND;
    extra->mnemonic_hash = get_string_md5(extra->mnemonics);
    extra->mnemonic_category_hash = get_string_md5(extra->mnemcats);
    std::string mnemonic_counts_str;
    for (auto const& mnemcount: extra->mnemonic_counts) {
      mnemonic_counts_str += mnemcount.first + std::to_string(mnemcount.second);
    }
    extra->mnemonic_count_hash = get_string_md5(mnemonic_counts_str);
    std::string mnemonic_category_counts_str;
    for (auto const& mnemcatcount: extra->mnemonic_category_counts) {
      mnemonic_category_counts_str += mnemcatcount.first + std::to_string(mnemcatcount.second);
    }
    extra->mnemonic_category_count_hash = get_string_md5(mnemonic_category_counts_str);
    // add bb stuff here too
    extra->basic_block_addrs = bbaddrs;
    // iterate over CFG to get edge data:
    BGL_FORALL_EDGES(edge, cfg, CFG) {
      CFGVertex src_vtx = boost::source(edge, cfg);
      SgAsmBlock *src_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, src_vtx));
      CFGVertex tgt_vtx = boost::target(edge, cfg);
      SgAsmBlock *tgt_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, tgt_vtx));
      std::pair< rose_addr_t, rose_addr_t > aedge; // will this be init to 0,0?
      if (src_bb)
        aedge.first = src_bb->get_address();
      if (tgt_bb)
        aedge.second = tgt_bb->get_address();
      extra->cfg_edges.push_back(aedge);
      OTRACE << "adding edge to cfg_edges: " << aedge.first << "->" << aedge.second << LEND;
    }
  }
}

// The mnemonic and mnemonic category related hashes used to be computed above and stored on
// the FD, but really only fn2hash cares about them so silly to always compute them and save
// the data on the object, just generate them on the fly when fn2hash asks now

const std::string& FunctionDescriptor::get_exact_bytes() {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return exact_bytes;
}

const std::string& FunctionDescriptor::get_exact_hash() {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return exact_hash;
}

const std::string& FunctionDescriptor::get_pic_bytes() {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return pic_bytes;
}

const std::list< uint32_t > & FunctionDescriptor::get_pic_offsets() {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return pic_offsets;
}

const std::string& FunctionDescriptor::get_pic_hash() {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return pic_hash;
}

const std::string& FunctionDescriptor::get_composite_pic_hash() {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return composite_pic_hash;
}

// TODO: note that this appears to be modifying the "rose cfg" we store in place due to the
// references being used here, in get_rose_cfg and in du.cleanup_cfg, so after calling this I
// believe that both of these functions will return the same "pharos cfg" (although if this one
// is called again it'll attempt to do the cleanup again)...is this what was intended?  Also,
// get_rose_cfg() caches, is there a reason this one doesnt'?
CFG& FunctionDescriptor::get_pharos_cfg() {

  assert(pdg!=NULL);

  CFG& cfg = get_rose_cfg();

  // The real magic here is "fixing" the CFG on demand. Note that get_cfg() returns the stock
  // rose CFG
  const DUAnalysis& du = pdg->get_usedef();
  du.cleanup_cfg(cfg);

  return cfg;
}

CFG& FunctionDescriptor::get_rose_cfg() {
  // If we've already done the work, just return the answer.
  if (control_flow_graph_cached) return control_flow_graph;
  // Otherwise, we have to do it now.
  control_flow_graph = cfg_analyzer.build_block_cfg_from_ast<CFG>(func);
  // TODO: set list of basic block boundaries (list of AddressInterval?) that are in CFG
  control_flow_graph_cached = true;
  return control_flow_graph;
}

// Added because the flowlist can only be obtained from the analyzer.
Rose::BinaryAnalysis::ControlFlow& FunctionDescriptor::get_cfg_analyzer() {
  // If we've already done the work, just return the answer.
  if (control_flow_graph_cached) return cfg_analyzer;
  control_flow_graph = cfg_analyzer.build_block_cfg_from_ast<CFG>(func);
  control_flow_graph_cached = true;
  return cfg_analyzer;
}

// There may be a better way to do this, but if you have the address and want the instruction,
// this is the only way Cory is currently aware of.
SgAsmInstruction* FunctionDescriptor::get_insn(const rose_addr_t addr) const {
  // TODO: have this build/access map?  Should also build basic block boundary list for BBs NOT
  // in CFG as part of this?  Or should that happen in get_cfg() as a secondary step?

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

// TODO: need an architecture agnostic version of this if we ever support non-x86 stuff
// explicit sorting of instructions by address using a map:
X86InsnVector FunctionDescriptor::get_insns_addr_order() const {
  // TODO: do this once & cache on object?  Also, should there be another variant for "only
  // ones in CFG" too?
  X86InsnVector result;
  std::map< rose_addr_t, SgAsmX86Instruction* > rmap;
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
      if (insn != NULL)
        rmap[insn->get_address()] = insn;
    }
  }
  result.reserve(rmap.size());
  for (auto &x: rmap)
  {
    result.push_back(x.second);
  }

  return result;
}

// There's probably a better way to do this.  I'm specifically looking for all addresses in the
// function, not just those in the control flow graph, because among other purposes, I'm using
// this to reason about broken control flow in unusual corner cases.
// NOTE: SgAsmFunction::get_extent() looks to return a map of Extents that should be able to be
// used to check if addr is "in" a function (although not if it maps to an instruction exactly).
bool FunctionDescriptor::contains_insn_at(rose_addr_t addr) {
  // TODO: this should use the saved insn map in the future
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
  CFG& cfg = get_rose_cfg();

  std::vector<CFGVertex> retblocks = Rose::BinaryAnalysis::ControlFlow().return_blocks(cfg, 0);
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

// return a string w/ a masm-ish disassembly of this function descriptor:
std::string FunctionDescriptor::disasm() const {
  // TODO: apparently I started adding this function and ended up outputting the disassembly in
  // debug statements in compute_function_hashes() instead because I was already walking the
  // functions, chunks, and instructions and inspecting the bytes there...  Should probably
  // actually implement that functionality here instead/additionally at some point?  Or for
  // now, could call debug_function from masm.cpp I suppose...better than an empty answer
  // should anyone use this...

  return debug_function(func,17,true,true);
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
