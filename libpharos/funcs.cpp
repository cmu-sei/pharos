// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <atomic>

#include <boost/format.hpp>
#include <boost/optional.hpp>

#include "rose.hpp"
#include <AstTraversal.h>
#include <sageInterfaceAsm.h> // For isNOP().

#include <Rose/BinaryAnalysis/Unparser/Settings.h>
#include <Rose/BinaryAnalysis/Unparser/Base.h>

#include "funcs.hpp"
#include "delta.hpp"
#include "sptrack.hpp"
#include "pdg.hpp"
#include "util.hpp"
#include "misc.hpp"
#include "method.hpp"
#include "masm.hpp"
#include "badcode.hpp"

#include <boost/graph/iteration_macros.hpp>

namespace BA = Rose::BinaryAnalysis;

namespace pharos {

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
template std::string Enum2Str<GenericConfidence>(GenericConfidence);

// This class handles translating between rose_addr_t and std::string when reading and writing
// json objects.
class RoseAddrTranslator
{
 public:
  using internal_type = std::string;
  using external_type = rose_addr_t;

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

namespace pharos {

bool FunctionDescriptorCompare::operator()(const FunctionDescriptor* x,
                                           const FunctionDescriptor* y) const {
  // If the pointers are the same, the function descriptors are the same.  This test is NOT
  // just a performance optimization.  The reason is that we need to acquire mutex locks in
  // order to call get_address(), but checking pointers does not, and so prevents a deadlock.
  if (x == y) {
    return true;
  }
  return (x->get_address() < y->get_address());
}

FunctionDescriptor::~FunctionDescriptor() = default;

FunctionDescriptor::FunctionDescriptor(DescriptorSet& d) : ds(d) {
  address = 0;
  pdg = NULL;
  func = NULL;
  // p2func is initialized to NULL by default.
  stack_delta = StackDelta(0, ConfidenceNone);
  stack_parameters = StackDelta(0, ConfidenceNone);
  returns_this_pointer = false;
  never_returns = false;
  target_func = NULL;
  target_address = 0;
  delete_method = false;
  excluded = false;
  pdg_hash = "";
  stack_analysis_failures = 0;

  // We'll build these when they're needed.
  rose_control_flow_graph_cached = false;
  pharos_control_flow_graph_cached = false;

  hashes_calculated = false;
  num_blocks = 0;
  num_blocks_in_cfg = 0;
  num_instructions = 0;
  num_bytes = 0;
}

FunctionDescriptor::FunctionDescriptor(DescriptorSet& d, SgAsmFunction* f)
  : ds(d), func(f)
{
  // should really check for NULL pointer here
  if (f)
  {
    set_address(f->get_entry_va());
    p2func = ds.get_partitioner().functionExists(address);
    if (p2func == NULL) {
      throw std::runtime_error("Partitioner function not found!");
    }
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
    SDEBUG << _address_string() << " function chunks: " << address_intervals << LEND;
  }
  else {
    address = 0;
  }
  target_func = NULL;
  target_address = 0;
  delete_method = false;
  stack_delta = StackDelta(0, ConfidenceNone);
  stack_parameters = StackDelta(0, ConfidenceNone);
  returns_this_pointer = false;
  never_returns = false;
  excluded = false;
  pdg_hash = "";
  stack_analysis_failures = 0;
  analyze();

  // We'll build these when they're needed.
  rose_control_flow_graph_cached = false;
  pharos_control_flow_graph_cached = false;

  hashes_calculated = false;
  num_blocks = 0;
  num_blocks_in_cfg = 0;
  num_instructions = 0;
  num_bytes = 0;
}

void FunctionDescriptor::set_address(rose_addr_t addr)
{
  write_guard<decltype(mutex)> guard{mutex};
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
  if (p2func && p2func->name().empty()) {
    p2func->name(display_name);
  }
}


// Get the name of the function.
std::string FunctionDescriptor::get_name() const {
  read_guard<decltype(mutex)> guard{mutex};

  if (p2func == NULL) {
    if (display_name.empty()) {
      return std::string("<none>");
    }
    return display_name;
  }

  std::string rose_name = p2func->name();
  if (!rose_name.empty())
    return rose_name;
  if (display_name.empty()) {
    return boost::str(boost::format("sub_%x") % address);
  }
  return display_name;
}

// Set the name of the function.
void FunctionDescriptor::set_name(const std::string& name) {
  write_guard<decltype(mutex)> guard{mutex};
  if (p2func != NULL) {
    p2func->name(name);
  }
  display_name = name;
}

void FunctionDescriptor::set_api(const APIDefinition& fdata) {
  write_guard<decltype(mutex)> guard{mutex};
  stack_delta = StackDelta(fdata.stackdelta, ConfidenceUser);
  // Get the calling convention from the API database.
  std::string convention;
  if (fdata.calling_convention.empty()) {
    // This is a hack.  The ApiDB should probably never have an empty calling convention.
    convention = "__stdcall";
  } else {
    convention = "__" + fdata.calling_convention;
  }
  const CallingConventionMatcher& matcher = ds.get_calling_conventions();
  size_t arch_bits = ds.get_arch_bits();
  const CallingConvention* cc = matcher.find(arch_bits, convention);

  // Clear the existing calling conventions, since if we've called SET_api(), we presumably
  // want just this API.  This defect as identifed by having the calling convention on delete()
  // methods twice in OOAnalyzer, which is probably the only place where we currently call
  // set_api outside of imports and the APIDB.  This change will fix that specific problem, but
  // if we want a more comprehensively correct set_api() call, this method will have to change
  // more extensively.
  calling_conventions.clear();

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
  RegisterDescriptor eax = ds.get_arch_reg("eax");

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
    ParameterDefinition & rpd = parameters.create_return_reg(eax, null_ptr);
    rpd.set_parameter_description("retval", fdata.return_type,
                                  ParameterDefinition::DIRECTION_OUT);
  }

  // Handle the "this" pointer for the __thiscall convention
  if (cc && convention == "__thiscall") {
    auto thisreg = cc->get_this_register();
    auto & thisparam = parameters.create_reg_parameter(
      thisreg, SymbolicValuePtr(), nullptr, SymbolicValuePtr());
    thisparam.set_name("this");
  }

  // Create some arbitrary stack parameters.
  size_t arch_bytes = ds.get_arch_bytes();
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
    pd->copy_parameter_description(ap);
    delta += arch_bytes;
  }

  if (!fdata.display_name.empty()) {
    display_name = fdata.display_name;
    if (p2func != NULL) {
      p2func->name(display_name);
    }
  }
}

void FunctionDescriptor::merge(const FunctionDescriptor *other) {
  if (this == other) return;
  write_guard<decltype(mutex)> guard{mutex};
  // Obviously not implemented yet.  I need to decide how to handle confidence levels.
  STRACE << "Merging call target " << other->address_string()
         << " into function descriptor for " << address_string() << LEND;
  if (!other) return;
  // WRONG WRONG WRONG, but at least it puts something in the current function.
  stack_delta = other->get_stack_delta();
}

void FunctionDescriptor::propagate(const FunctionDescriptor *merged) {
  if (this == merged) return;
  write_guard<decltype(mutex)> guard{mutex};
  // Obviously not implemented yet.  I need to decide how to handle confidence levels.
  if (!merged) return;
  STRACE << "Propagating function descriptor for " << merged->_address_string()
         << " back into call target " << _address_string() << LEND;
}

void FunctionDescriptor::print(std::ostream &o) const {
  read_guard<decltype(mutex)> guard{mutex};
  o << "Func: addr=" << _address_string() << " delta=" << stack_delta << " conv=";
  for (const CallingConvention* cc : calling_conventions) {
    o << " " << cc->get_name();
  }
  o << " callers=[";
  for (auto & c : callers.values()) {
    o << str(boost::format(" 0x%08X") % c);
  }
  o << " ]";
}

std::string FunctionDescriptor::debug_deltas() const {
  read_guard<decltype(mutex)> guard{mutex};
  std::stringstream s;
  s << " delta=" << stack_delta;
  return s.str();
}

void FunctionDescriptor::update_target_address() {
  // Determine whether we're a thunk, and if we are, what address we jump to.

  // mwd: this code assumes this.  Is it guaranteed?
  assert(p2func);

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
    if (bblock->get_address() == p2func->address()) break;
  }

  // If we didn't find the entry point block, that's unexpected and we can't continue.
  if (bblock == NULL) {
    GERROR << "Unable to find entry point block " << addr_str(p2func->address())
           << " in function " << _address_string() << LEND;
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
  auto successors = insn->getSuccessors(ignored);

  // Because there's some difficulties surrounding the interpretation of imports, ROSE didn't
  // create control flow edges for the jumps to the dereferences of the import table.  Assuming
  // that they've been populated with real addreses when they haven't causes bad edges in the
  // control flow graph.  Here's our chance to correct the missing edges.  It's not clear to
  // Cory that this is the best way to do this.  Perhaps the function descriptor should point
  // to the import descriptor somehow, and it's thunkishness should be ignored...
  if (successors.size() == 0) {
    SDEBUG << "Successors for jump at " << _address_string() << " is empty." << LEND;
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
      SDEBUG << "JMP at " << _address_string() << " is NOT a memory deref." << LEND;
    }
    else {
      SDEBUG << "JMP at " << _address_string() << " is a memory deref." << LEND;
      SgAsmExpression *addr_expr = mr->get_address();
      SgAsmIntegerValueExpression* int_expr = isSgAsmIntegerValueExpression(addr_expr);
      size_t arch_bits = ds.get_arch_bits();
      if (int_expr != NULL && int_expr->get_significantBits() == arch_bits) {
        target_address = int_expr->get_absoluteValue();
        SDEBUG << "Function " << _address_string() << " is a thunk that jumps to ["
               << addr_str(target_address) << "]." << LEND;
      }
    }
    // Don't fall through and allow our possibly updated target address to be overwritten.
    return;
  }

  // Anything other than one successor is highly unsuspected.
  if (successors.size() != 1) return;

  // Set the target address to the destination of the jump instruction.
  target_address = successors.least();

  SDEBUG << "Function " << _address_string() << " is a thunk that jumps to "
         << addr_str(target_address) << "." << LEND;

  // This routine leaves target_address and target_func out of sync, which is bad.  But we're
  // being called at the time that the FunctionDescriptor is originally created, meaning that
  // the function being jumped too may not have a function descriptor yet.  That's why this
  // function is private, and not public.  This inconsistency is corrected by calling the
  // update_connections() method below.
}

void FunctionDescriptor::update_connections(FunctionDescriptorMap& fdmap) {
  FunctionDescriptor * tfunc = nullptr;
  {
    write_guard<decltype(mutex)> guard{mutex};

    // Update connections between function descriptors.  Called for each function descriptor.
    if (target_address) {
      // One possibility is that the jump target address is to another function.
      if (fdmap.find(target_address) != fdmap.end()) {
        // First record the matching function descriptor for the thunk address.
        target_func = &(fdmap.at(target_address));
        // Then notify the target that we're one of several possible thunks that point to them.
        tfunc = target_func;
      }
      // But the other possibility is that the address points to an import table entry.  Cory
      // thinks that there's growing awareness that the relationship between import descriptors
      // and function descriptors is backward.  This is one example of that, since there's no
      // where good to store the observation about the import case, and it has to be deferred
      // until later.  In this case, target_address and target_func have to be out of sync. :-(
    }
  }
  if (tfunc) {
    tfunc->add_thunk(this);
  }
}

void FunctionDescriptor::propagate_thunk_info() {
  write_guard<decltype(mutex)> guard{mutex};
  _propagate_thunk_info();
}

// Propagate important parameters to this function (like the return code booleans) if this
// function is a thunk.  While called at the very end of update_connections() in the descriptor
// set, this function is also called (untidily) at the beginning of analyze_return_code.  This
// is because calling convention could only be computed reliably after the PDG pass, where it's
// also called from.
void FunctionDescriptor::_propagate_thunk_info() {

  // Don't require the caller to test whether we're a thunk or not.
  if (!target_address) return;

  bool endless;
  // The address where we eventually end up.
  rose_addr_t taddr = _follow_thunks(&endless);
  // Here's at least one case where we can set never returns.
  if (endless) {
    never_returns = true;
    return;
  }

  // The EAX register is still kind of magical in this code. :-(
  RegisterDescriptor eaxrd = ds.get_arch_reg("eax");

  // Get the import descriptor for that address if there is one.
  const ImportDescriptor* id = ds.get_import(taddr);
  if (id != NULL) {
    SDEBUG << "Function: " << _address_string() << " is a thunk to an import: "
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
  const FunctionDescriptor* fd = ds.get_func(taddr);
  if (fd != NULL) {
    SDEBUG << "Function: " << _address_string() << " is a thunk to another function at "
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
  SWARN << "Function: " << _address_string()
        << " is a thunk that jumps to the non-function address " << addr_str(taddr) << LEND;
  register_usage.changed_registers.insert(eaxrd);
}

SgAsmBlock*
FunctionDescriptor::get_entry_block() const {
  // mwd: this assumes func is non-null.  Is this guaranteed?
  assert(func);
  return func->get_entry_block(); // Isolate references to SgAsmFunction
}

void FunctionDescriptor::analyze() {
  if (!func) return;

  // mwd: this code assumes this.  Is it guaranteed?
  assert(p2func);

  // If the func has a chunk w/ a lower address, calling get_address() returns that instead of
  // the entry_va.  We want to explicitly get the entry address.
  set_address(p2func->address());
  // Determine whether we're a thunk.
  update_target_address();

  STRACE << "Analyzing function descriptor: " << *this << LEND;
}

void FunctionDescriptor::validate(std::ostream &o) const {
  read_guard<decltype(mutex)> guard{mutex};
  if (callers.isEmpty())
    o << "No callers for function " << _address_string() << LEND;
}

void FunctionDescriptor::update_stack_delta(StackDelta sd) {
  write_guard<decltype(mutex)> guard{mutex};
  if (sd.confidence < stack_delta.confidence) return;
  if (sd.confidence <= stack_delta.confidence && sd.delta != stack_delta.delta) {
    SERROR << "Attempt to change function stack delta without changing confidence for function: "
           << _address_string() << " old=" << stack_delta << " new=" << sd << LEND;
    return;
  }
  STRACE << "Setting stack delta for " << _address_string() << " to " << sd << LEND;
  stack_delta.delta = sd.delta;
  stack_delta.confidence = sd.confidence;
  if (sd.confidence == ConfidenceMissing && !stack_delta_variable) {
    size_t arch_bits = ds.get_arch_bits();
    stack_delta_variable = SymbolicExpr::makeIntegerVariable(
      arch_bits, "", UNKNOWN_STACK_DELTA);
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
  stack_vars = std::move(stkvar_analyzer.analyze());
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
  StackDelta maxparam = StackDelta(0, stack_delta.confidence);

  // Get the PDG object...
  const PDG* p = get_pdg();
  // And the UseDef object...
  const DUAnalysis& du = p->get_usedef();

  size_t arch_bytes = ds.get_arch_bytes();

  // For each instruction in the function in address order.  It might be more correct to use
  // some kind of flow order here, but that's not as convenient right now.
  for (SgAsmInstruction* insn : get_insns_addr_order()) {
    SgAsmX86Instruction* xinsn = isSgAsmX86Instruction(insn);
    if (!xinsn) continue;
    // LEA's reference memory but do not "read" them... Therefore, let's determine if the value
    // being moved into the register could reference a function parameter.  This is old Wes
    // code, and Cory has cleaned it up some, but it's still a bit hackish.
    if (xinsn->get_kind() == x86_lea) {
      // Get the writes for this LEA instruction.
      auto writes = du.get_writes(insn->get_address());
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
    const DUChain* deps = du.get_dependencies(insn->get_address());
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
        if (xinsn->get_kind() == x86_ret) continue;

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
            size_t arch_bits = ds.get_arch_bits();
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
    SDEBUG << "Parameters for function " << _address_string() << " is "
           << maxparam << " bytes of stack space." << LEND;
    SDEBUG << "Parameters for function " << _address_string() << " are: ";
    parameters.debug();
  }

  if (stack_delta.delta != 0 && stack_delta.delta != maxparam.delta) {
    // This error frequently occurs in conjunction with stack delta analysis failures, but
    // there's at most one message per function, so it doesn't necessarily need to be
    // downgraded to from WARN in order to reduce spew.  On the other hand it could if desired.
    SWARN << "Counted stack parameters for function " << _address_string()
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
            << _address_string() << " setting to zero." << LEND;
      // Overwrite the values in maxparam, with something less harmful.
      maxparam.delta = 0;
      maxparam.confidence = ConfidenceWrong;
    }

    stack_parameters = maxparam;
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
  size_t arch_bits = ds.get_arch_bits();

  // If we didn't identify a calling convention, simply push the used parameter registers into
  // the parameter list in an arbitrary order.  This should probably at least be deterministic,
  // rather than based on pointer order, but sadly, that's inconvenient in C++. :-(
  if (cc == NULL) {
    for (const RegisterEvidenceMap::value_type& rpair : register_usage.parameter_registers) {
      RegisterDescriptor rd = rpair.first;
      // Read the symbolic value for the specified register from input state.
      SymbolicValuePtr rpsv = input_state->read_register(rd);
      GDEBUG << "Adding reg parameter '" << unparseX86Register(rd, {})
             << "' to unknown convention for " << _address_string() << " sv=" << *rpsv << LEND;
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
      GDEBUG << "Unused reg parameter '" << unparseX86Register(rd, {})
             << "' to convention " << cc->get_name() << " for " << _address_string() << LEND;
    }
    else {
      SymbolicValuePtr rpsv = input_state->read_register(rd);

      GDEBUG << "Adding reg parameter '" << unparseX86Register(rd, {}) << "' to convention "
             << cc->get_name() << " for " << _address_string() << " sv=" << *rpsv << LEND;
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
    GWARN << "update_return_values, no output state for " << _address_string() << LEND;
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

    ParameterDefinition & pd = parameters.create_return_reg(retval_reg, retval);
    if (GTRACE) {
      GTRACE << "The return value for " << _address_string() << " is: " << LEND;
      pd.debug();
    }
  }
}

const PDG * FunctionDescriptor::get_pdg() const {
  FunctionDescriptor * self = const_cast<FunctionDescriptor *>(this);
  return self->_get_pdg();
}

static std::atomic_flag arch_warn_once = ATOMIC_FLAG_INIT;
const PDG * FunctionDescriptor::_get_pdg() {
  write_guard<decltype(pdg_mutex)> pdg_guard{pdg_mutex};

  if (pdg) return &(*pdg); // &(*pdg) to convert from std::unique_ptr to raw pointer.
  // If we're an excluded function, don't try to compute the PDG.
  if (excluded) return nullptr;


  if (global_rops == nullptr) {
    if (!arch_warn_once.test_and_set()) {
      GFATAL << "This tool requires instruction semantics, which are not currently "
             << "supported for architecture '" << ds.get_arch_name() << "'." << LEND;
    }
    return nullptr;
  }

  // Set our stack delta analysis failures to zero, and reset the stack tracker.
  stack_analysis_failures = 0;
  GDEBUG << "Computing PDG for function " << _address_string() << LEND;

  pdg = make_unique<PDG>(ds, *this);
  assert(pdg);

  // How many stack delta analysis failures did we have?
  stack_analysis_failures = pdg->get_delta_failures();
  if (stack_analysis_failures > 0) {
    // This is the primary place that we report stack delta analysis filaures right now.
    SWARN << "There were " << stack_analysis_failures
          << " stack delta analysis failures in function " << _address_string() << LEND;
  }

  // Curiously, we never seem to have thought too much about what this routine was doing for
  // thunks and other "lightwight" functions.  For thunks, we probably should NOT be setting
  // calling conventions and parameters from the analysis that we just completed, but instead
  // propagating information from where we jump to, which should now be processed since we're
  // typically calling get_pdg in bottom up order.

  if (target_address) {
    GTRACE << "Propagating parameters from thunk for " << _address_string() << LEND;
    _propagate_thunk_info();
  }
  else {
    // Analyze our calling convention.  Must be AFTER we've marked the PDG as cached, because
    // analyzing the calling convention will attempt to recurse into get_pdg().
    register_usage.analyze(this);

    // Now that we know what our register usage was, determine our calling conventions.
    const CallingConventionMatcher& matcher = ds.get_calling_conventions();
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

    // We used to disable the creation of register and stack parameters if the calling
    // convention was invalid, but we found some cases where OOAnalyzer needed to be able to
    // work around some defects in _EH_prolog and _EH_epilog.  Since it's not clear that
    // creating these parameters will be harmful in anyway, let's try that.

    // Assume that registers always preceed all parameters (always true on Intel platforms?),
    // and create the register parameters.
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

  return &(*pdg); // &(*pdg) to convert from std::unique_ptr to raw pointer.
}

void FunctionDescriptor::free_pdg() {
  write_guard<decltype(pdg_mutex)> pdg_guard{pdg_mutex};
  pdg.reset();
}

// Get the PDG hash for the function.  This turns out to be really expensive -- like half the
// cost of the entire analysis of an OO program expensive... :-(
std::string FunctionDescriptor::get_pdg_hash(unsigned int num_hash_funcs) {
  if (pdg_hash.size() != 0) return pdg_hash;
  const PDG* p = get_pdg();
  if (p == NULL) return "";
  pdg_hash = p->getWeightedMaxHash(num_hash_funcs);
  return pdg_hash;
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

// TODO: replace x86 specific stuff w/ code that will work w/ other ISAs, should we ever start
// supporting those...  Here's a small start from Cory...  We might work with non-X86
// architectures now, but we'll warn about it (once).
//static bool arch_warned_once = false;
void FunctionDescriptor::_compute_function_hashes(ExtraFunctionHashData *extra) {
  // mwd: this code assumes this.  Is it guaranteed?
  assert(func);

  const CFG& cfg = get_pharos_cfg();
  write_guard<decltype(mutex)> guard{mutex};
  if (hashes_calculated) { return; }
  auto finally = make_finalizer([this]{hashes_calculated = true;});

  // should really do these elsewhere, but this is good for now:
  num_blocks = 0;
  num_blocks_in_cfg = 0;
  num_instructions = 0;
  num_bytes = 0;

  // A non-trivial change was made here by Cory.  Previously we were using the ROSE
  // (unfiltered) control flow graph, but now we're using the Pharos (filtered) control flow
  // graph to compute the function hashes.  Of course this cna _change_ the hashes for
  // functions.  The choice to use the unfiltered CFG seems to have been based on an inability
  // to conveniently call get_pharos_cfg() here without doing the complete PDG analysis.  Since
  // that bug is now fixed, there's no reason this shouldn't be based on the the Pharos CFG,
  // especially since it updates the function descriptor with fields likethe count of basic
  // blocks that are would be inconsistent with other important pharos analyses.
  std::vector<CFGVertex> cfgblocks = get_vertices_in_flow_order(cfg, entry_vertex);

  // ODEBUG produces too much in objdigger test output, so let's use trace for this:
  GTRACE << _address_string() << " fn has " << cfgblocks.size()
         << " basic blocks in control flow" << LEND;
  if (cfgblocks.size() == 0) {
    return;
  }

  SgAsmBlock *funceb = func->get_entry_block();
  SgAsmBlock *cfgeb = get(boost::vertex_name, cfg, cfgblocks[entry_vertex]);
  // I don't think this should be possible:
  if (funceb == NULL) {
    GERROR << "CFB No entry block in function: " << _address_string() << LEND;
    return;
  }
  if (cfgeb == NULL) {
    GERROR << "CFB No entry block in flow order: " << _address_string() << LEND;
    return;
  }
  // and I *really* hope this isn't either:
  if (funceb != cfgeb) {
    GERROR << "CFB Entry blocks do not match! " << addr_str(funceb->get_address()) << "!="
           << addr_str(cfgeb->get_address()) << " in function: " << _address_string() << LEND;
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
  dbg_disasm << "Debug Disassembly of Function " << display_name
             << " (" << addr_str(address) << ")" << std::endl;

  std::vector< rose_addr_t > bbaddrs;

  // iterate over all basic blocks in the function:
  for (size_t x = 0; x < num_blocks_in_cfg; x++) {
    SgAsmBlock *bb = get(boost::vertex_name, cfg, cfgblocks[x]);
    P2::BasicBlock::Ptr block = ds.get_block(bb->get_address());
    assert(block != NULL);

    std::string bbcpicbytes; // CPIC bytes (no control flow insns)
    std::string bbpicbytes; // PIC bytes (control flow insns included)
    std::vector< std::string > bbmnemonics;
    std::vector< std::string > bbmnemcats;

    dbg_disasm << "\t; --- bb start ---" << std::endl; // show start of basic block
    // Iterate over the instructions in the basic block:
    num_instructions += block->nInstructions();
    for (SgAsmInstruction* insn : block->instructions()) {
      // We're only X86 depdendent to the extent that we haven't thought about other architectures.
      //if (!isSgAsmX86Instruction(insn) && !arch_warned_once) {
      //  GERROR << "Non-X86 architectures are not supported!" << LEND;
      //  arch_warned_once = true;
      //}

      // Get the raw bytes...
      SgUnsignedCharList bytes = insn->get_raw_bytes();
      num_bytes += bytes.size();
      if (bytes.size() == 0) { // is this possible?
        GERROR << "CFB no raw bytes in instruction at " << addr_str(insn->get_address()) << LEND;
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
            if (program->memory.is_mapped(rose_addr_t(val))) {
              AddressIntervalSet chunks = fd->get_address_intervals();
              auto chunk1 = chunks.find(insn->get_address());
              auto chunk2 = chunks.find(val);
              // only null out address reference if it leaves the current chunk
              if (chunk1 != chunk2) {
                auto off = intexp->get_bit_offset();
                auto sz = intexp->get_bit_size();
                auto insnsz = insn->get_raw_bytes().size();

                // In some samples (e.g. 82c9e0083bd...) there are zero size expressions.  The
                // cause seems to be related to an Image with an usual ImageBase of zero.
                if (sz <= 0 || off % 8 != 0 || sz % 8 != 0 || // positive and byte-aligneed
                    sz/8 >= insnsz || off/8 >= insnsz || insnsz > 17) { // reasonable sizes
                  GWARN << "Instruction '" << debug_instruction(insn)
                        << "' has suspicious properties, size=" << insnsz
                        << " opsize=" << sz << " opoffset=" << off << LEND;
                  return;
                }
                std::pair< uint32_t, uint32_t > pval(off,sz);
                candidates.push_back(pval);
              }
            }
          }
        }
      };

      IntegerOffsetSearcher searcher(&ds, this, insn);
      searcher.traverse(insn, preorder);
      int numnulls = 0;
      for (auto sc = searcher.candidates.begin(); sc != searcher.candidates.end(); ++sc) {
        auto off = sc->first;
        auto sz = sc->second;
        // Ensure that updates will fit in the buffer. Should be enforced by insnsz above.
        if ((off/8 + sz/8) > wildcard.size()) {
          GERROR << "Instruction" << debug_instruction(insn) << " extends past buffer." << LEND;
          continue;
        }
        do {
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
    GTRACE << "calculating 'extra' hashes" << LEND;
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
      GTRACE << "adding edge to cfg_edges: " << aedge.first << "->" << aedge.second << LEND;
    }
  }
}

void FunctionDescriptor::compute_function_hashes(ExtraFunctionHashData *extra) const {
  const_cast<FunctionDescriptor *>(this)->_compute_function_hashes(extra);
}

// The mnemonic and mnemonic category related hashes used to be computed above and stored on
// the FD, but really only fn2hash cares about them so silly to always compute them and save
// the data on the object, just generate them on the fly when fn2hash asks now

const std::string& FunctionDescriptor::get_exact_bytes() const {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return exact_bytes;
}

const std::string& FunctionDescriptor::get_exact_hash() const {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return exact_hash;
}

const std::string& FunctionDescriptor::get_pic_bytes() const {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return pic_bytes;
}

const std::list< uint32_t > & FunctionDescriptor::get_pic_offsets() const {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return pic_offsets;
}

const std::string& FunctionDescriptor::get_pic_hash() const {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return pic_hash;
}

const std::string& FunctionDescriptor::get_composite_pic_hash() const {
  // If the bytes haven't been computed already, do so now.
  if (!hashes_calculated) compute_function_hashes();
  return composite_pic_hash;
}

// There seems to have been some confusion about the ROSE versus Pharos control flow graphs.
// The pharos control flow graph is the ROSE control flow graph with some blocks (vertices)
// removed.  The removed vertices are ones that we've deemed to be "bad" code, and those with
// no known predecessors (excluding the entry block).  It is now properly cached and updated in
// comparison to some earlier code that did strange things.  Cory later notes that we don't
// actually remove the vertices, just the edges to and from the vertices.  This was perhaps
// accidental since the vertex can't be removed correctly while iterating over the vertices.
//
// Here are some examples of the kinds of things removed in the Pharos CFG: Basic blocks that
// aren't in the control flow at all (NOP padding?).  Blocks that have no known predecessors
// (computed jumps?).  Catch handler blocks that are connected to the control flow only through
// advanced reasoning.  Code that looks like "bad" code (e.g. from a jump into encrypted code).
// Another less desired example is that in conjunction with our thunk/jmp splitting partitioner
// behavior, we appear to be removing the blocks of the called function following tail-call
// optimzied jumps.  It's not clear that this is what was really desired in cases where the
// remaining code was not literally a thunk.  More investigation is needed.
CFG const & FunctionDescriptor::get_pharos_cfg() const
{
  write_guard<decltype(mutex)> guard{mutex};

  // If we've already done the work, just return the answer.
  if (pharos_control_flow_graph_cached) return pharos_control_flow_graph;

  // Otherwise, we have to do it now.
  FunctionDescriptor & t = const_cast<FunctionDescriptor &>(*this);
  CFG const & rose_cfg = _get_rose_cfg();
  t.pharos_control_flow_graph = rose_cfg;
  t.pharos_control_flow_graph_cached = true;

  // Decide which blocks are bad code.  Because bad block analysis could be expensive, we
  // should probably be saving this somewhere (rather than in a local variable).  For now,
  // we'll just keep it locally, and in the future, we'll see if we can stick this in a flag
  // bit on the Partitioner2 basic block or something like that.
  std::map<rose_addr_t, bool> bad;
  for (auto vertex : cfg_vertices(t.pharos_control_flow_graph)) {
    SgAsmBlock *block = get(boost::vertex_name, t.pharos_control_flow_graph, vertex);
    bad[block->get_address()] = check_for_bad_code(ds, block);
  }

  // But for the control-flow graph portions of the analysis we need a set of edges that are
  // consistent with our algorithm.  Presently, we've determined that blocks which lack
  // predecessors (other than the entry block) are not permitted, even thought they commonly
  // occur for a variety of reasons (e.g. catch blocks).  It is permitted however to have
  // multiple blocks with no successors (e.g. multiple returns, indeterminate jumps, etc.)
  // This algorithm recursively removes the edges for vertexes if they're bad or have no
  // predecessors.  It needs to do so recursively so that edges are also removed from blocks
  // that only follow removed blocks, since they might flow into blocks that are in the control
  // flow.
  bool changed = true;
  while (changed) {
    changed = false;
    for (auto vertex : cfg_vertices(t.pharos_control_flow_graph)) {
      SgAsmBlock *block = get(boost::vertex_name, t.pharos_control_flow_graph, vertex);
      rose_addr_t baddr = block->get_address();
      size_t degree = boost::in_degree(vertex, t.pharos_control_flow_graph);
      // The entry block is permitted to be deemed as bad code.
      if ((degree == 0 && vertex != entry_vertex) || bad[baddr]) {
        // If the block isn't in the control flow, remove both the in and out edges.
        SDEBUG << "Removing block " << baddr << " in function " << _address_string()
               << " from control flow graph because it was bad or unreachable." << LEND;
        size_t out_degree = boost::out_degree(vertex, t.pharos_control_flow_graph);
        if (out_degree) {
          remove_out_edge_if(vertex, [](...){return true;}, t.pharos_control_flow_graph);
          changed = true;
        }
        size_t in_degree = boost::in_degree(vertex, t.pharos_control_flow_graph);
        if (in_degree) {
          remove_in_edge_if(vertex, [](...){return true;}, t.pharos_control_flow_graph);
          changed = true;
        }
      }
    }
  }

  return t.pharos_control_flow_graph;
}

CFG const & FunctionDescriptor::get_rose_cfg() const {
  write_guard<decltype(mutex)> guard{mutex};
  return _get_rose_cfg();
}

CFG const & FunctionDescriptor::_get_rose_cfg() const {
  // mwd: this code assumes this.  Is it guaranteed?
  assert(func);

  // If we've already done the work, just return the answer.
  if (rose_control_flow_graph_cached) return rose_control_flow_graph;

  // Otherwise, we have to do it now.  We're still using the AST based control flow graph
  // analyzer for a little while longer, but hopefully that will change soon.
  Rose::BinaryAnalysis::ControlFlow rose_cfg_analyzer;

  FunctionDescriptor & t = const_cast<FunctionDescriptor &>(*this);
  t.rose_control_flow_graph = rose_cfg_analyzer.build_block_cfg_from_ast<CFG>(t.func);
  // TODO: set list of basic block boundaries (list of AddressInterval?) that are in CFG
  t.rose_control_flow_graph_cached = true;
  return t.rose_control_flow_graph;
}

// There may be a better way to do this, but if you have the address and want the instruction,
// this is the only way Cory is currently aware of.
SgAsmInstruction* FunctionDescriptor::get_insn(const rose_addr_t addr) const {
  read_guard<decltype(mutex)> guard{mutex};

  // mwd: this code assumes this.  Is it guaranteed?
  assert(func);

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

// explicit sorting of instructions by address using a map:
InsnVector FunctionDescriptor::get_insns_addr_order() const {
  read_guard<decltype(mutex)> guard{mutex};

  // TODO: do this once & cache on object?  Also, should there be another variant for "only
  // ones in CFG" too?
  InsnVector result;
  std::map< rose_addr_t, SgAsmInstruction* > rmap;
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
      SgAsmInstruction *insn = isSgAsmInstruction(insns[y]);
      if (insn) {
        rmap[insn->get_address()] = insn;
      }
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
bool FunctionDescriptor::contains_insn_at(rose_addr_t addr) const {
  read_guard<decltype(mutex)> guard{mutex};

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

// Return the connected vertices in flow order in the Pharos (filtered) control flow graph.  We
// should use the pharos control flow graph whenever possible because most of the other fields
// in the function descriptor are based on this CFG as well.  There's also no need to specify
// the entry point, because every vertex is connected to the entry point.
std::vector<CFGVertex> FunctionDescriptor::get_vertices_in_flow_order() const {
  return get_vertices_in_flow_order(get_pharos_cfg(), entry_vertex);
}

// Return the connected vertices in flow order in the provided control flow graph. This should
// be used when you explicitly want to use the unfiltered ROSE CFG.  Note that other fields in
// function descriptor may not be consistent with this CFG.  The entry vertex is optional, and
// will default to the entry vertex (vertex 0).
std::vector<CFGVertex> FunctionDescriptor::get_vertices_in_flow_order(const CFG& cfg, CFGVertex entry) {
  Rose::BinaryAnalysis::ControlFlow analyzer;
  return analyzer.flow_order(cfg, entry);
}

// Return the list of blocks with no successors connected to the entry point in the Pharos CFG.
// Since there's only a single entry vertex (vertex 0), it doesn't need to be passed.
std::vector<CFGVertex> FunctionDescriptor::get_return_vertices() const {
  return get_return_vertices(get_pharos_cfg(), entry_vertex);
}

// Return the list of blocks with no successors from the provided CFG and entry point.
std::vector<CFGVertex> FunctionDescriptor::get_return_vertices(const CFG& cfg, CFGVertex entry) {
  Rose::BinaryAnalysis::ControlFlow analyzer;
  return analyzer.return_blocks(cfg, entry);
}

// Deprecated in favor of get_return_vertices(), provides backward compatability with apigraph.cpp
BlockSet FunctionDescriptor::get_return_blocks() const {
  BlockSet blocks;
  const CFG& cfg = get_pharos_cfg();
  for (CFGVertex vertex : get_return_vertices()) {
    SgAsmBlock *block = convert_vertex_to_bblock(cfg, vertex);
    if (block) blocks.insert(block);
  }
  return blocks;
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
rose_addr_t FunctionDescriptor::follow_thunks(bool* endless) const {
  read_guard<decltype(mutex)> guard{mutex};
  return _follow_thunks(endless);
}

rose_addr_t FunctionDescriptor::_follow_thunks(bool* endless) const {

  // We've always got to return a value in endless if the caller requested one.
  if (endless != NULL) *endless = false;
  // A short circuit for the most common scenario (no thunks at all).
  if (!target_address) return address;
  if (!target_func) return target_address;

  // Start with an empty list of visited addresses.
  AddrSet visited;
  // Add ourselves
  visited.insert(address);

  FunctionDescriptor const *fd = target_func;

  while (true) {
    // Get the address of the current function.
    rose_addr_t faddr = (fd == this) ? address : fd->get_address();
    // If we've already visited this address, there's a loop.
    if (visited.find(faddr) != visited.end()) {
      // If the caller is interested in testing for endless loops, they will have passed a
      // pointer to a boolean for that purpose, if not, the boolean pointer defaults to
      // NULL.  Most callers don't care and can ignore this parameter.
      if (endless != NULL) {
        *endless = true;
      }
      // Log a warning, since endless loops in programs are always suspicious.
      SWARN << "Endless loop of thunks detected at " << _address_string() << LEND;
      return faddr;
    }
    // Add this address to the list of visited addresses.
    visited.insert(faddr);
    assert(fd != this);
    // Get the next function descriptor in the chain if there is one.
    FunctionDescriptor const * next_fd = fd->get_jmp_fd();
    // If there is a function descriptor, just follow it to the next function.
    if (next_fd == nullptr) {
      break;
    }
    fd = next_fd;
  }

  // But if there wasn't a function descriptor we're at the end of the chain.  First check to
  // see if there was an address, but just no function descriptor to go with it.
  rose_addr_t next_addr = fd->get_jmp_addr();
  // If the target address is zero, then we're not a thunk at all.  That makes the current
  // function the end of the chain, and that address is in faddr.  Return it now.
  if (next_addr == 0) return fd->get_address();
  // Regardless of whether the end of the chain is an import descriptor or a disassembly
  // failure, the correct answer is in next_addr.  Return it now.
  return next_addr;
}

// Forces the address returned from follow_thunks into a function descriptor or NULL.
const FunctionDescriptor* FunctionDescriptor::follow_thunks_fd(bool* endless) const {
  read_guard<decltype(mutex)> guard{mutex};
  rose_addr_t target = _follow_thunks(endless);
  const FunctionDescriptor* tfd = ds.get_func(target);
  return tfd;
}

// return a string w/ a masm-ish disassembly of this function descriptor:
std::string FunctionDescriptor::disasm() const {
  // TODO: apparently I started adding this function and ended up outputting the disassembly in
  // debug statements in compute_function_hashes() instead because I was already walking the
  // functions, chunks, and instructions and inspecting the bytes there...  Should probably
  // actually implement that functionality here instead/additionally at some point?  Or for
  // now, could call debug_function from masm.cpp I suppose...better than an empty answer
  // should anyone use this...

  return debug_function(this,17,true,true);
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
