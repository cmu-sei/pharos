
// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.
// Author: Jeff Gennari

#include "types.hpp"
#include "xsb.hpp"
#include "pdg.hpp"
#include "defuse.hpp"
#include "stkvar.hpp"

// set up local logging
namespace {
Sawyer::Message::Facility mlog("TYPEA");
}
struct InitTypeLogger {
  InitTypeLogger() {
    Sawyer::Message::mfacilities.insert(mlog);
  }
};
static InitTypeLogger _turnon;

namespace pharos {

// Enumerations to support prolog queries
enum type_enum { IS, ISNOT, BOTTOM, TOP };
template <> const char *EnumStrings<type_enum>::data[] = {"is", "isnot", "bottom", "top"};

enum pointer_enum { POINTER, NOTPOINTER };
template <> const char *EnumStrings<pointer_enum>::data[] = {"pointer", "notpointer"};

enum dir_enum { IN, OUT };
template <> const char *EnumStrings<dir_enum>::data[] = {"in", "out"};

enum sign_enum { SIGNED, UNSIGNED };
template <> const char *EnumStrings<sign_enum>::data[] = {"signed", "unsigned"};

// Prolog fact strings
const std::string MEMADDR_FACT = "memaddr";
const std::string BITWIDTH_FACT = "bitwidth";
const std::string VAL_FACT = "value";
const std::string FNCALL_ARG_FACT = "functionCallArg";
const std::string FNCALL_TARGET_FACT = "functionCallTarget";
const std::string APINAME_FACT = "apiCallName";        // name of an API function
const std::string API_PARAM_TYPE_FACT = "apiParamType"; // name of parameter type
const std::string TYPE_POINTER_FACT = "typePointerness";   // is parameter a pointer type
const std::string TYPE_SIGNED_FACT = "typeSignedness";    // is parameter signed
const std::string KNOWN_POINTER_FACT = "knownPointer";  // is parameter a pointer type
const std::string KNOWN_SIGNED_FACT = "knownSigned";   // is parameter signed
const std::string KNOWN_TYPENAME_FACT = "knownTypename";     // the typename is known
const std::string TYPE_REF_FACT = "typeRef";
const std::string SAME_TYPE_FACT = "sameType";
const std::string POINTS_TO_FACT = "pointsTo";
const std::string ARCH_FACT = "archBits";

// Prolog query strings
const std::string FINAL_POINTER_QUERY = "finalPointer";
const std::string FINAL_SIGNED_QUERY = "finalSigned";
const std::string TYPE_NAME_QUERY = "typeName";

using namespace prolog;

typedef impl::xsb::xsb_term XsbTerm;

bool
has_type_descriptor(TreeNodePtr tnp) {

   if (tnp == NULL) {
    MDEBUG << "Cannot fetch/create type descriptor because treenode is NULL" << LEND;
    return false;
  }

  try {
    TypeDescriptorPtr tmp = boost::any_cast< TypeDescriptorPtr >(tnp->userData());
    return true;
  }
  catch ( boost::bad_any_cast& e ) {
    // For whatever reason this type descriptor is invalid, so create a default one
  }
  return false;
}

// Fetch the type descriptor off of a treenode or create a default one
// if it cannot be found
TypeDescriptorPtr
fetch_type_descriptor(TreeNodePtr tnp) {

  if (has_type_descriptor(tnp)) {
    return boost::any_cast< TypeDescriptorPtr >(tnp->userData());
  }

  MINFO << "Creating new default type descriptor" << LEND;

  TypeDescriptorPtr td(new TypeDescriptor);

  // Every types treenode has a bitwidth fact from the treenode itself
  td->bit_width(tnp->nBits());

  boost::any ud = td;
  tnp->userData(ud);

  return td;
}

// Format tree nodes so that value facts are asserted. These methods
// are ways to get tree nodes in to, and out of, XSB prolog. This
// really means just treating Tree Node pointers as a unsigned 64 bit
// number
uint64_t treenode_to_xsb(TreeNodePtr tn) {
  return reinterpret_cast<uint64_t>(&*tn);
}

TreeNode* xsb_to_treenode(uint64_t tn) {
  return reinterpret_cast<TreeNode*>(tn);
}

// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
// TypeDescriptor methods
// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-

// The default constructor simply sets everything to the top of the lattices
// to indicate that nothing is yet known.
TypeDescriptor::TypeDescriptor()
  :  pointerness_(types::Pointerness::Top),
     signedness_(types::Signedness::Top),
     type_name_(types::TypenameTop),
     bit_width_(types::BitwidthTop),
     is_aggregate_(false) { }

// Copy constructor for a type descriptor
TypeDescriptor::TypeDescriptor(const TypeDescriptor& other) {
  type_name_ = other.type_name_;
  pointerness_ = other.pointerness_;
  signedness_ = other.signedness_;
  bit_width_ = other.bit_width_;
  is_aggregate_ = other.is_aggregate_;

  if (pointerness_ == types::Pointerness::Pointer) {
    reference_types_ = other.reference_types_;
  }

  if (is_aggregate_) {
    components_ = other.components_;
  }
}

// assignment operator
TypeDescriptor&
TypeDescriptor::operator=(const TypeDescriptor &other) {
  type_name_ = other.type_name_;
  pointerness_ = other.pointerness_;
  signedness_ = other.signedness_;
  bit_width_ = other.bit_width_;
  is_aggregate_ = other.is_aggregate_;

  if (pointerness_ == types::Pointerness::Pointer) {
    reference_types_ = other.reference_types_;
  }

  if (is_aggregate_) {
    components_ = other.components_;
  }
  return *this;
}

TypeDescriptor::~TypeDescriptor() {
  if (reference_types_.empty() == false) {
    reference_types_.clear();
  }
  if (components_.empty() == false) {
    components_.clear();
  }
}

void
TypeDescriptor::to_facts(TreeNodePtr tn, std::shared_ptr<prolog::Session> session) {

  // Emit known typename facts
  session->add_fact(KNOWN_TYPENAME_FACT, treenode_to_xsb(tn), type_name_);

  // Emit known pointerness facts
  if (pointerness_ == types::Pointerness::Pointer) {
    session->add_fact(KNOWN_POINTER_FACT, treenode_to_xsb(tn), IS);
  }
  else if (pointerness_ == types::Pointerness::NotPointer) {
    session->add_fact(KNOWN_POINTER_FACT, treenode_to_xsb(tn), ISNOT);
  }
  else if (pointerness_ == types::Pointerness::Bottom) {
    session->add_fact(KNOWN_POINTER_FACT, treenode_to_xsb(tn), BOTTOM);
  }
  else if (pointerness_ == types::Pointerness::Top) {
    session->add_fact(KNOWN_POINTER_FACT, treenode_to_xsb(tn), TOP);
  }

  // Emit known signedness facts
  if (signedness_ == types::Signedness::Signed) {
    session->add_fact(KNOWN_SIGNED_FACT, treenode_to_xsb(tn), IS);
  }
  else if (signedness_ == types::Signedness::Unsigned) {
    session->add_fact(KNOWN_SIGNED_FACT, treenode_to_xsb(tn), ISNOT);
  }
  else if (signedness_ == types::Signedness::Bottom) {
    session->add_fact(KNOWN_SIGNED_FACT,treenode_to_xsb(tn), BOTTOM);
  }
  else if (signedness_ == types::Signedness::Top) {
    session->add_fact(KNOWN_SIGNED_FACT, treenode_to_xsb(tn), TOP);
  }

 // Emit known bitwidth
 session->add_fact(BITWIDTH_FACT, treenode_to_xsb(tn), bit_width_);
}

std::string
TypeDescriptor::to_string() {

  std::stringstream ss;

  if (pointerness_ == types::Pointerness::Pointer) {
    ss << "pointerness=pointer";
  }
  else if (pointerness_ == types::Pointerness::NotPointer) {
    ss << "pointerness=not pointer";
  }
  else if (pointerness_ == types::Pointerness::Bottom) {
    ss << "pointerness=bottom";
  }
  else if (pointerness_ == types::Pointerness::Top) {
    ss << "pointerness=top";
  }
  else {
    ss << "pointerness=unknown";
  }

  if (signedness_ == types::Signedness::Signed) {
    ss << " signedness:signed";
  }
  else if (signedness_ == types::Signedness::Unsigned) {
    ss << " signedness=unsigned";
  }
  else if (signedness_ == types::Signedness::Bottom) {
    ss << " signedness=bottom";
  }
  else if (signedness_ == types::Signedness::Top) {
    ss << " signedness=top";
  }
  else {
    ss << " signedness=unknown";
  }

  if (bit_width_ == types::BitwidthTop) {
    ss << " width=top";
  }
  else if (bit_width_ == types::BitwidthBottom) {
    ss << " width=bottom";
  }
  else {
    ss << " width=" << bit_width_;
  }

  if (type_name_ == types::TypenameTop) {
    ss << " name=<unknown>";
  }
  else {
    ss << " name=" << type_name_;
  }

  return ss.str();
}

// type properties

void TypeDescriptor::bit_width(size_t bw) { bit_width_ = bw; }

size_t TypeDescriptor::bit_width() const { return bit_width_; }

void TypeDescriptor::is_pointer() { pointerness_ = types::Pointerness::Pointer; }

void TypeDescriptor::not_pointer() { pointerness_ = types::Pointerness::NotPointer; }

void TypeDescriptor::bottom_pointer() { pointerness_ = types::Pointerness::Bottom; }

types::Pointerness TypeDescriptor::Pointerness() const { return pointerness_; }

void TypeDescriptor::is_signed() { signedness_ = types::Signedness::Signed; }

void TypeDescriptor::not_signed() { signedness_ = types::Signedness::Unsigned; }

void TypeDescriptor::bottom_signed() { signedness_ = types::Signedness::Bottom; }

types::Signedness TypeDescriptor::Signedness() const { return signedness_; }

// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
// OperationStrategyContext methods
// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-

const std::string &OperationStrategy::get_op_name() const {
  return op_name_;
}

// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
// TypeSolver methods
// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-

void
TypeSolver::assert_arch_fact() {

  if (!session_) return;

  session_->add_fact(ARCH_FACT, global_descriptor_set->get_arch_bits());
}

// This function asserts facts for actual values on tree nodes
void
TypeSolver::assert_value_facts(TreeNodePtr tnp) {

  if (!session_ || !tnp) return;

  // we currently don't handle values larger than 64 bits, i.e. floats
  if (tnp->nBits() > 64) {
    MDEBUG << "Detected possible floating point value: " << *tnp << LEND;
    return;
  }
  session_->add_fact(VAL_FACT, treenode_to_xsb(tnp), tnp->toInt());
}

// assert facts concerning the size of tree nodes. The format of this fact is
// (bitwidth HASH SIZE)
void TypeSolver::assert_bitwidth_fact(TreeNodePtr tnp) {

  if (!session_ || !tnp) return;

  session_->add_fact(BITWIDTH_FACT, treenode_to_xsb(tnp), tnp->nBits());
}

// Assert various facts for function calls. In particular, three
// facts are asserted:
//
// A fact to relate call addresses to call targets
// A fact to relate call addresses to function parameters
void
TypeSolver::assert_function_call_facts(const CallDescriptor *cd) {

  MDEBUG << "Analyzing function call at " << addr_str(cd->get_address()) << LEND;

  if (cd == NULL) {
    OERROR << "Invalid call descriptor" << LEND;
  }

  if (!session_) {
    OERROR << "Cannot assert function call facts - invalid prolog session" << LEND;
    return;
  }

  // for each out-going call add a fact for the target of a function call
  // functionCallTarget(Source Address, Destination Address).
  FunctionDescriptor *targetFd = cd->get_function_descriptor();
  if (targetFd) {
    if (targetFd->get_address() != 0) { // the called function address may be null, for instance if it is an imported function

      MDEBUG << "Generating facts for outgoing call at " << addr_str(cd->get_address()) << " to "
            << addr_str(targetFd->get_address()) << LEND;

      session_->add_fact(FNCALL_TARGET_FACT, cd->get_address(), targetFd->get_address());

    }
  }

  const StackVariablePtrList& stack_vars = current_function_->get_stack_variables();
  const ParamVector& caller_params = cd->get_parameters().get_params();

  MDEBUG << "This function has " << stack_vars.size() << " stack variables and "
         << caller_params.size() << " parameters" << LEND;

  // For each stack variable, emit the "pointsTo" facts
  for (StackVariable *stkvar : stack_vars) {
    std::vector<std::reference_wrapper<const AbstractAccess>> var_aas = stkvar->accesses();
    const AbstractAccess& var_aa = var_aas.at(0);

    if (!var_aa.value || !var_aa.memory_address) continue;

    TreeNodePtr var_aa_val = var_aa.value->get_expression();
    TreeNodePtr var_aa_mem = var_aa.memory_address->get_expression();
    uint64_t v = reinterpret_cast<uint64_t>(&*var_aa_val);
    uint64_t m = reinterpret_cast<uint64_t>(&*var_aa_mem);

    if (has_type_descriptor(var_aa_val) == false) {
      //assert_initial_facts(var_aa_val);
      recursively_assert_facts(var_aa_val);
    }
    if (has_type_descriptor(var_aa_mem) == false) {
      // assert_initial_facts(var_aa_mem);
      recursively_assert_facts(var_aa_mem);
    }

    session_->add_fact(POINTS_TO_FACT, treenode_to_xsb(var_aa_mem), treenode_to_xsb(var_aa_val));

    MTRACE << "Stack variable PointsTo:  = " << *var_aa_mem << " - " << addr_str(m)
           << " -> " << *var_aa_val << " - " << addr_str(v) << LEND;
  }

  // For each global variable, emit the "pointsTo" facts
  const GlobalMemoryDescriptorMap& globals = global_descriptor_set->get_global_map();
  const FunctionDescriptorMap& funcs = global_descriptor_set->get_func_map();
  for (const GlobalMemoryDescriptorMap::value_type & pair : globals) {

    GlobalMemoryDescriptor global_var = pair.second;

    // is this is a function, then it is not really a global variable

    if (funcs.find(global_var.get_address()) != funcs.end()) continue;

    SymbolicValuePtr address = global_var.get_memory_address();
    SymbolicValuePtr value = global_var.get_value();

    if (!value || !address) continue;

    TreeNodePtr global_val_tnp = value->get_expression();
    TreeNodePtr global_mem_tnp = address->get_expression();
    uint64_t v = reinterpret_cast<uint64_t>(&*global_val_tnp);
    uint64_t m = reinterpret_cast<uint64_t>(&*global_mem_tnp);

    if (has_type_descriptor(global_val_tnp) == false) {
      recursively_assert_facts(global_val_tnp);
    }
    if (has_type_descriptor(global_mem_tnp) == false) {
      recursively_assert_facts(global_mem_tnp);
    }

    session_->add_fact(POINTS_TO_FACT, treenode_to_xsb(global_mem_tnp), treenode_to_xsb(global_val_tnp));

    MTRACE << "Global variable PointsTo:  = " << *global_mem_tnp << " - " << addr_str(m)
           << " -> " << *global_val_tnp << " - " << addr_str(v) << LEND;
  }

  // For each stack variable, emit the "pointsTo" facts
  for (StackVariable *stkvar : stack_vars) {
    std::vector<std::reference_wrapper<const AbstractAccess>> var_aas = stkvar->accesses();
    const AbstractAccess& var_aa = var_aas.at(0);

    if (!var_aa.value || !var_aa.memory_address) continue;

    TreeNodePtr var_aa_val = var_aa.value->get_expression();
    TreeNodePtr var_aa_mem = var_aa.memory_address->get_expression();
    uint64_t v = reinterpret_cast<uint64_t>(&*var_aa_val);
    uint64_t m = reinterpret_cast<uint64_t>(&*var_aa_mem);

    if (has_type_descriptor(var_aa_val) == false) {
      recursively_assert_facts(var_aa_val);
    }
    if (has_type_descriptor(var_aa_mem) == false) {
      recursively_assert_facts(var_aa_mem);
    }

    session_->add_fact(POINTS_TO_FACT, treenode_to_xsb(var_aa_mem), treenode_to_xsb(var_aa_val));

    MTRACE << "Stack variable PointsTo:  = " << *var_aa_mem << " - " << addr_str(m)
           << " -> " << *var_aa_val << " - " << addr_str(v) << LEND;
  }

  for (const ParameterDefinition &param : caller_params) {

    if (!param.value || !param.address) continue;

    TreeNodePtr par_aa_val = param.value->get_expression();
    TreeNodePtr par_aa_mem = param.address->get_expression();
    uint64_t pvaddr = reinterpret_cast<uint64_t>(&*par_aa_val);
    uint64_t pmaddr = reinterpret_cast<uint64_t>(&*par_aa_mem);

    session_->add_fact(FNCALL_ARG_FACT, cd->get_address(), param.num, treenode_to_xsb(par_aa_val));

    MTRACE << "===" << LEND;
    MTRACE << "Evaluating TNP Param: (" << addr_str(pvaddr) << ") " << *par_aa_val << LEND;

    if (has_type_descriptor(par_aa_val) == false) {
      // assert_initial_facts(par_aa_val);
      recursively_assert_facts(par_aa_val);
    }
    if (has_type_descriptor(par_aa_mem) == false) {
      // assert_initial_facts(par_aa_mem);
      recursively_assert_facts(par_aa_mem);
    }

    // 1. param_mem points to param val fact
    session_->add_fact(POINTS_TO_FACT, treenode_to_xsb(par_aa_mem), treenode_to_xsb(par_aa_val));

    for (StackVariable *stkvar : stack_vars) {

      // TODO: don't just take the 0 abstract access.
      std::vector<std::reference_wrapper<const AbstractAccess>> var_aas = stkvar->accesses();
      const AbstractAccess& var_aa = var_aas.at(0);

      if (!var_aa.value || !var_aa.memory_address) continue;

      TreeNodePtr var_aa_val = var_aa.value->get_expression();
      TreeNodePtr var_aa_mem = var_aa.memory_address->get_expression();
      uint64_t vvaddr = reinterpret_cast<uint64_t>(&*var_aa_val);
      uint64_t vmaddr = reinterpret_cast<uint64_t>(&*var_aa_mem);

      MTRACE << "Stack variable: " << stkvar->to_string() << LEND;
      MTRACE << "Stack variable AA: val = " << *var_aa_val << " - " << addr_str(vvaddr)
            << ", mem = " << *var_aa_mem << " - " << addr_str(vmaddr) << LEND;

      MTRACE << "Param variable AA: val = " << *par_aa_val << " - " << addr_str(pvaddr)
             << ", mem = " << *par_aa_mem << " - " << addr_str(pmaddr) << LEND;


      auto& is = param.value->get_defining_instructions();
      MTRACE << "Parameter definers:" << LEND;
      for (auto& i : is) {
        MTRACE << "   Def: " << addr_str(i->get_address()) << LEND;
      }

      auto& sis = var_aa.value->get_defining_instructions();
      MTRACE << "Stkvar definers:" << LEND;
      for (auto& si : sis) {
        MTRACE << "   Def: " << addr_str(si->get_address()) << LEND;
      }

      // Do the parameter and stack variable share evidence?  if the
      // value in parameter read from insn from the local variable,
      // they must be the same type.  is var address the same value
      // read?

      // in this case the address of the stack var is pushed so it's
      // stack address is the param value. This is a classic
      // pass-by-reference (PBR) arrangement. Essentially, this means
      // that we are passing the address of a stack variable to a function
      if (var_aa.memory_address->can_be_equal(param.value)) {

        if (vmaddr != pvaddr) {
          MTRACE << "*** Detected stack variable pass by reference" << LEND;
          session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(var_aa_mem), treenode_to_xsb(par_aa_val));
        }
      }

      // This first test checks for pass by value by comparing values
      else if (var_aa_val->isEquivalentTo(par_aa_val)) {

        // sameType facts are not needed for the exact same treenode
        if (vvaddr != pvaddr) {

          // If the two values are equal, check their lineage to see if
          // they are related (i.e. have commong defining instructions).
          const InsnSet& par_definers = param.value->get_defining_instructions();
          const InsnSet& var_definers = var_aa.value->get_defining_instructions();
          InsnSet intersect;

          // if the intersection of the parameter and stack definers is not the empty set
          std::set_intersection(par_definers.begin(), par_definers.end(),
                                var_definers.begin(), var_definers.end(),
                                std::inserter(intersect, intersect.begin()));

          if (intersect.size() > 0) {

            session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(var_aa_val), treenode_to_xsb(par_aa_val));

            MTRACE << "*** Detected stack variable pass by value" << LEND;
          }
        }
      }
    } // for each stack variable

    // check for PBV and PBR in global vars
    for (const GlobalMemoryDescriptorMap::value_type & pair : globals)  {

      GlobalMemoryDescriptor global_var = pair.second;

      // Again, skip function pointers
      if (funcs.find(global_var.get_address()) != funcs.end()) continue;

      SymbolicValuePtr global_address = global_var.get_memory_address();
      SymbolicValuePtr global_value = global_var.get_value();

      if (!global_value || !global_address) continue;

      TreeNodePtr global_val_tnp = global_value->get_expression();
      TreeNodePtr global_mem_tnp = global_address->get_expression();

      if (!global_val_tnp || !global_mem_tnp) continue;

      MTRACE << "Global variable val = " << *global_val_tnp << ", mem = " << *global_mem_tnp << LEND;
      MTRACE << "Param "  << param.num << " variable val = " << *par_aa_val << ", mem = " << *par_aa_mem << LEND;

      // if the memory address of the global is the value of the parameter, then this is PBR
      if (global_mem_tnp->isEquivalentTo(par_aa_val)) {

        uint64_t gmaddr = reinterpret_cast<uint64_t>(&*global_mem_tnp);

        // there is no reason to emit sameType facts for the same exact treenode
        if (gmaddr != pvaddr) {
          MTRACE << "*** Detected global variable pass by reference" << LEND;
          session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(global_mem_tnp), treenode_to_xsb(par_aa_val));
        }
      }

      // Test for PBV by comparing values
      else if (global_val_tnp->isEquivalentTo(par_aa_val)) {

        uint64_t gvaddr = reinterpret_cast<uint64_t>(&*global_val_tnp);

        // there is no reason to emit sameType facts for the same exact treenode
        if (gvaddr != pvaddr) {
          MTRACE << "*** Detected global variable pass by value" << LEND;
          session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(global_val_tnp), treenode_to_xsb(par_aa_val));
        }
      }
    } // for each global variable

    MTRACE << "===" << LEND;
  }  // for each parameter


  ParamVector callee_params;
  // if this is an import, then there are no interprocedural facts, but there are caller-perspective facts
  const ImportDescriptor *imp = cd->get_import_descriptor(); // is this an import?
   if (imp != NULL) {
     MDEBUG << "Detected call to import" << LEND;
     const FunctionDescriptor* impfd = imp->get_function_descriptor();
     if (impfd) {
       callee_params = impfd->get_parameters().get_params();
     }
     //return;
   }
   else {
     MDEBUG << "Detected regular call" << LEND;
     if (targetFd) {
       callee_params = targetFd->get_parameters().get_params();
     }
   }
   // assert facts based on function flow

   // It is possible that caller and callee parameter lists are empty
   if (caller_params.empty() || callee_params.empty()) {
     MDEBUG << "Abandoning function fact generation due to empty parameter list" << LEND;
     return;
   }

   ParamVector::const_iterator callee_iter = callee_params.begin();
   ParamVector::const_iterator caller_iter = caller_params.begin();

   while (caller_iter != caller_params.end() && callee_iter != callee_params.end()) {

     const ParameterDefinition &caller_param = *caller_iter;
     const ParameterDefinition &callee_param = *callee_iter;

     // the parameters map to each other
     if (caller_param.num == callee_param.num) {

       if (caller_param.value != NULL && callee_param.value != NULL) {

         TreeNodePtr caller_tnp = caller_param.value->get_expression(); // the caller is this function
         bool caller_has_td = has_type_descriptor(caller_tnp);
         TypeDescriptorPtr caller_td = fetch_type_descriptor(caller_tnp);
         if (caller_has_td == false) {
           recursively_assert_facts(caller_tnp);
         }

         TreeNodePtr callee_tnp = callee_param.value->get_expression(); // the callee is the called function
         bool callee_has_td = has_type_descriptor(callee_tnp);
         TypeDescriptorPtr callee_td = fetch_type_descriptor(callee_tnp);
         if (callee_has_td == false) {
           recursively_assert_facts(callee_tnp);
         }

         rose_addr_t addr = reinterpret_cast<rose_addr_t>(&*callee_tnp);
         MDEBUG << "TypeDescriptor for callee TNP (" << addr_str(addr) << "): " << callee_td->to_string() << LEND;

         if (callee_td->Pointerness() == types::Pointerness::Pointer) {
           session_->add_fact(KNOWN_POINTER_FACT, treenode_to_xsb(caller_tnp), IS);
         }
         else if (callee_td->Pointerness() == types::Pointerness::NotPointer) {
           session_->add_fact(KNOWN_POINTER_FACT, treenode_to_xsb(caller_tnp), ISNOT);
         }

         if (callee_td->Signedness() == types::Signedness::Signed) {
           session_->add_fact(KNOWN_SIGNED_FACT, treenode_to_xsb(caller_tnp), IS);
         }
         else if (callee_td->Signedness() == types::Signedness::Unsigned) {
           session_->add_fact(KNOWN_SIGNED_FACT, treenode_to_xsb(caller_tnp), ISNOT);
         }

         std::string known_type_name = callee_td->get_name();
         if (known_type_name.empty() == false) {
           // there is a name
           session_->add_fact(KNOWN_TYPENAME_FACT, treenode_to_xsb(caller_tnp), known_type_name);
         }
       }
     }
     // Move to the next parameter set
     ++callee_iter;
     ++caller_iter;
   }
}

void
TypeSolver::assert_initial_facts(TreeNodePtr tnp) {

  // Should we create default facts for the tree nodes?

  assert_bitwidth_fact(tnp);

  if (tnp->isNumber()) {
    if (tnp->nBits() <= 64) { // <= this is a hack to prevent a core dump in ROSE
      MDEBUG << "This param is a number and will receive a value fact" << LEND;

      assert_value_facts(tnp);
    }
  }

  // Must handle ITEs by basically asserting that all ITE elements
  // are the same type

  TreeNodePtrSet possible_val_set;
  const InternalNodePtr in = tnp->isInteriorNode();
  if (in && in->getOperator() == Rose::BinaryAnalysis::SymbolicExpr::OP_ITE) {

    extract_possible_values(tnp, possible_val_set);

    // If the possible value set only contains one element, then it is
    // the current treenode and can be ignored
    if (possible_val_set.size() > 1) {
      for (auto ite_elm : possible_val_set) {
        OINFO << "Exporting fact sameType("
              << addr_str( treenode_to_xsb(ite_elm))
              << ", " << addr_str(treenode_to_xsb(tnp)) << ")." << LEND;
        session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(ite_elm), treenode_to_xsb(tnp));
      }
    }
  }
}

// Assert facts about API calls. These facts concern the specific
// types of variables based on how they are passed to APIs.
void
TypeSolver::assert_api_facts(const CallDescriptor *cd) {

  // If this is a call to an API, then there must be an import descriptor
  const ImportDescriptor* id = cd->get_import_descriptor();
  if (id == NULL) return;

  if (!session_) {
    OERROR << "Cannot assert function call facts - invalid prolog session" << LEND;
    return;
  }

  // There is an import descriptor for this call, assert a fact for the name
  std::stringstream imp_ss;
  imp_ss << boost::to_upper_copy(id->get_dll_name()) + "!" + boost::to_upper_copy(id->get_name());

  // add a fact that names the function call
  session_->add_fact(APINAME_FACT, cd->get_address(), imp_ss.str());

     // Now assert facts for treenodes associated with this function call

  const ParamVector& cd_params = cd->get_parameters().get_params();

  for (const ParameterDefinition &param : cd_params) { // for each param on the call
    // add the type names for the

    // get the tree node for the parameter
    TreeNodePtr tnp = param.get_value()->get_expression();

    auto type = param.get_type();

    if (!type.empty()) {

      auto ref = typedb_.lookup(type);

      dir_enum dir = IN;
      // parameters that receive a (persistent) value are OUT or IN/OUT.
      if (param.direction == ParameterDefinition::DIRECTION_OUT ||
          param.direction == ParameterDefinition::DIRECTION_INOUT) {
        dir = OUT;
      }

      if (ref->get_pointerness() == types::Pointerness::Pointer) {
        session_->add_fact(TYPE_POINTER_FACT, ref->get_name(), POINTER);

        // if this is a pointer, then we should know something about
        // what it points to.

        auto pointer = ref->as<typedb::Pointer>();
        if (pointer) {
          auto pointee = pointer->get_contained();

          // emit a fact stating what type the reference type points to
          session_->add_fact(TYPE_REF_FACT,ref->get_name(), pointee->get_name());

          if (pointee->get_pointerness() == types::Pointerness::Pointer) {
            session_->add_fact(TYPE_POINTER_FACT, pointee->get_name(), POINTER);
          }
          else {
             session_->add_fact(TYPE_POINTER_FACT, pointee->get_name(), NOTPOINTER);
          }
        }
      }
      else if (ref->get_pointerness() == types::Pointerness::NotPointer) {
        session_->add_fact(TYPE_POINTER_FACT, ref->get_name(), NOTPOINTER);
      }

      if (ref->get_signedness() == types::Signedness::Signed) {
        session_->add_fact(TYPE_SIGNED_FACT, ref->get_name(), SIGNED);
      }
      else if (ref->get_signedness() == types::Signedness::Unsigned) {
        session_->add_fact(TYPE_SIGNED_FACT, ref->get_name(), UNSIGNED);
      }

      // name the parameter type by ordinal
      session_->add_fact(API_PARAM_TYPE_FACT, imp_ss.str(), param.num, ref->get_name(), dir);
    }
  }
}


void
TypeSolver::save_arch_facts(std::iostream &out_sstream) {

  if (!session_) return;

  auto query = session_->query(ARCH_FACT, any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// (bitwidth hash SIZE_VALUE)
void
TypeSolver::save_bitwidth_facts(std::iostream &out_sstream) {

  if (!session_) return;

  auto query = session_->query(BITWIDTH_FACT, any(), any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// This method dumps facts about
// (functionCall(INSN, ORD, TREENODE)
void
TypeSolver::save_function_call_facts(std::iostream &out_sstream) {

  if (!session_) return;

  // Dump function call argument facts
  auto callQuery = session_->query(FNCALL_TARGET_FACT, any(), any());
  for (; !callQuery->done(); callQuery->next()) {
    callQuery->debug_print(out_sstream);
  }

  // Dump function call facts
  auto argQuery = session_->query(FNCALL_ARG_FACT, any(), any(), any());
  for (; !argQuery->done(); argQuery->next()) {
    argQuery->debug_print(out_sstream);
  }

  auto known_pointer_query_ = session_->query(KNOWN_POINTER_FACT, any(), any());
  for (; !known_pointer_query_->done(); known_pointer_query_->next()) {
    known_pointer_query_->debug_print(out_sstream);
  }

  auto signedQuery = session_->query(KNOWN_SIGNED_FACT, any(), any());
  for (; !signedQuery->done(); signedQuery->next()) {
    signedQuery->debug_print(out_sstream);
  }

  auto knownTypeQuery = session_->query(KNOWN_TYPENAME_FACT, any(), any());
  for (; !knownTypeQuery->done(); knownTypeQuery->next()) {
    knownTypeQuery->debug_print(out_sstream);
  }

  auto refQuery = session_->query(SAME_TYPE_FACT, any(), any());
  for (; !refQuery->done(); refQuery->next()) {
    refQuery->debug_print(out_sstream);
  }

  auto pointerQuery = session_->query(POINTS_TO_FACT, any(), any());
  for (; !pointerQuery->done(); pointerQuery->next()) {
    pointerQuery->debug_print(out_sstream);
  }
}

/**
 * Dump facts related to API Calls
 *
 * apiCallName(ADDRESS, API).
 * apiParamType(API, ORDINAL, TYPENAME).
 * typePointerness(TYPE, pointer|notpointer).
 * typeSignedness(TYPE, signed|unsigned).
 */

void
TypeSolver::save_api_facts(std::iostream &out_sstream) {

  // Dump function call name facts
  auto nameQuery = session_->query(APINAME_FACT, any(), any());
  for (; !nameQuery->done(); nameQuery->next()) {
    nameQuery->debug_print(out_sstream);
  }

  // Dump API function parameter name facts
  auto pnameQuery = session_->query(API_PARAM_TYPE_FACT, any(), any(), any(), any());
  for (; !pnameQuery->done(); pnameQuery->next()) {
    pnameQuery->debug_print(out_sstream);
  }

  // Dump API function parameter pointer facts
  auto pointerQuery = session_->query(TYPE_POINTER_FACT, any(), any());
  for (; !pointerQuery->done(); pointerQuery->next()) {
    pointerQuery->debug_print(out_sstream);
  }

  // Dump API function parameter signedness facts
  auto signQuery = session_->query(TYPE_SIGNED_FACT, any(), any());
  for (; !signQuery->done(); signQuery->next()) {
    signQuery->debug_print(out_sstream);
  }

  // Dump API function parameter direction facts
  auto refQuery = session_->query(TYPE_REF_FACT, any(), any());
  for (; !refQuery->done(); refQuery->next()) {
    refQuery->debug_print(out_sstream);
  }
}

// (value term() VALUE)
void TypeSolver::save_value_facts(std::iostream &out_sstream) {

  if (!session_) return;

  auto query = session_->query(VAL_FACT, any(), any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// (memaddr term)
void TypeSolver::save_memory_facts(std::iostream &out_sstream) {

  if (!session_) return;

  auto query = session_->query(MEMADDR_FACT, any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// Add the memory address facts
void TypeSolver::assert_memory_facts(TreeNodePtr tnp) {
  if (!session_ || !tnp) return;

  session_->add_fact(MEMADDR_FACT, treenode_to_xsb(tnp));
}

void TypeSolver::set_output_file(std::string fn) {

  facts_filename_ = fn;
  save_to_file_ = true;
}

// When the typesolver is created, so is the prolog session
TypeSolver::TypeSolver(const DUAnalysis& du, const  FunctionDescriptor* f)
  : du_analysis_(du), current_function_(f),
    typerules_("types/typerules"), save_to_file_(false) {

  try {

    const ProgOptVarMap& vm = global_descriptor_set->get_arguments();

    typedb_ = typedb::DB::create_standard(vm);

    // Get the session
    session_ = std::make_shared<Session>(vm, typerules_);
  }
  catch (const Error& error) {
    OFATAL << "Unable to start Prolog session." << LEND;
    OFATAL << error.what() << LEND;
    session_ = NULL;
  }

  assert_arch_fact();

}

// The only thing to do here is invalidate the session
TypeSolver::~TypeSolver() {
  tree_nodes_.clear();
}

// recursively assert facts
void
TypeSolver::recursively_assert_facts(TreeNodePtr tnp) {

  uint64_t tnaddr = reinterpret_cast<uint64_t>(&*tnp);
  MDEBUG << "Generating facts for (" << addr_str(tnaddr) << ") " << *tnp << LEND;

  // Has this tree node been processed? Tree node hashes are based
  // on value not pointer so there can be different pointers and
  // missing type descriptors.

  if (tree_nodes_.find(tnaddr) != tree_nodes_.end()) {
    MDEBUG << "Tree node already processed" << LEND;
    return;
  }

  // add/replace tree node in the master list
  tree_nodes_.emplace(tnaddr, tnp);

  // Assign a default type descriptor
  TypeDescriptorPtr td_ptr = fetch_type_descriptor(tnp);

  // set the size here while we have access to the treenode
  td_ptr->bit_width(tnp->nBits());

  // assert initial facts for this type descriptor (size and value)
  assert_bitwidth_fact(tnp);

  if (tnp->isNumber()) {
    if (tnp->nBits() <= 64) { // <= this is a hack to prevent a core dump in ROSE
      MDEBUG << "This param is a number and will receive a value fact" << LEND;
      assert_value_facts(tnp);
    }
  }

  boost::any ud = td_ptr;
  tnp->userData(ud); // The tree node now has a TypeDescriptor

  MDEBUG << "Added type descriptor for " << addr_str(tnaddr) << LEND;

  // Check to see if the treen node is an operation. If it is assert an operation fact
  if (!tnp->isLeafNode()) {

    // The tree node is an interior node, recurse through its
    // children to assert necessary facts.

    const InternalNodePtr in = tnp->isInteriorNode();
    if (in) {

      Rose::BinaryAnalysis::SymbolicExpr::Operator op = in->getOperator();
      op_context_.assert_operation_fact(op, in, session_);

      const TreeNodePtrVector& kids = in->children();

      if (op == Rose::BinaryAnalysis::SymbolicExpr::OP_ITE) {

        session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(kids[1]), treenode_to_xsb(tnp));
        MDEBUG << "Exporting fact sameType(" << addr_str( treenode_to_xsb(kids[1])) << ", " << addr_str(treenode_to_xsb(tnp)) << ")." << LEND;

        session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(kids[2]), treenode_to_xsb(tnp));
        MDEBUG << "Exporting fact sameType(" << addr_str( treenode_to_xsb(kids[2])) << ", " << addr_str(treenode_to_xsb(tnp)) << ")." << LEND;
      }

      for (TreeNodePtr child : kids) {
        recursively_assert_facts(child);
      }
    }
  }
}

bool
TypeSolver::generate_type_information(const std::map<TreeNode*,TreeNodePtr> &treenodes,
                                      const std::map<TreeNode*,TreeNodePtr> &memory_accesses)
{
  if (!session_) {
    OERROR << "Error cannot start prolog" << LEND;
    return false;
  }

  MDEBUG << "Generating type facts" << LEND;

  for (auto& tnpair : treenodes) {
    recursively_assert_facts(tnpair.second);
  }

  MDEBUG << "Analyzing " << memory_accesses.size() << " memory accesses" << LEND;

  // assert the memory facts

  for (auto mempair : memory_accesses) {

    TreeNodePtr mem_tnp = mempair.second;
    if (mem_tnp) {
      assert_memory_facts(mem_tnp);
      recursively_assert_facts(mem_tnp);
    }
  }

  // examine the calls in this function and assert facts
  const CallDescriptorSet& outCalls = current_function_->get_outgoing_calls();
  for (const CallDescriptor *cd : outCalls) {

    if (cd) {
      // for each found call descriptor assert the relevant facts
      assert_function_call_facts(cd);
      assert_api_facts(cd);
    }
  }

  // assert the type descriptors based on collected facts
  generate_type_descriptors();

  // if specified, dump the facts to a file for further processing
  if (save_to_file_) {
    save_facts();
  }

  return true;
}

bool
TypeSolver::save_facts_to_file(std::string &facts) {

  MDEBUG << "Dumping facts to " << facts_filename_ << LEND;

  static bool first_run = true;

  // clear the file on first run
  if (first_run) {
    // clear the file on first run
    std::ofstream f(facts_filename_,std::ofstream::out | std::ofstream::trunc);
  }

  // append is needed because the file will be repeatedly opened and closed
  std::ofstream facts_file(facts_filename_,std::ofstream::out | std::ofstream::app);

  if (!facts_file.is_open()) {
    OERROR << "Unable to open prolog facts file '" << facts_filename_ << "'." << LEND;
    return false;
  }

  facts_file << "% Asserted type facts for function: "
             << addr_str(current_function_->get_address())
             << "\n" << facts;

  facts_file.close();

  if (first_run) first_run = false;

  return true;
}

/**
 * Update TypeDescriptor type name information
 */
void TypeSolver::update_typename() {

  if (!session_) {
    OERROR << "Invalid prolog session!" << LEND;
    return;
  }

  uint64_t tnp_term;
  std::string name;
  auto query = session_->query(TYPE_NAME_QUERY, var(tnp_term), var(name));
  for (; !query->done(); query->next()) {

    TreeNode* tn = xsb_to_treenode(tnp_term);
    TreeNodePtr tnp = tn->sharedFromThis();

    uint64_t addr = reinterpret_cast<uint64_t>(&*tnp);
    MDEBUG << "setting " << *tnp << " ID: "<< addr_str(addr) << " name to " << name << LEND;

    TypeDescriptorPtr typeDesc = fetch_type_descriptor(tnp);
    typeDesc->set_name(name); // This type has a known name
  }
}

/**
 * Update TypeDescriptor pointerness information
 */
void TypeSolver::update_pointerness() {

  MDEBUG << "Updating pointerness" << LEND;

  if (!session_) {
    OERROR << "Invalid prolog session!" << LEND;
    return;
  }

  uint64_t is_ptr_term;
  auto is_ptr_query = session_->query(FINAL_POINTER_QUERY, var(is_ptr_term), IS);
  for (; !is_ptr_query->done(); is_ptr_query->next()) {

    TreeNode* tn = xsb_to_treenode(is_ptr_term);
    TreeNodePtr tnp = tn->sharedFromThis();

    uint64_t addr = reinterpret_cast<uint64_t>(&*tnp);
    MDEBUG << "setting " << addr_str(addr) <<  " ( " << *tnp << ") to IS pointer" << LEND;

    TypeDescriptorPtr type_desc = fetch_type_descriptor(tnp);
    type_desc->is_pointer(); // indicate this is a pointer
  }

  uint64_t not_pointer_term;
  auto not_ptr_query = session_->query(FINAL_POINTER_QUERY, var(not_pointer_term), ISNOT);
  for (; !not_ptr_query->done(); not_ptr_query->next()) {

    TreeNode* tn = xsb_to_treenode(not_pointer_term);
    TreeNodePtr tnp = tn->sharedFromThis();

    uint64_t addr = reinterpret_cast<uint64_t>(&*tnp);
    MDEBUG << "setting " << addr_str(addr) <<  " ( " << *tnp << ") to ISNOT pointer" << LEND;

    TypeDescriptorPtr type_desc = fetch_type_descriptor(tnp);
    type_desc->not_pointer(); // indicate this is not a pointer
  }

  uint64_t bottom_pointer_term;
  auto bottom_ptr_query = session_->query(FINAL_POINTER_QUERY, var(bottom_pointer_term), BOTTOM);
  for (; !bottom_ptr_query->done(); bottom_ptr_query->next()) {

    TreeNode* tn = xsb_to_treenode(bottom_pointer_term);
    TreeNodePtr tnp = tn->sharedFromThis();

    uint64_t addr = reinterpret_cast<uint64_t>(&*tnp);
    MDEBUG << "setting " << addr_str(addr) << " to BOTTOM pointer" << LEND;

    TypeDescriptorPtr type_desc = fetch_type_descriptor(tnp);
    type_desc->bottom_pointer();  // indicate conflicting information
  }
}

/**
 * Update the TypeDescriptor signedness  information
 */
void TypeSolver::update_signedness() {

  if (!session_) {
    OERROR << "Invalid prolog session!" << LEND;
    return;
  }

  uint64_t is_signed_term;
  auto is_signed_query = session_->query(FINAL_SIGNED_QUERY, var(is_signed_term), IS);
  for (; !is_signed_query->done(); is_signed_query->next()) {

    TreeNode* tn = xsb_to_treenode(is_signed_term);
    TreeNodePtr tnp = tn->sharedFromThis();

    uint64_t addr = reinterpret_cast<uint64_t>(&*tnp);
    MDEBUG << "setting " << addr_str(addr) << " to IS signed" << LEND;

    TypeDescriptorPtr typeDesc = fetch_type_descriptor(tnp);

    typeDesc->is_signed(); // indicate this is signed
  }

  uint64_t not_signed_term;
  auto not_signed_query = session_->query(FINAL_SIGNED_QUERY, var(not_signed_term), ISNOT);
  for (; !not_signed_query->done(); not_signed_query->next()) {

    TreeNode* tn = xsb_to_treenode(not_signed_term);
    TreeNodePtr tnp = tn->sharedFromThis();

    uint64_t addr = reinterpret_cast<uint64_t>(&*tnp);
    MDEBUG << "setting " << addr_str(addr) << " to ISNOT signed" << LEND;

    TypeDescriptorPtr type_desc = fetch_type_descriptor(tnp);
    type_desc->not_signed(); // indicate this is not signed
  }

  uint64_t bottom_signed_term;
  auto bottom_signed_query = session_->query(FINAL_SIGNED_QUERY, var(bottom_signed_term), BOTTOM);
  for (; !bottom_signed_query->done(); bottom_signed_query->next()) {

    TreeNode* tn = xsb_to_treenode(bottom_signed_term);
    TreeNodePtr tnp = tn->sharedFromThis();

    uint64_t addr = reinterpret_cast<uint64_t>(&*tnp);
    MDEBUG << "setting " << addr_str(addr) << " to BOTTOM signed" << LEND;

    TypeDescriptorPtr type_desc = fetch_type_descriptor(tnp);
    type_desc->bottom_signed(); // indicate this is signed
  }
}

void
TypeSolver::save_facts_private()
{
  // This method should take a filename to write the facts to!
  std::cout << "% Prolog facts autoasserted by TypeAnalysis." << std::endl;

  size_t exported = 0;

  exported += session_->print_predicate(std::cout, MEMADDR_FACT, 1);
  exported += session_->print_predicate(std::cout, BITWIDTH_FACT, 2);
  exported += session_->print_predicate(std::cout, VAL_FACT, 2);
  exported += session_->print_predicate(std::cout, FNCALL_ARG_FACT, 3);
  exported += session_->print_predicate(std::cout, FNCALL_TARGET_FACT, 3);
  exported += session_->print_predicate(std::cout, APINAME_FACT, 2);
  exported += session_->print_predicate(std::cout, API_PARAM_TYPE_FACT, 4);
  exported += session_->print_predicate(std::cout, TYPE_POINTER_FACT, 2);
  exported += session_->print_predicate(std::cout, TYPE_SIGNED_FACT, 2);
  exported += session_->print_predicate(std::cout, KNOWN_POINTER_FACT, 3);
  exported += session_->print_predicate(std::cout, KNOWN_SIGNED_FACT, 3);
  exported += session_->print_predicate(std::cout, KNOWN_TYPENAME_FACT, 2);
  exported += session_->print_predicate(std::cout, TYPE_REF_FACT, 2);
  exported += session_->print_predicate(std::cout, SAME_TYPE_FACT, 2);
  exported += session_->print_predicate(std::cout, POINTS_TO_FACT, 2);

  std::cout << "% type fact exporting complete." << std::endl;

  MINFO << "Exported " << exported << " Prolog facts." << LEND;
}

/**
 * This function will update the default type descriptors, currently
 * with pointer and sign information
 */
void TypeSolver::generate_type_descriptors() {

  MINFO << "Updating type descriptors for function "
        << addr_str(current_function_->get_address()) << LEND;

  update_pointerness();

  update_signedness();

  update_typename();
}

/**
 * Write facts to a stream of some sort.
 */
bool TypeSolver::save_facts() {

  bool result = true;

  std::stringstream out_sstream;

  op_context_.save_operation_facts(session_, out_sstream);

  save_arch_facts(out_sstream);
  save_memory_facts(out_sstream);
  save_bitwidth_facts(out_sstream);
  save_value_facts(out_sstream);
  save_function_call_facts(out_sstream);
  save_api_facts(out_sstream);

  std::string facts = out_sstream.str();
  if (facts.empty() == false) {
    result = save_facts_to_file(facts);
  }
  return result;
}

OperationContext::~OperationContext() {

  for (auto& p : strategies_) {
    OperationStrategy *s = p.second;
    if (s) delete s;
    s = NULL;
  }
  strategies_.clear();
}

OperationContext::OperationContext()
{

  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_ADD, new AddStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_AND, new AndStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_ASR, new AsrStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_BV_AND, new BvAndStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_BV_OR, new BvOrStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_BV_XOR, new BvXorStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_CONCAT, new ConcatStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_EQ, new EqStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_EXTRACT, new ExtractStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_INVERT, new InvertStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_ITE, new IteStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_LSSB, new LssbStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_MSSB, new MssbStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_NE, new NeStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_NEGATE, new NegateStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_NOOP, new NoopStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_OR, new OrStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_READ, new ReadStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_ROL, new RolStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_ROR, new RorStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SDIV, new SdivStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SET, new SetStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SEXTEND, new SextendStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SGE, new SgeStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SGT, new SgtStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SHL0, new Shl0Strategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SHL1, new Shl1Strategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SHR0, new Shr0Strategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SHR1, new Shr1Strategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SLE, new SleStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SLT, new SltStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SMOD, new SmodStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_SMUL, new SmulStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_UDIV, new UdivStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_UEXTEND, new UextendStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_UGE, new UgeStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_UGT, new UgtStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_ULE, new UleStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_ULT, new UltStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_UMOD, new UmodStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_UMUL, new UmulStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_WRITE, new WriteStrategy());
  strategies_.emplace(Rose::BinaryAnalysis::SymbolicExpr::Operator::OP_ZEROP, new ZeropStrategy());
}

// Analyze the operations by selecting and executing the strategy based on RISC
// operator
void OperationContext::assert_operation_fact(Rose::BinaryAnalysis::SymbolicExpr::Operator op,
                                             InternalNodePtr tnp,
                                             std::shared_ptr<prolog::Session> session) {

  // determins if we have a strategy for this operation
  if (strategies_.find(op) == strategies_.end()) {
    MDEBUG << "Could not find strategy" << LEND;
    return;
  }

  MDEBUG << "Generating strategy for " << strategies_[op]->get_op_name() << LEND;

  // If desired strategy is found, then execute it to assert facts
  strategies_[op]->assert_facts(tnp, session);
}

// Flush asserted facts to a string stream. Each strategy must know how to
// dump itself
void OperationContext::save_operation_facts(std::shared_ptr<Session> session, std::iostream &out_sstream) {

  if (!session) {
    MDEBUG << "Prolog session invalid!" << LEND;
    return;
  }

  for (auto s : strategies_) {
    s.second->save_facts(session, out_sstream);
  }
}

// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
// Concrete strategies per operation
//
// This is where the facts for each operation should be asserted. for each
// operation it is expected that we will assert a set of facts that are
// relevant to type information
// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-

// OP_SEXTEND: Signed extension at msb. Extend B to A bits by replicating B's most significant bit.
void SextendStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {

  MDEBUG << "Generating facts for OP_SEXTEND tree node: " << *in << LEND;

  if (!session || !in) return;

  TreeNodePtrVector kids;
  kids = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(B), treenode_to_xsb(A));
}

void SextendStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream) {

  if (!session) return;

  XsbTerm in, A, B;
  auto query = session->query(op_name_,  var(in), var(A), var(B));

  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_UEXTEND: Unsigned extention at msb. Extend B to A bits by introducing zeros at the msb of B.
void UextendStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {

  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_UEXTEND tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(B), treenode_to_xsb(A));
}

void UextendStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term, A, B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_ADD: Addition. One or more operands, all the same width.
//
//
void AddStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {

  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_ADD strategy, tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();

  auto ops = list();
  for(auto k : kids) {
    ops.push_back(treenode_to_xsb(k));
  }
  session->add_fact(op_name_, treenode_to_xsb(in), ops);
}

void AddStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream) {

  if (!session) return;

  XsbTerm term;
  auto query = session->query(op_name_, var(term), any());
  query->debug_print(out_sstream);
}

// ------------------------------------------------------------------------------

// OP_SMUL: Signed multiplication. Two operands A*B. Result width is width(A)+width(B).
void SmulStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {

  if (!session || !in) return;

  MDEBUG << "Generating facts OP_SMUL tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void SmulStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream) {

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_UMUL: Unsigned multiplication. Two operands, A*B. Result width is width(A)+width(B).
void UmulStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_UMUL tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();

  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void UmulStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream) {

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_BV_AND: Bitwise AND. There may be more than one operands
void BvAndStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {

  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_BV_AND tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();

  auto ops = list();
  for(auto k : kids) {
    ops.push_back(k->hash());
  }
  session->add_fact(op_name_, treenode_to_xsb(in), ops);
}

void BvAndStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term;
  auto query = session->query(op_name_, var(term), any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_AND: Boolean AND. Operands are all Boolean (1-bit) values. See also OP_BV_AND.
// JSG doesn't think this tree node will occur at the instruction level (save for flags)
void AndStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {

  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_AND tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();

  auto ops = list();
  for(auto k : kids) {
    ops.push_back(k->hash());
  }
  session->add_fact(op_name_, treenode_to_xsb(in), ops);
}

void AndStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term;
  auto query = session->query(op_name_, var(term), any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_ASR: Arithmetic shift right. Operand B shifted by A bits; 0 <= A < width(B). A is unsigned.
void AsrStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_ASR tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();

  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(B), treenode_to_xsb(A));
}

void AsrStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, term, var(B), var(A));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_CONCAT: Concatenation. Operand A becomes high-order bits. Any number of operands.
void ConcatStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_CONCAT tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();

  auto ops = list();
  for(auto k : kids) {
    ops.push_back(treenode_to_xsb(k));
  }
  session->add_fact(op_name_, treenode_to_xsb(in), ops);

}

void ConcatStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term;
  auto query = session->query(op_name_, var(term), any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_EQ: Equality. Two operands, both the same width.
void EqStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_EQ tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();

  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void EqStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_EXTRACT: Extract subsequence of bits. Extract bits [A..B) of C. 0 <= A < B <= width(C).
void ExtractStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_EXTRACT tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();

  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);
  TreeNodePtr C = kids.at(2);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B), treenode_to_xsb(C));
}

void ExtractStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream) {

  if (!session) return;

  XsbTerm term, A, B, C;
  auto query = session->query(op_name_, var(term), var(A), var(B), var(C));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_INVERT  Boolean inversion. One operand.
void InvertStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_INVERT tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();

  TreeNodePtr A = kids.at(0);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A));
}

void InvertStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A;
  auto query = session->query(op_name_, var(term), var(A));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_ITE: If-then-else. A must be one bit. Returns B if A is set, C otherwise.
void IteStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_ITE tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();

  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);
  TreeNodePtr C = kids.at(2);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B), treenode_to_xsb(C));
}

void IteStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;
  XsbTerm term,A,B,C;
  auto query = session->query(op_name_, var(term), var(A), var(B), var(C));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_LSSB:  Least significant set bit or zero. One operand.
void LssbStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_INVERT tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();

  TreeNodePtr A = kids.at(0);
  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A));
}

void LssbStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A;
  auto query = session->query(op_name_, var(term), var(A));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_MSSB: Most significant set bit or zero. One operand.
void MssbStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_MSSB tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();

  TreeNodePtr A = kids.at(0);
  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A));
}

void MssbStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A;
  auto query = session->query(op_name_, var(term), var(A));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_NE: Inequality. Two operands, both the same width.
void NeStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_NE tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();

  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A) ,treenode_to_xsb(B));
}

void NeStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_NEGATE: Arithmetic negation. One operand.
void NegateStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_NEGATE tree node: " << *in << LEND;
  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr t = kids.at(0);
  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(t));
}

void NegateStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A;
  auto query = session->query(op_name_, var(term), var(A));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_NOOP: No operation. Used only by the default constructor.
void NoopStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_NOOP tree node: " << *in << LEND;

  // JSG thinks that there is nothing to do here?
}

void NoopStrategy::save_facts(std::shared_ptr<prolog::Session> session, UNUSED std::iostream &out_sstream){

  if (!session) return;
  // there is nothing to do here
}

// ------------------------------------------------------------------------------

// OP_BV_XOR: Bitwise XOR. One or more operands, all the same width.
void BvXorStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_BV_XOR tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();

  auto ops = list();
  for(auto k : kids) {
    ops.push_back(treenode_to_xsb(k));
  }
  session->add_fact(op_name_, treenode_to_xsb(in), ops);
}

void BvXorStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term;
  auto query = session->query(op_name_, var(term), any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// OP_BV_OR: Bitwise OR. One or more operands, all the same width.
void BvOrStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_BV_OR tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();

  auto ops = list();
  for(auto k : kids) {
    ops.push_back(treenode_to_xsb(k));
  }
  session->add_fact(op_name_, treenode_to_xsb(in), ops);
}

void BvOrStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term;
  auto query = session->query(op_name_, var(term), any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_BV_OR: Bitwise OR. One or more operands, all the same width.
// OP_OR: Boolean OR. Operands are all Boolean (1-bit) values. See also OP_BV_OR.
void OrStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_OR tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();

  auto ops = list();
  for(auto k : kids) {
    ops.push_back(treenode_to_xsb(k));
  }
  session->add_fact(op_name_, treenode_to_xsb(in), ops);
}

void OrStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term;
  auto query = session->query(op_name_, var(term), any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_READ: Read a value from memory.  Arguments are the memory state and the address expression.
void ReadStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_READ tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr address_tnp = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(address_tnp));
}

void ReadStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A;
  auto query = session->query(op_name_, var(term), var(A));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_ROL: Rotate left. Rotate bits of B left by A bits.  0 <= A < width(B). A is unsigned.
void RolStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_ROL tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();

  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(B), treenode_to_xsb(A));
}

void RolStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_ROR: Rotate right. Rotate bits of B right by A bits. 0 <= B < width(B). A is unsigned.
void RorStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_ROR tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(B), treenode_to_xsb(A));
}

void RorStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_SDIV: Signed division. Two operands, A/B. Result width is width(A).
void SdivStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SDIV tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void SdivStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_UDIV:  Signed division. Two operands, A/B. Result width is width(A).
void UdivStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_UDIV tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void UdivStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_SET: Set of expressions. Any number of operands in any order.
void SetStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SET tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();

  auto ops = list();
  for(auto k : kids) {
    ops.push_back(treenode_to_xsb(k));
  }
  session->add_fact(op_name_, treenode_to_xsb(in), ops);
}

void SetStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term;
  auto query = session->query(op_name_, var(term), any());
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_SGE: Signed greater-than-or-equal. Two operands of equal width. Result is Boolean.
void SgeStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SGE tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();

  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void SgeStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_SGT: Signed greater-than. Two operands of equal width. Result is Boolean.
void SgtStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SGT tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void SgtStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_SHL0: Shift left, introducing zeros at lsb. Bits of B are shifted by A, where 0 <=A < width(B).
void Shl0Strategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SHL0 tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(B), treenode_to_xsb(A));
}

void Shl0Strategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(B), var(A));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// OP_SHL1: Shift left, introducing ones at lsb. Bits of B are shifted by A, where 0 <=A < width(B).
void Shl1Strategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SHL1 tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(B), treenode_to_xsb(A));
}

void Shl1Strategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, term, B, A);
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}
// ------------------------------------------------------------------------------

// OP_SHR1: Shift right, introducing ones at msb. Bits of B are shifted by A, where 0 <=A <width(B).
void Shr1Strategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SHR1 tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(B), treenode_to_xsb(A));
}

void Shr1Strategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, term, B, A);
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// OP_SHR0: Shift right, introducing zeros at msb. Bits of B are shifted by A, where 0 <=A <width(B)./
void Shr0Strategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SHR0 tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(B), treenode_to_xsb(A));
}

void Shr0Strategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(B), var(A));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_SLE:  Signed less-than-or-equal. Two operands of equal width. Result is Boolean.
void SleStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SLE tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void SleStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_SLT: Signed less-than. Two operands of equal width. Result is Boolean.
void SltStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SLT tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void SltStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_SMOD: Signed modulus. Two operands, A%B. Result width is width(B).
void SmodStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_SMOD tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void SmodStrategy::save_facts(std::shared_ptr<prolog::Session> session, UNUSED std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_UMOD: Unsigned modulus. Two operands, A%B. Result width is width(B).
void UmodStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_UMOD tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void UmodStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_UGE:Unsigned greater-than-or-equal. Two operands of equal width. Boolean result.
void UgeStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {

  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_UGE tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void UgeStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, term, A, B);
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_UGT: Unsigned greater-than. Two operands of equal width. Result is Boolean.
void UgtStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_UGT tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void UgtStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_ULE: Unsigned less-than-or-equal. Two operands of equal width. Result is Boolean.
void UleStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_ULE tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();
  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void UleStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_ULT: Unsigned less-than. Two operands of equal width. Result is Boolean (1-bit vector).
void UltStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_ULT tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids  = in->children();

  TreeNodePtr A = kids.at(0);
  TreeNodePtr B = kids.at(1);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
}

void UltStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A,B;
  auto query = session->query(op_name_, var(term), var(A), var(B));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

// OP_WRITE: Write (update) memory with a new value. Arguments are memory, address and value.
void WriteStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_WRITE tree node: " << *in << LEND;

  // JSG is not sure what to do here ...
}

void WriteStrategy::save_facts(std::shared_ptr<prolog::Session> session, UNUSED std::iostream &out_sstream){

  if (!session) return;
}

// ------------------------------------------------------------------------------

// OP_ZEROP: Equal to zero. One operand. Result is a single bit, set iff A is equal to zero.
void ZeropStrategy::assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session) {
  if (!session || !in) return;

  MDEBUG << "Generating facts for OP_ZEROP tree node: " << *in << LEND;

  TreeNodePtrVector kids;
  kids = in->children();
  TreeNodePtr A = kids.at(0);

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A));
}

void ZeropStrategy::save_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream){

  if (!session) return;

  XsbTerm term,A;
  auto query = session->query(op_name_, var(term), var(A));
  for (; !query->done(); query->next()) {
    query->debug_print(out_sstream);
  }
}

// ------------------------------------------------------------------------------

} // namespace pharos
