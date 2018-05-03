
// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.
// Author: Jeff Gennari

#include <boost/range/adaptor/map.hpp>

#include "types.hpp"
#include "xsb.hpp"
#include "pdg.hpp"
#include "defuse.hpp"
#include "stkvar.hpp"
#include "demangle.hpp"

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
const std::string FNCALL_RETVAL_FACT = "functionCallRetval";
const std::string APINAME_FACT = "apiCallName";               // name of an API function
const std::string API_PARAM_TYPE_FACT = "apiParamType";       // name of parameter type
const std::string API_RET_TYPE_FACT = "apiReturnType";        // return type of an API
const std::string TYPE_POINTER_FACT = "typePointerness";      // is parameter a pointer type
const std::string TYPE_SIGNED_FACT = "typeSignedness";        // is parameter signed
const std::string KNOWN_POINTER_FACT = "knownPointer";        // is parameter a pointer type
const std::string KNOWN_SIGNED_FACT = "knownSigned";          // is parameter signed
const std::string KNOWN_TYPENAME_FACT = "knownTypename";      // the typename is known
const std::string KNOWN_OBJECT_FACT = "knownObject";
const std::string TYPE_REF_FACT = "typeRef";
const std::string SAME_TYPE_FACT = "sameType";
const std::string POINTS_TO_FACT = "pointsTo";
const std::string ARCH_FACT = "archBits";

// Prolog query strings
const std::string FINAL_POINTER_QUERY = "finalPointer";
const std::string FINAL_SIGNED_QUERY = "finalSigned";
const std::string FINAL_TYPENAME_QUERY = "finalTypeName";
const std::string FINAL_OBJECT_QUERY = "finalObject";

const std::string THISCALL_CONVENTION = "__thiscall";

using namespace prolog;

typedef impl::xsb::xsb_term XsbTerm;

bool
has_type_descriptor(TreeNodePtr tnp) {

   if (tnp == NULL) {
    OWARN << "Cannot fetch/create type descriptor because treenode is NULL" << LEND;
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

// An implementation of can-be-equals that ignores zero values
bool
smart_can_be_equal(SymbolicValuePtr sv1, SymbolicValuePtr sv2) {

  if (!sv1 || !sv2) return false;

  if (!sv1->contains_ite() && !sv2->contains_ite()) {
    return sv1->can_be_equal(sv2);
  }
  // one or more values contains an ite,

  std::set<TreeNodePtr> sv1_treenodes;
  std::set<TreeNodePtr> sv2_treenodes;

  if (sv1->contains_ite()) {
    for (const TreeNodePtr& tn : sv1->get_possible_values()) {
      if (tn->isNumber() && tn->isLeafNode()->bits().isAllClear()) {
        continue;
      }
      sv1_treenodes.insert(tn);
    }
  }
  else {
    sv1_treenodes.insert(sv1->get_expression());
  }
  if (sv2->contains_ite()) {
    for (const TreeNodePtr& tn : sv2->get_possible_values()) {
      if (tn->isNumber() && tn->isLeafNode()->bits().isAllClear()) {
        continue;
      }
      sv2_treenodes.insert(tn);
    }
  }
  else {
    sv2_treenodes.insert(sv2->get_expression());
  }

  std::set<TreeNodePtr> intersection;

  auto TreeNodeCmp = [](TreeNodePtr lhs, TreeNodePtr rhs) { return lhs->isEquivalentTo(rhs); };
  std::set_intersection(sv1_treenodes.begin(), sv1_treenodes.end(),
                        sv1_treenodes.begin(), sv2_treenodes.end(),
                        std::inserter(intersection, intersection.begin()),
                        TreeNodeCmp);

  // If there is an intersection then there was a match
  return (intersection.size() > 0);

}

// Fetch the type descriptor off of a SymbolicValue or create a default one
// if it cannot be found
TypeDescriptorPtr
fetch_type_descriptor(SymbolicValuePtr val) {
  if (!val) return NULL;
  return fetch_type_descriptor(val->get_expression());
}

// Fetch the type descriptor off of a treenode or create a default one
// if it cannot be found
TypeDescriptorPtr
fetch_type_descriptor(TreeNodePtr tnp) {

  if (tnp == NULL) return NULL;

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

void
to_facts(TreeNodePtr tn, std::shared_ptr<prolog::Session> session) {

  TypeDescriptorPtr td = fetch_type_descriptor(tn);

  // Emit known typename facts
  session->add_fact(KNOWN_TYPENAME_FACT, treenode_to_xsb(tn), td->get_type_name());

   // Emit known bitwidth
  session->add_fact(BITWIDTH_FACT, treenode_to_xsb(tn), td->bit_width());

  // Emit known pointerness facts
  if (td->Pointerness() == types::Pointerness::Pointer) {
    session->add_fact(KNOWN_POINTER_FACT, treenode_to_xsb(tn), IS);
  }
  else if (td->Pointerness() == types::Pointerness::NotPointer) {
    session->add_fact(KNOWN_POINTER_FACT, treenode_to_xsb(tn), ISNOT);
  }
  else if (td->Pointerness() == types::Pointerness::Bottom) {
    session->add_fact(KNOWN_POINTER_FACT, treenode_to_xsb(tn), BOTTOM);
  }
  else if (td->Pointerness() == types::Pointerness::Top) {
    session->add_fact(KNOWN_POINTER_FACT, treenode_to_xsb(tn), TOP);
  }

  // Emit known signedness facts
  if (td->Signedness() == types::Signedness::Signed) {
    session->add_fact(KNOWN_SIGNED_FACT, treenode_to_xsb(tn), IS);
  }
  else if (td->Signedness() == types::Signedness::Unsigned) {
    session->add_fact(KNOWN_SIGNED_FACT, treenode_to_xsb(tn), ISNOT);
  }
  else if (td->Signedness() == types::Signedness::Bottom) {
    session->add_fact(KNOWN_SIGNED_FACT, treenode_to_xsb(tn), BOTTOM);
  }
  else if (td->Signedness() == types::Signedness::Top) {
    session->add_fact(KNOWN_SIGNED_FACT, treenode_to_xsb(tn), TOP);
  }

  // Emit known object facts
  if (td->Objectness() == types::Objectness::Object) {
    session->add_fact(KNOWN_OBJECT_FACT, treenode_to_xsb(tn), IS);
  }
  else if (td->Objectness() == types::Objectness::NotObject) {
    session->add_fact(KNOWN_OBJECT_FACT, treenode_to_xsb(tn), ISNOT);
  }
  else if (td->Objectness() == types::Objectness::Bottom) {
    session->add_fact(KNOWN_OBJECT_FACT,treenode_to_xsb(tn), BOTTOM);
  }
  else if (td->Objectness() == types::Objectness::Top) {
    session->add_fact(KNOWN_OBJECT_FACT, treenode_to_xsb(tn), TOP);
  }
}


// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
// TypeDescriptor methods
// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-

// The default constructor simply sets everything to the top of the lattices
// to indicate that nothing is yet known.
TypeDescriptor::TypeDescriptor()
{
  pointerness_ = types::Pointerness::Top;
  signedness_ = types::Signedness::Top;
  objectness_ = types::Objectness::Top;
  type_name_ = types::TypenameTop;
  bit_width_ = types::BitwidthTop;
  is_aggregate_ = false;
}

// Copy constructor for a type descriptor
TypeDescriptor::TypeDescriptor(const TypeDescriptor& other) {
  type_name_ = other.type_name_;
  pointerness_ = other.pointerness_;
  signedness_ = other.signedness_;
  objectness_ = other.objectness_;
  bit_width_ = other.bit_width_;
  is_aggregate_ = other.is_aggregate_;

  candidate_typenames_ = other.candidate_typenames_;

  if (pointerness_ == types::Pointerness::Pointer) {
    reference_types_ = other.reference_types_;
  }

  if (is_aggregate_) {
    components_ = other.components_;
  }
}

bool
TypeDescriptor::type_unknown() const {
  return (pointerness_ == types::Pointerness::Top &&
          signedness_ == types::Signedness::Top &&
          objectness_ == types::Objectness::Top &&
          type_name_ == types::TypenameTop);
}

// assignment operator
TypeDescriptor&
TypeDescriptor::operator=(const TypeDescriptor &other) {
  type_name_ = other.type_name_;
  pointerness_ = other.pointerness_;
  signedness_ = other.signedness_;
  objectness_ = other.objectness_;
  bit_width_ = other.bit_width_;
  is_aggregate_ = other.is_aggregate_;
  candidate_typenames_ = other.candidate_typenames_;

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
    ss << "pointerness=<unknown>";
  }

  if (signedness_ == types::Signedness::Signed) {
    ss << " signedness=signed";
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
    ss << " signedness=<unknown>";
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

  if (objectness_ == types::Objectness::Object) {
    ss << " objectness=object";
  }
  else if (objectness_ == types::Objectness::NotObject) {
    ss << " objectness=not object";
  }
  else if (objectness_ == types::Objectness::Top) {
    ss << " objectness=top";
  }
  else if (objectness_ == types::Objectness::Bottom) {
    ss << " objectness=bottom";
  }
  else {
    ss << " objectness=<unknown>";
  }

  if (type_name_ == types::TypenameTop) {
    ss << " typename=<unknown>";
  }
  else {
    ss << " typename=" << type_name_;
  }

  return ss.str();
}

// Width properties
void
TypeDescriptor::bit_width(size_t bw) { bit_width_ = bw; }

size_t
TypeDescriptor::bit_width() const { return bit_width_; }

// Pointerness properties
void
TypeDescriptor::is_pointer() { pointerness_ = types::Pointerness::Pointer; }

void
TypeDescriptor::not_pointer() { pointerness_ = types::Pointerness::NotPointer; }

void
TypeDescriptor::bottom_pointer() { pointerness_ = types::Pointerness::Bottom; }

void
TypeDescriptor::top_pointer() { pointerness_ = types::Pointerness::Top; }

types::Pointerness
TypeDescriptor::Pointerness() const { return pointerness_; }

// Signedness properties
void
TypeDescriptor::is_signed() { signedness_ = types::Signedness::Signed; }

void
TypeDescriptor::not_signed() { signedness_ = types::Signedness::Unsigned; }

void
TypeDescriptor::bottom_signed() { signedness_ = types::Signedness::Bottom; }

void
TypeDescriptor::top_signed() { signedness_ = types::Signedness::Top; }

types::Signedness
TypeDescriptor::Signedness() const { return signedness_; }

// Objectness properties
void
TypeDescriptor::is_object() { objectness_ = types::Objectness::Object; }

void
TypeDescriptor::not_object() { objectness_ = types::Objectness::NotObject; }

void
TypeDescriptor::bottom_object() { objectness_ = types::Objectness::Bottom; }

void
TypeDescriptor::top_object() { objectness_ = types::Objectness::Top; }

types::Objectness
TypeDescriptor::Objectness() const { return objectness_; }

void
TypeDescriptor::set_type_name(std::vector<std::string> candidates) {

  candidate_typenames_ = candidates;

  if (candidate_typenames_.size() == 1) {
    type_name_ = candidate_typenames_.at(0);
  }
  else if (candidate_typenames_.size() > 1) {
    type_name_ = types::TypenameBottom;
  }
  else { // There are 0 candidates
    type_name_ = types::TypenameTop;
  }
}

// Explicitly set type name
void
TypeDescriptor::set_type_name(std::string n) {
  type_name_ = n;
}

std::string
TypeDescriptor::get_type_name() const {
  return type_name_;
}

const std::vector<std::string>&
TypeDescriptor::get_candidate_type_names() {
  return candidate_typenames_;
}

void
TypeDescriptor::bottom_name() {
  type_name_ = types::TypenameBottom;
}

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
    OWARN << "Detected possible floating point value: " << *tnp << ", Not asserting value" << LEND;
    return;
  }
  session_->add_fact(VAL_FACT, treenode_to_xsb(tnp), tnp->toInt());
}

// assert facts concerning the size of tree nodes. The format of this fact is
// (bitwidth HASH SIZE)
void
TypeSolver::assert_bitwidth_fact(TreeNodePtr tnp) {

  if (!session_ || !tnp) return;

  session_->add_fact(BITWIDTH_FACT, treenode_to_xsb(tnp), tnp->nBits());
}

// Assert basic facts about global memory, such as global addreses refer to specific values
void
TypeSolver::assert_global_variable_facts() {

  // ======================================================
  // Emit global variable facts. These facts capture the fact that
  const GlobalMemoryDescriptorMap& globals = global_descriptor_set->get_global_map();
  const FunctionDescriptorMap& funcs = global_descriptor_set->get_func_map();
  for (const GlobalMemoryDescriptorMap::value_type & pair : globals) {

    GlobalMemoryDescriptor global_var = pair.second;

    // is this is a function, then it is not really a global variable
    if (funcs.find(global_var.get_address()) != funcs.end()) continue;

    SymbolicValuePtr global_address = global_var.get_memory_address();
    const std::vector<SymbolicValuePtr>& global_values = global_var.get_values();

    if (global_values.empty() || !global_address) continue;

    TreeNodePtr global_mem_tnp = global_address->get_expression();
    if (has_type_descriptor(global_mem_tnp) == false) {
      recursively_assert_facts(global_mem_tnp);
    }
    else {

      // if the global variable has already been assigned a type descriptor, turn it to facts
      // and re-analyze with new evidence
      to_facts(global_mem_tnp, session_);
    }
    uint64_t m = reinterpret_cast<uint64_t>(&*global_mem_tnp);

    for (auto gv : global_values) {
      TreeNodePtr global_val_tnp = gv->get_expression();
      uint64_t v = reinterpret_cast<uint64_t>(&*global_val_tnp);

      if (has_type_descriptor(global_val_tnp) == false) {
        recursively_assert_facts(global_val_tnp);
      }
      else {

      // if the global variable has already been assigned a type descriptor, turn it to facts
      // and re-analyze with new evidence

        TypeDescriptorPtr known_val_tdp = fetch_type_descriptor(global_mem_tnp);
        to_facts(global_mem_tnp, session_);
      }

      session_->add_fact(POINTS_TO_FACT,
                         treenode_to_xsb(global_mem_tnp),
                         treenode_to_xsb(global_val_tnp));

      MTRACE << "Global variable PointsTo:  = " << *global_mem_tnp << " - " << addr_str(m)
             << " -> " << *global_val_tnp << " - " << addr_str(v) << LEND;
    }


    // As with stack variable there can be multiple values. All the values in the global
    // variable value set should be the same type. Of course, there must be multiple values for
    // this to make sense

    if (global_values.size() > 1) {
      for (unsigned int i=0; i < global_values.size()-1; i++) {
        const SymbolicValuePtr& cur_val = global_values.at(i);
        const SymbolicValuePtr& nxt_val = global_values.at(i+1);

        if (!cur_val || !nxt_val) continue;

        TreeNodePtr cur_val_tnp = cur_val->get_expression();
        TreeNodePtr nxt_val_tnp = nxt_val->get_expression();

        if (!cur_val_tnp || !nxt_val_tnp) continue;

        session_->add_fact(SAME_TYPE_FACT,
                           treenode_to_xsb(cur_val_tnp),
                           treenode_to_xsb(nxt_val_tnp));

        MDEBUG << "Emitting sameType fact for global values treenodes: (cur==nxt): "
               << addr_str(treenode_to_xsb(cur_val_tnp)) << " == " << addr_str(treenode_to_xsb(nxt_val_tnp))
               << LEND;
      }
    }
  }
}

void
TypeSolver::assert_objectness_facts(const CallDescriptor *cd) {

  FunctionDescriptor *target_fd = cd->get_function_descriptor();
  RegisterDescriptor ecx_thisptr = global_descriptor_set->get_arch_reg("ecx");

  MTRACE << "Generating objectness facts for call at " << addr_str(cd->get_address()) << LEND;

  // the called function address may be null, for instance if it is an
  // imported function
  if (target_fd && target_fd->get_address() != 0) {

    // Is this a call to the new operator? If so, emit facts that the value is an object
    if (target_fd->is_new_method()) {

      MTRACE << "Found call to static new method (" << target_fd->address_string() << ")"
            << " at call " << addr_str(cd->get_address()) << LEND;

      // This is how we must get the return value for new() at the call point
      SgAsmx86Instruction* call_insn = isSgAsmX86Instruction(cd->get_insn());
      SymbolicValuePtr new_retval;
      access_filters::aa_range reg_writes = du_analysis_.get_reg_writes(call_insn);
      if (std::begin(reg_writes) != std::end(reg_writes)) {
        for (const AbstractAccess &rwaa : reg_writes) {
          std::string regname = unparseX86Register(rwaa.register_descriptor, NULL);
          if (regname == "eax") {
            new_retval = rwaa.value;
            break;
          }
        }
      }

      if (new_retval) {

        TreeNodePtr new_tnp = new_retval->get_expression();
        if (new_tnp) {
          uint64_t new_tnp_id = reinterpret_cast<uint64_t>(&*new_tnp);
          MDEBUG << "Adding KNOWN OBJECT fact for static new operator, tnp: "
                 << *new_tnp << " (" << addr_str(new_tnp_id) << ")" << LEND;

          session_->add_fact(KNOWN_OBJECT_FACT, treenode_to_xsb(new_tnp), IS);

          std::string default_type_name = "obj_" + cd->address_string();
          session_->add_fact(KNOWN_TYPENAME_FACT, treenode_to_xsb(new_tnp), default_type_name);

        }
      }
    }

    // Not new() operator - check for thiscall-ness in regular functions
    else {

      MDEBUG << "Function call at " << addr_str(cd->get_address()) << " to "
             << addr_str(target_fd->get_address()) << " not new(), checking for thiscall" << LEND;

      ParamVector callee_params = target_fd->get_parameters().get_params();

      // In the case where this is a regular call (i.e. the function body is in this program),
      // then assert the objectness on the callee parameters

      const CallingConventionPtrVector& conventions = target_fd->get_calling_conventions();
      if (conventions.size() == 1) {
        const CallingConvention* conv = conventions.at(0);

        MDEBUG << "The calling convention for " << addr_str(target_fd->get_address())
               << " is " << conv->get_name() << LEND;

        if (conv->get_name() == THISCALL_CONVENTION) {

          MDEBUG << "Detected  __thiscall method: "
                 << addr_str(target_fd->get_address()) << " called from "
                 << addr_str(cd->get_address()) << LEND;

          for (auto callee_param : callee_params) {
            if (callee_param.value && callee_param.reg == ecx_thisptr) {

              TreeNodePtr ecx_tnp = callee_param.value->get_expression();
              if (ecx_tnp) {
                MDEBUG << "Adding KNOWN OBJECT fact for regular __thiscall method" << LEND;
                session_->add_fact(KNOWN_OBJECT_FACT, treenode_to_xsb(ecx_tnp), IS);
              }
            }
          }
        }
      }
    }
  }

  // If the call is to a function without a descriptor, then it is an
  // import. If it is an import to new() then we know something about
  // it's objectness. Specifically, the return value is an object

  else {

    ImportDescriptor* id = cd->get_import_descriptor();
    if (id != NULL) {
      if (id->is_new_method()) {

        MINFO << "Found call to imported new method at "
              << cd->address_string() << " called from " << addr_str(cd->get_address()) << LEND;

        const SymbolicValuePtr &rv = cd->get_return_value();
        if (rv) {
          TreeNodePtr rv_tnp = rv->get_expression();
          if (rv_tnp) {

            MTRACE << "Adding KNOWN OBJECT fact for imported new" << LEND;
            session_->add_fact(KNOWN_OBJECT_FACT, treenode_to_xsb(rv_tnp), IS);

            // Now create a default typename for this allocation
            std::string default_type_name = "obj_" + cd->address_string();
            session_->add_fact(KNOWN_TYPENAME_FACT, treenode_to_xsb(rv_tnp), default_type_name);

          }
        }
      }

       // If the import is not a call to new() then check to see if it is thiscall-ness and
       // propogate objectness

      else {

        try {
          auto dtype = demangle::visual_studio_demangle(id->get_name());

          if (dtype) {

            // Evaluate imported __thiscall methods and set the ECX parameter to an object
            if (dtype->symbol_type == demangle::SymbolType::ClassMethod) {

              MTRACE << "Detected imported __thiscall method: "
                     << addr_str(id->get_address()) << " called from "
                     << addr_str(cd->get_address()) << LEND;

              // Duggan says get the params from the import descriptor
              const ParamVector& caller_params = cd->get_parameters().get_params();

              for (const ParameterDefinition &param : caller_params) {

                if (param.value  && param.reg == ecx_thisptr) {

                  TreeNodePtr ecx_tnp = param.value->get_expression();
                  if (ecx_tnp) {
                    MDEBUG << "Adding KNOWN OBJECT fact for imported __thiscall method" << LEND;
                    session_->add_fact(KNOWN_OBJECT_FACT, treenode_to_xsb(ecx_tnp), IS);
                  }
                }
              }
            }
          }
        }
        catch (const demangle::Error &) {
          // I guess this isn't an OO Method
        }
      }
    }
  }
}

void
TypeSolver::assert_local_variable_facts() {

  // ===================================================
  // Emit stack variable facts
  const StackVariablePtrList& stack_vars = current_function_->get_stack_variables();

  // For each stack variable, emit the "pointsTo" facts. These facts
  // capture the stack variable memory addresses refer to stack
  // variable values (if present)
  for (StackVariable *stkvar : stack_vars) {

    MTRACE << "Emitting facts for stack variable: " << stkvar->to_string() << LEND;

    SymbolicValuePtr var_addr = stkvar->get_memory_address();
    if (!var_addr) continue;

    // the stack var address is valid ... it always should be at this
    // point

    TreeNodePtr var_addr_tnp = var_addr->get_expression();

    // add default type info to the memory address
    if (!has_type_descriptor(var_addr_tnp)) {
      recursively_assert_facts(var_addr_tnp);
    }

    // There can be multiple values
    std::vector<SymbolicValuePtr> var_vals = stkvar->get_values();
    for (auto var_val : var_vals) {

      if (var_val) {
        TreeNodePtr var_val_tnp = var_val->get_expression();

        // add default type info to the value
        if (!has_type_descriptor(var_val_tnp)) {
          recursively_assert_facts(var_val_tnp);
        }

        session_->add_fact(POINTS_TO_FACT,
          treenode_to_xsb(var_addr_tnp),
          treenode_to_xsb(var_val_tnp));


        MDEBUG << "Stack variable PointsTo:  = "
               << *var_addr_tnp << " - " << addr_str(treenode_to_xsb(var_addr_tnp))
               << " -> " << *var_val_tnp << " - " << addr_str(treenode_to_xsb(var_val_tnp)) << LEND;
      }
    }

    // There can be multiple values. All the values in the stack
    // variable value set should be the same type. Of course, there
    // must be multiple values for this to make sense
    if (var_vals.size() > 1) {
      for (unsigned int i=0; i < var_vals.size()-1; i++) {
        SymbolicValuePtr& cur_val = var_vals.at(i);
        SymbolicValuePtr& nxt_val = var_vals.at(i+1);

        if (!cur_val || !nxt_val) continue;

        TreeNodePtr cur_val_tnp = cur_val->get_expression();
        TreeNodePtr nxt_val_tnp = nxt_val->get_expression();

        if (!cur_val_tnp || !nxt_val_tnp) continue;

        session_->add_fact(SAME_TYPE_FACT,
                           treenode_to_xsb(cur_val_tnp),
                           treenode_to_xsb(nxt_val_tnp));

        MDEBUG << "Emitting sameType fact for stack values treenodes: (cur==nxt): "
              << addr_str(treenode_to_xsb(cur_val_tnp)) << " == " << addr_str(treenode_to_xsb(nxt_val_tnp)) << LEND;
      }
    }
  }
}

void
TypeSolver::assert_function_call_facts() {

  // To make the reasoning work for the entire program, all the facts for each call must be
  // available at every function

  for (auto call_pair : global_descriptor_set->get_call_map()) {
    CallDescriptor cd = call_pair.second;

    const ParamVector& caller_params = cd.get_parameters().get_params();
    ParamVector callee_params;

    // if this is an import, then there are no interprocedural facts, but there are caller-perspective facts
    const ImportDescriptor *imp = cd.get_import_descriptor(); // is this an import?
    if (imp != NULL) {
      // import
      const FunctionDescriptor* impfd = imp->get_function_descriptor();
      if (impfd) {
        callee_params = impfd->get_parameters().get_params();
      }
    }
    else {
      // Not import
      FunctionDescriptor *target_fd = cd.get_function_descriptor();
      if (target_fd) {
        callee_params = target_fd->get_parameters().get_params();
      }
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
          TypeDescriptorPtr caller_td = fetch_type_descriptor(caller_tnp);

          TreeNodePtr callee_tnp = callee_param.value->get_expression();
          TypeDescriptorPtr callee_td = fetch_type_descriptor(callee_tnp);

          // Emit all the known facts about the callee to ensure the type is correct
          to_facts(callee_tnp, session_);


          // Link the caller/callee params to enable interprocedural reasoning

          session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(caller_tnp), treenode_to_xsb(callee_tnp));

          MTRACE << "Emitting sameType fact for caller/callee params. (caller==callee) "
                 << addr_str(treenode_to_xsb(caller_tnp)) << " == " << addr_str(treenode_to_xsb(callee_tnp)) << LEND;
        }
      }
      // Move to the next parameter set
      ++callee_iter;
      ++caller_iter;
    }
  }
}

// ============================================================================================
// Assert various same type facts for function calls including facts to relate parameters to
// variables, return values, and global memory. These facts enable interprocedural analysis by
// emitting a facts for variety of equivalence relationships.

void
TypeSolver::assert_function_call_parameter_facts(const CallDescriptor *cd) {

  MDEBUG << "Analyzing function call at "
         << addr_str(cd->get_address()) << LEND;

  if (cd == NULL) {
    OERROR << "Invalid call descriptor" << LEND;
  }

  if (!session_) {
    OERROR << "Cannot assert function call facts - invalid prolog session" << LEND;
    return;
  }

  // ==========================================================================================
  // Emit facts about how return values relate to parameters, local
  // variables and global variables. facts.
  //
  const StackVariablePtrList& stack_vars = current_function_->get_stack_variables();

  const ParamVector& cd_rets = cd->get_parameters().get_returns();
  for (const ParameterDefinition &retval : cd_rets) {

    if (retval.value) {

      TreeNodePtr retval_tnp = retval.value->get_expression();

      if (false == has_type_descriptor(retval_tnp)) {
        recursively_assert_facts(retval_tnp);
      }

      if (!retval_tnp) continue;
      session_->add_fact(FNCALL_RETVAL_FACT,
                         cd->get_address(),
                         treenode_to_xsb(retval_tnp));

      // ======================================================================================
      // Tie return values to stack variables
      for (StackVariable *stkvar : stack_vars) {
        if (!stkvar) continue;

        std::vector<SymbolicValuePtr> var_vals = stkvar->get_values();
        for (SymbolicValuePtr varval_sv : var_vals) {

          if (varval_sv) {
            TreeNodePtr varval_tnp = varval_sv->get_expression();

            if (!varval_tnp) continue;

            if (smart_can_be_equal(retval.value, varval_sv) == true) {
              MDEBUG << "Emitting sameType fact for stackvar/ret val: (retval==stackvar) "
                     << *retval_tnp << " == " << *varval_tnp << LEND
                     << addr_str(treenode_to_xsb(retval_tnp)) << " == " << addr_str(treenode_to_xsb(varval_tnp))
                     << LEND;

              session_->add_fact(SAME_TYPE_FACT,
                                 treenode_to_xsb(retval_tnp),
                                 treenode_to_xsb(varval_tnp));
              break;
            }
          }
        }
      }

      // ======================================================================================
      // Type global variables from return values; for example:
      //
      // int x;
      // void func() {
      //   x = API();
      // }

      // Check the global value against the return value
      const GlobalMemoryDescriptorMap& globals = global_descriptor_set->get_global_map();
      const FunctionDescriptorMap& funcs = global_descriptor_set->get_func_map();

       for (const GlobalMemoryDescriptorMap::value_type & pair : globals) {

         GlobalMemoryDescriptor global_var = pair.second;

         // is this is a function, then it is not really a global variable
         if (funcs.find(global_var.get_address()) != funcs.end()) continue;

         SymbolicValuePtr global_address = global_var.get_memory_address();
         const std::vector<SymbolicValuePtr>& global_values = global_var.get_values();

         if (smart_can_be_equal(global_address,retval.value) == true) {
           TreeNodePtr global_addr_tnp = global_address->get_expression();

           session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(retval_tnp), treenode_to_xsb(global_addr_tnp));

           MDEBUG << "Emitting sameType fact for global addr to ret val: (ret_val==global_addr) "
                  << addr_str(treenode_to_xsb(retval_tnp)) << " == " << addr_str(treenode_to_xsb(global_addr_tnp))
                  << LEND;

         }
         else {
           for (auto global_val : global_values) {
             if (smart_can_be_equal(global_val,retval.value) == true) {
               TreeNodePtr global_val_tnp = global_val->get_expression();

               session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(retval_tnp), treenode_to_xsb(global_val_tnp));

               MDEBUG << "Emitting sameType fact for global val to ret val: (global_val==ret_val) "
                      << addr_str(treenode_to_xsb(global_val_tnp)) << " == " << addr_str(treenode_to_xsb(retval_tnp))
                      << LEND;
             }
           }
         }
       }

       // TODO: We also need to check return values against parameters. Consider the
       // following:
       //
       //  Object *o = new Object();
       //  o->method();
       //
       // In this case the return value of new may be placed directly in ECX and passe to
       // o::method

    } // if retval is valid
  } // for each retval

  // ======================================================================================================
  // Emit facts about parameters as they relate to stack and global variables. We are
  // looking for pass byte value and pass by reference relationships
  const ParamVector& caller_params = cd->get_parameters().get_params();

  MDEBUG << "This function has " << stack_vars.size() << " stack variables and "
         << caller_params.size() << " parameters" << LEND;

  for (const ParameterDefinition &param : caller_params) {

    if (!param.value || !param.address) continue;

    TreeNodePtr par_val_tnp = param.value->get_expression();
    TreeNodePtr par_mem_tnp = param.address->get_expression();
    uint64_t par_val_id = reinterpret_cast<uint64_t>(&*par_val_tnp);

    session_->add_fact(FNCALL_ARG_FACT,
                       cd->get_address(), param.num, treenode_to_xsb(par_val_tnp));

    MTRACE << "===" << LEND;
    MTRACE << "Evaluating TNP Param: (" << addr_str(par_val_id) << ") " << *par_val_tnp << LEND;

    if (has_type_descriptor(par_val_tnp) == false) {
      recursively_assert_facts(par_val_tnp);
    }
    if (has_type_descriptor(par_mem_tnp) == false) {
      recursively_assert_facts(par_mem_tnp);
    }

    // Emit (obvious) facts that the parameter memory address "points
    // to" the parameter value
    session_->add_fact(POINTS_TO_FACT,
                       treenode_to_xsb(par_mem_tnp), treenode_to_xsb(par_val_tnp));

    for (StackVariable *stkvar : stack_vars) {

      if (!stkvar) continue;

      SymbolicValuePtr var_addr = stkvar->get_memory_address();

      if (!var_addr) continue;

      TreeNodePtr var_addr_tnp = var_addr->get_expression();
      uint64_t var_addr_id = reinterpret_cast<uint64_t>(&*var_addr_tnp);

      // Do the parameter and stack variable share evidence?  if the
      // value in parameter read from insn from the local variable,
      // they must be the same type.  This really means is the var
      // address the same value read? if so, then the address of the
      // stack var is pushed so it's stack address is the param
      // value. This is a classic pass-by-reference (PBR)
      // arrangement. Essentially, this means that we are passing the
      // address of a stack variable to a function

      MTRACE << "Checking sameType fact for PBR treenodes: var_addr: "
            << *var_addr_tnp << " : " << addr_str(var_addr_id)
            << ", par_val: " << *par_val_tnp << " : " << addr_str(par_val_id) << LEND;

      if (smart_can_be_equal(var_addr, param.value) == true) {
        if (var_addr_id != par_val_id) {
          MTRACE << "*** Detected stack variable pass by reference" << LEND;
          session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(var_addr_tnp), treenode_to_xsb(par_val_tnp));

          MDEBUG << "Emitting sameType fact for param/var PBR: (var_addr==param_val) "
                 << addr_str(treenode_to_xsb(var_addr_tnp)) << " == " << addr_str(treenode_to_xsb(par_val_tnp))
                 << LEND;
        }
      }
      else {

        // If the relationship is not PBR, check for pass-by-value
        // (PBV). With PBV relationships the values contained in the
        // stack variables will be used as parameters. The approach to
        // detecting PBV is to compare values and then, if there is a
        // match, look for common defining instructions

        std::vector<SymbolicValuePtr> var_vals = stkvar->get_values();
        for (auto var_val : var_vals) {

          if (!var_val) continue;

          TreeNodePtr var_val_tnp = var_val->get_expression();
          if (!var_val_tnp) continue;

          // This test checks for pass by value by comparing
          // values. Not a given that this indicates PBV, but a
          // necessary precondition
          if (var_val_tnp->isEquivalentTo(par_val_tnp)) {

            uint64_t var_val_id = reinterpret_cast<uint64_t>(&*var_val_tnp);

            // sameType facts are not needed for the exact same treenode

            if (var_val_id != par_val_id) { // TODO: Check this, it will not work for symbolic memory addresses

              // If the two values are equal but not identical, check
              // their lineage to see if they are related (i.e. have
              // commong defining instructions).
              const InsnSet& par_definers = param.value->get_defining_instructions();
              const InsnSet& var_definers = var_val->get_defining_instructions();
              InsnSet intersect;

              // if the intersection of the parameter and stack definers is not the empty set
              std::set_intersection(par_definers.begin(), par_definers.end(),
                                    var_definers.begin(), var_definers.end(),
                                    std::inserter(intersect, intersect.begin()));

              MTRACE << "Checking sameType fact for PBV treenodes: var_val: "
                     << *var_val_tnp << " : " << addr_str(var_val_id)
                     << ", par_val: " << *par_val_tnp << " : " << addr_str(par_val_id) << LEND;

              if (intersect.size() > 0) {
                MTRACE << "*** Detected stack variable pass by value" << LEND;

                session_->add_fact(SAME_TYPE_FACT,
                                   treenode_to_xsb(var_val_tnp), treenode_to_xsb(par_val_tnp));

                MDEBUG << "Emitting sameType fact for param/var PBV: (var_val==param_val) "
                       << addr_str(treenode_to_xsb(var_val_tnp)) << " == " << addr_str(treenode_to_xsb(par_val_tnp))
                       << LEND;


              }
            }
          }
        } // for each val
      } // else check PBV
    } // for each stack variable

    // ======================================================================================
    // check for PBV and PBR in global vars
    const GlobalMemoryDescriptorMap& globals = global_descriptor_set->get_global_map();
    const FunctionDescriptorMap& funcs = global_descriptor_set->get_func_map();

    for (const GlobalMemoryDescriptorMap::value_type & pair : globals)  {

      GlobalMemoryDescriptor global_var = pair.second;

      // Again, skip function pointers
      if (funcs.find(global_var.get_address()) != funcs.end()) continue;

      SymbolicValuePtr global_address = global_var.get_memory_address();
      const std::vector<SymbolicValuePtr>& global_values = global_var.get_values();

      if (global_values.empty() || !global_address) continue;

      TreeNodePtr global_mem_tnp = global_address->get_expression();

      for (auto gv : global_values) {
        TreeNodePtr global_val_tnp = gv->get_expression();

        if (!global_val_tnp || !global_mem_tnp) continue;

        MDEBUG << "Global variable val = " << *global_val_tnp << ", mem = " << *global_mem_tnp << LEND;
        MDEBUG << "Param "  << param.num << " variable val = " << *par_val_tnp << ", mem = " << *par_mem_tnp << LEND;

        // if the memory address of the global is the value of the parameter, then this is PBR
        if (global_mem_tnp->isEquivalentTo(par_val_tnp)) {

          uint64_t gmaddr = reinterpret_cast<uint64_t>(&*global_mem_tnp);

          // there is no reason to emit sameType facts for the same exact treenode
          if (gmaddr != par_val_id) {
            MDEBUG << "*** Detected global variable pass by reference" << LEND;

            MDEBUG << "Emitting sameType fact for global PBR treenodes: (global mem==param) "
                  << addr_str(treenode_to_xsb(global_mem_tnp)) << " == " << addr_str(treenode_to_xsb(par_val_tnp)) << LEND;

            session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(global_mem_tnp), treenode_to_xsb(par_val_tnp));
          }
        }

        // Test for PBV by comparing values
        else if (global_val_tnp->isEquivalentTo(par_val_tnp)) {

          uint64_t gvaddr = reinterpret_cast<uint64_t>(&*global_val_tnp);

          // there is no reason to emit sameType facts for the same exact treenode
          if (gvaddr != par_val_id) {
            MDEBUG << "*** Detected global variable pass by value" << LEND;

            MDEBUG << "Emitting sameType fact for global PBV treenodes: gbl address: (global==param) "
                  << addr_str(treenode_to_xsb(global_val_tnp)) << " == " << addr_str(treenode_to_xsb(par_val_tnp)) << LEND;

            session_->add_fact(SAME_TYPE_FACT,
                               treenode_to_xsb(global_val_tnp), treenode_to_xsb(par_val_tnp));
          }
        }
      } // for each global variable value
    } // for each global variable
  }  // for each parameter
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
    // the current treenode and can be ignored2
    if (possible_val_set.size() > 1) {
      for (auto ite_elm : possible_val_set) {

        MDEBUG << "Emitting sameType fact for ITE (part 2)"
               << addr_str( treenode_to_xsb(ite_elm)) << " == " << addr_str(treenode_to_xsb(tnp))
               << LEND;

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

    TreeNodePtr tnp = param.get_value()->get_expression();
    auto type = param.get_type();

    if (!type.empty()) {

      typedb::TypeRef ref = typedb_.lookup(type);

      dir_enum dir = IN;
      // parameters that receive a (persistent) value are OUT or IN/OUT.
      if (param.direction == ParameterDefinition::DIRECTION_OUT ||
          param.direction == ParameterDefinition::DIRECTION_INOUT) {
        dir = OUT;
      }

      assert_type_facts(ref);

      // name the parameter type by ordinal
      session_->add_fact(API_PARAM_TYPE_FACT, imp_ss.str(), param.num, ref->get_name(), dir);
    }
  } // foreach param

  // emit facts about return types for functions ... the "by-convention" return type
  RegisterDescriptor eax_reg = global_descriptor_set->get_arch_reg("eax");

  // Emit a fact about return type for the API
  const ParamVector& cd_rets = cd->get_parameters().get_returns();
  for (const ParameterDefinition &retval : cd_rets) {

    // for now just track eax and the "return value"
    if (retval.reg == eax_reg) {
      typedb::TypeRef ret_type = typedb_.lookup(retval.get_type());
      // emit a fact about return type

      MTRACE << "The return type of " << imp_ss.str()
            << " is " << ret_type->get_name() << LEND;

      session_->add_fact(API_RET_TYPE_FACT, imp_ss.str(),  ret_type->get_name());

      assert_type_facts(ret_type);

      break;
    }
  }
}

// assert basic facts about this type
void
TypeSolver::assert_type_facts(typedb::TypeRef& ref) {

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
  // This is not a pointer. Do we know of any types that point to it?
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

  // Dump function return value facts
  auto rvQuery = session_->query(FNCALL_RETVAL_FACT, any(), any());
  for (; !rvQuery->done(); rvQuery->next()) {
    rvQuery->debug_print(out_sstream);
  }

  // Dump function return value facts
  auto obj_query = session_->query(KNOWN_OBJECT_FACT, any(), any());
  for (; !obj_query->done(); obj_query->next()) {
    obj_query->debug_print(out_sstream);
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
 */
void
TypeSolver::save_api_facts(std::iostream &out_sstream) {

  if (!session_) return;

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

  // Dump API function return type facts
  auto rtQuery = session_->query(API_RET_TYPE_FACT, any(), any());
  for (; !rtQuery->done(); rtQuery->next()) {
    rtQuery->debug_print(out_sstream);
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

// Find new methods by examining imports.
void find_imported_new_methods() {
  MTRACE << "Finding imported new methods..." << LEND;

  // Make a list of names that represent new in it's various forms.
  StringSet new_method_names;
  new_method_names.insert("??2@YAPAXI@Z");
  new_method_names.insert("??2@YAPAXIHPBDH@Z");
  // From notepad++5.6.8:
  // void *__cdecl operator new(size_t Size, const struct std::nothrow_t *)
  new_method_names.insert("??2@YAPAXIABUnothrow_t@std@@@Z");

  // Get the import map out of the provided descriptor set.
  ImportDescriptorMap& im = global_descriptor_set->get_import_map();

  // For each new() name...
  for (const std::string & name : new_method_names) {
    // Find all the import descriptors that match.

    for (ImportDescriptor* id : im.find_name(name)) {
      MTRACE << "Imported new '" << name << "' found at address "
            << id->address_string() << "."<< LEND;
      id->set_new_method(true);
      id->get_rw_function_descriptor()->set_new_method(true);

      // This part is kind-of icky.  Maybe we should make a nice set of backward links to all
      // the imports from all the thunks that jump to them...  For now Cory's going to brute
      // force it and move on.
      FunctionDescriptorMap& fdmap = global_descriptor_set->get_func_map();
      for (FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
        // If it's not a thunk to the import, move on to the next function.
        if (fd.get_jmp_addr() != id->get_address()) continue;
        // If this function is a thunk to the import, it's a new method.
        MTRACE << "Function at " << fd.address_string()
              << " is a thunk to a new() method." << LEND;
        fd.set_new_method(true);
        // Also any functions that are thunks to this function are new methods.  This is
        // another example of why thunks are tricky.  In this case we want to access them
        // backwards.  We don't currently have an inverted version of follow_thunks().
        for (FunctionDescriptor* tfd : fd.get_thunks()) {
          MTRACE << "Function at " << tfd->address_string()
                << " is a thunk to a thunk to a new() method." << LEND;
          tfd->set_new_method(true);
        }
      }
    }
  }
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

  // TODO: This code is literally copied from ooanalyzer and should be
  // moved into a Known Function Analyzer
  find_imported_new_methods();

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
  // MDEBUG << "Generating facts for (" << addr_str(tnaddr) << ") " << *tnp << LEND;

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

        MDEBUG << "Emitting sameType fact for ITE: "
               << addr_str( treenode_to_xsb(kids[1])) << " == " << addr_str(treenode_to_xsb(tnp))
               << LEND;

        session_->add_fact(SAME_TYPE_FACT, treenode_to_xsb(kids[2]), treenode_to_xsb(tnp));

        MDEBUG << "Emitting sameType fact for ITE: "
              << addr_str( treenode_to_xsb(kids[2])) << " == " << addr_str(treenode_to_xsb(tnp))
              << LEND;
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
  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

  if (!session_) {
    OERROR << "Error cannot start prolog" << LEND;
    return false;
  }

  MDEBUG << "Generating type facts" << LEND;

  time_point factgen_ts = clock::now();

  for (auto& tnpair : treenodes) {
    recursively_assert_facts(tnpair.second);
  }

  MDEBUG << "Analyzing " << memory_accesses.size() << " memory accesses" << LEND;

  // assert the memory facts
  for (auto mempair : memory_accesses) {
    if (mempair.second) {
      assert_memory_facts(mempair.second);
      recursively_assert_facts(mempair.second);
    }
  }

  assert_global_variable_facts();

  assert_local_variable_facts();

  assert_function_call_facts();

  // examine the calls in this function and assert relevant facts
  for (const CallDescriptor *cd : current_function_->get_outgoing_calls()) {

    if (cd) {
      // for each found call descriptor assert the relevant facts
      assert_objectness_facts(cd);
      assert_function_call_parameter_facts(cd);
      assert_api_facts(cd);
    }
  }

  time_point factgen_te = clock::now();
  duration factgen_secs = factgen_te - factgen_ts;

  // Generate the type descriptors based on collected facts
  time_point typegen_ts = clock::now();

  generate_type_descriptors();

  time_point typegen_te = clock::now();
  duration typegen_secs = typegen_te - typegen_ts;

  MTRACE << "Type analysis complete for function " << addr_str(current_function_->get_address())
         << ", fact generation took " << factgen_secs.count()
         << "s; type generation took " << typegen_secs.count() << "s" << LEND;

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

// Update TypeDescriptor type name information
void TypeSolver::update_typename() {

  if (!session_) {
    OERROR << "Invalid prolog session!" << LEND;
    return;
  }

  uint64_t tnp_term;
  std::vector<std::string> candidate_names;
  auto query = session_->query(FINAL_TYPENAME_QUERY, var(tnp_term), var(candidate_names));

  for (; !query->done(); query->next()) {

    TreeNode* tn = xsb_to_treenode(tnp_term);
    TreeNodePtr tnp = tn->sharedFromThis();

    TypeDescriptorPtr type_desc = fetch_type_descriptor(tnp);
    type_desc->set_type_name(candidate_names); // This type has a known name
  }
}

// Update TypeDescriptor pointerness information
void
TypeSolver::update_pointerness() {

  MDEBUG << "Updating pointerness" << LEND;

  if (!session_) {
    OERROR << "Invalid prolog session!" << LEND;
    return;
  }

  uint64_t pointer_term;
  type_enum pointer_result;

  auto pointer_query = session_->query(FINAL_POINTER_QUERY, var(pointer_term), var(pointer_result));
  for (; !pointer_query->done(); pointer_query->next()) {

    TreeNode* tn = xsb_to_treenode(pointer_term);
    TreeNodePtr tnp = tn->sharedFromThis();
    uint64_t addr = reinterpret_cast<uint64_t>(&*tnp);

    TypeDescriptorPtr type_desc = fetch_type_descriptor(tnp);
    if (pointer_result == IS) {
      MDEBUG << "setting " << addr_str(addr) << " to IS pointer" << LEND;
      type_desc->is_pointer(); // indicate this is a pointer
    }
    else if (pointer_result == ISNOT) {
      MDEBUG << "setting " << addr_str(addr) << " to ISNOT pointer" << LEND;
      type_desc->not_pointer(); // indicate this is not a pointer
    }
    else if (pointer_result == BOTTOM) {
      MDEBUG << "setting " << addr_str(addr) << " to BOTTOM object" << LEND;
      type_desc->bottom_pointer(); // indicate there is conflicting evidence of pointerness
    }
    else {
      // This may be redundant, but it is explicit
      MDEBUG << "setting " << addr_str(addr) << " to TOP object" << LEND;
      type_desc->top_pointer(); // indicate we don't know about pointerness
    }
  }
}


// Update the TypeDescriptor objectness information
void
TypeSolver::update_objectness() {

  if (!session_) {
    OERROR << "Invalid prolog session!" << LEND;
    return;
  }

  uint64_t obj_term;
  type_enum obj_result;

  auto obj_query = session_->query(FINAL_OBJECT_QUERY, var(obj_term), var(obj_result));
  for (; !obj_query->done(); obj_query->next()) {

    TreeNode* tn = xsb_to_treenode(obj_term);
    TreeNodePtr tnp = tn->sharedFromThis();
    uint64_t addr = reinterpret_cast<uint64_t>(&*tnp);

    TypeDescriptorPtr type_desc = fetch_type_descriptor(tnp);

    if (obj_result == IS) {
      MDEBUG << "setting " << addr_str(addr) << " to IS object" << LEND;
      type_desc->is_object(); // indicate this is an object
    }
    else if (obj_result == ISNOT) {
      MDEBUG << "setting " << addr_str(addr) << " to ISNOT object" << LEND;
      type_desc->not_object(); // indicate this is not an object
    }
    else if (obj_result == BOTTOM) {
      MDEBUG << "setting " << addr_str(addr) << " to BOTTOM object" << LEND;
      type_desc->bottom_object(); // indicate there is no evidence of objectness
    }
    else {
      MDEBUG << "setting " << addr_str(addr) << " to TOP object" << LEND;
      type_desc->top_object(); // indicate there is no evidence of objectness
    }
  }
}

/**
 * Update the TypeDescriptor signedness information
 */
void TypeSolver::update_signedness() {

  if (!session_) {
    OERROR << "Invalid prolog session!" << LEND;
    return;
  }

  uint64_t signed_term;
  type_enum signed_result;

  auto signed_query = session_->query(FINAL_SIGNED_QUERY, var(signed_term), var(signed_result));
  for (; !signed_query->done(); signed_query->next()) {

    TreeNode* tn = xsb_to_treenode(signed_term);
    TreeNodePtr tnp = tn->sharedFromThis();
    uint64_t addr = reinterpret_cast<uint64_t>(&*tnp);

    TypeDescriptorPtr type_desc = fetch_type_descriptor(tnp);

    if (signed_result == IS) {
      MDEBUG << "setting " << addr_str(addr) << " to signed" << LEND;
      type_desc->is_signed(); // indicate this is signed
    }
    else if (signed_result == ISNOT) {
      MDEBUG << "setting " << addr_str(addr) << " to unsigned" << LEND;
      type_desc->not_signed(); // indicate this is unsigned
    }
    else if (signed_result == BOTTOM) {
      MDEBUG << "setting " << addr_str(addr) << " to BOTTOM signed" << LEND;
      type_desc->bottom_signed(); // indicate there is conflicting evidence of signedness
    }
    else {
      // This may be redundant, but it makes intentions explicit
      MDEBUG << "setting " << addr_str(addr) << " to TOP signed" << LEND;
      type_desc->top_signed();
    }
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
  exported += session_->print_predicate(std::cout, APINAME_FACT, 2);
  exported += session_->print_predicate(std::cout, API_PARAM_TYPE_FACT, 4);
  exported += session_->print_predicate(std::cout, TYPE_POINTER_FACT, 2);
  exported += session_->print_predicate(std::cout, TYPE_SIGNED_FACT, 2);
  exported += session_->print_predicate(std::cout, KNOWN_OBJECT_FACT, 2);
  exported += session_->print_predicate(std::cout, KNOWN_POINTER_FACT, 3);
  exported += session_->print_predicate(std::cout, KNOWN_SIGNED_FACT, 3);
  exported += session_->print_predicate(std::cout, KNOWN_TYPENAME_FACT, 2);
  exported += session_->print_predicate(std::cout, TYPE_REF_FACT, 2);
  exported += session_->print_predicate(std::cout, SAME_TYPE_FACT, 2);
  exported += session_->print_predicate(std::cout, POINTS_TO_FACT, 2);

  std::cout << "% type fact exporting complete." << std::endl;

  MINFO << "Exported " << exported << " Prolog facts." << LEND;
}


// This function will update the default type descriptors, currently
// with pointer and sign information
void TypeSolver::generate_type_descriptors() {
  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

  MINFO << "Updating type descriptors for function "
        << addr_str(current_function_->get_address()) << LEND;

  time_point t1 = clock::now();

  update_pointerness();
  time_point t2 = clock::now();
  duration secs1 = t2 - t1;
  MINFO << "update_pointerness() for function " << addr_str(current_function_->get_address())
        << " took " << secs1.count() << "s" << LEND;

  update_signedness();
  time_point t3 = clock::now();
  duration secs2 = t3 - t2;
  MINFO << "update_signedness() for function " << addr_str(current_function_->get_address())
        << " took " << secs2.count() << "s" << LEND;

  update_typename();
  time_point t4 = clock::now();
  duration secs3 = t4 - t3;
  MINFO << "update_typename() for function " << addr_str(current_function_->get_address())
        << " took " << secs3.count() << "s" << LEND;

  update_objectness();
  time_point t5 = clock::now();
  duration secs4 = t5 - t4;
  MINFO << "update_objectness() for function " << addr_str(current_function_->get_address())
        << " took " << secs4.count() << "s" << LEND;
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

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
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

  session->add_fact(op_name_, treenode_to_xsb(in), treenode_to_xsb(A), treenode_to_xsb(B));
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

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
