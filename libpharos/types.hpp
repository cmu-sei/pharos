// Copyright 2016-2023 Carnegie Mellon University.  See LICENSE file for terms.
// Author: Jeff Gennari

#ifndef Pharos_Type_Descriptor_H
#define Pharos_Type_Descriptor_H

#include <vector>

#include "misc.hpp" // Needed mainly for the typedefs to avoid crazy long names
#include "util.hpp"
#include "prolog.hpp"
#include "options.hpp"
#include "typedb.hpp"
#include "funcs.hpp"
#include "calls.hpp"

namespace pharos {

// Forward declaration in lieu of including the full OOAnalyzer header.
// This should really be a function finder, and not an OOAnalyzer anyway.
class OOAnalyzer;

void init_type_logging();

namespace types {

// The top of the bitwidth lattice. Clearly this is not a proper
// lattice, but it serves its purpose. In reality the bitwidth is
// fairly easy to determine by looking at underlying treenodes
const size_t BitwidthTop = SIZE_MAX;

// The "top" of the type name lattice really means that we know
// nothing about type name; i.e. it is unknown
const std::string TypenameTop = "top";

const std::string TypenameBottom = "bottom";

// The bottom of the bitwidth lattice. The smallest size possible is
// 0. Again, not a proper lattice
const size_t BitwidthBottom = 0;

} // namespace types

// A type descriptor is a representation of a type lattice. Among the things
// captured by the type descriptor are whether or not a type is a pointer, its
// sign, and its width. There is also support for aggregate types, such as
// structs an classes
class TypeDescriptor {

 private:

  // The following pointers are approximations for lattices. The "Bottom" is
  // the case where analysis is irrelevant or not yet completed.

  types::Pointerness pointerness_;

  // Signedness (signed or unsigned) is the other
  types::Signedness signedness_;

  // Indicates whether this type a pointer to an object
  types::Objectness objectness_;

  std::vector<std::string> candidate_typenames_;

  // This is the human readable type name. Should this be a lattice unto itself
  std::string type_name_;

  // The bitwidth can vary, so there is not a lattice with discrete values.
  size_t bit_width_;

  // if this flag is true then we have an aggregate type
  bool is_aggregate_;

  // The set of things that this type refers to if it is a pointer. I suppose
  // that this needs to be a set because of things like polymorphism
  std::vector<TypeDescriptor*> reference_types_;

  // In the case of aggregate types, keep a list of constituent parts. A pair
  // is needed because each constituent component will be identified via an
  // offset
  std::map< uint32_t, TypeDescriptor*> components_;

 public:

  // The default constructor simply sets everything to the top of the lattices
  // to indicate that nothing is yet known.
  TypeDescriptor();

  TypeDescriptor(const TypeDescriptor& other);

  // assignment operator
  TypeDescriptor& operator=(const TypeDescriptor &other);

  ~TypeDescriptor();

  std::string to_string();

  void set_type_name(std::vector<std::string> candidates);

  void set_type_name(std::string n);

  std::string get_type_name() const;

  const std::vector<std::string>& get_candidate_type_names();

  void bottom_name();

  // TypeDescriptor properties

  void bit_width(size_t bw);
  size_t bit_width() const;

  void is_pointer();
  void not_pointer();
  void bottom_pointer();
  void top_pointer();
  types::Pointerness Pointerness() const;

  void is_signed();
  void not_signed();
  void bottom_signed();
  void top_signed();
  types::Signedness Signedness() const;

  void is_object();
  void not_object();
  void bottom_object();
  void top_object();
  types::Objectness Objectness() const;

  bool type_unknown() const;

}; // TypeDescriptor

// shared pointer to a TypeDescriptor
using TypeDescriptorPtr = boost::shared_ptr< TypeDescriptor >;

// Utility functions to fetch type descriptors from tree nodes. Note
// that this method will create a default type descriptor if one isn't
// found. These functions are meant to be the primary way to access
// type descriptors.
TypeDescriptorPtr fetch_type_descriptor(TreeNodePtr tnp);
TypeDescriptorPtr fetch_type_descriptor(SymbolicValuePtr val);

// returns true if a tree node has a type descriptor
bool has_type_descriptor(TreeNodePtr tnp);

// emit type-relevant facts for a tree node
void to_facts(TreeNodePtr tn, std::shared_ptr<prolog::Session> session);

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
//
// This is the strategy interface for different commands. Every command must over-ride
// this interface
class OperationStrategy {
 protected:

  // operand name
  std::string op_name_;
  std::size_t arity_;

  OperationStrategy(char const * name, std::size_t arity) : op_name_{name}, arity_{arity} {}

 public:

  // The name of the operation; to be defined by extending classes
  const std::string& get_op_name() const;

  // Every strategy for analyzing types must implement this function. The InternalNodePtr
  // in is the (operation) tree node being processed. The session is an active
  // prolog session.
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session)=0;

  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream)
    const;

  // Must have a virtual destructor to ensure proper destructor called.
  virtual ~OperationStrategy() = default;
};

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
// The concrete strategy definition - shouldn't have to touch these unless they are
// being added to or removed from
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

class SextendStrategy : public OperationStrategy {
 public:
  SextendStrategy() : OperationStrategy{"opSextend", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class UextendStrategy : public OperationStrategy {
 public:
  UextendStrategy() : OperationStrategy{"opUextend", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class AddStrategy : public OperationStrategy {
 public:
  AddStrategy() : OperationStrategy{"opAdd", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class BvAndStrategy : public OperationStrategy {
 public:
  BvAndStrategy() : OperationStrategy{"opBvAnd", 2}  {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class AndStrategy : public OperationStrategy {
 public:
  AndStrategy() : OperationStrategy{"opAnd", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class SmulStrategy : public OperationStrategy {
 public:
  SmulStrategy() : OperationStrategy{"opSmul", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class UmulStrategy : public OperationStrategy {

 public:
  UmulStrategy() : OperationStrategy{"opUmul", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class AsrStrategy : public OperationStrategy {
 public:
  AsrStrategy() : OperationStrategy{"opAsr", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class BvXorStrategy : public OperationStrategy {
 public:
  BvXorStrategy() : OperationStrategy{"opBvXor", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class ConcatStrategy : public OperationStrategy {
 public:
  ConcatStrategy() : OperationStrategy{"opConcat", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class EqStrategy : public OperationStrategy {
 public:
  EqStrategy() : OperationStrategy{"opEq", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class ExtractStrategy : public OperationStrategy {
 public:
  ExtractStrategy() : OperationStrategy{"opExtract", 4} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class InvertStrategy : public OperationStrategy {
 public:
  InvertStrategy() : OperationStrategy{"opInvert", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class IteStrategy : public OperationStrategy {
 public:
  IteStrategy() : OperationStrategy{"opIte", 4} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class LssbStrategy : public OperationStrategy {
 public:
  LssbStrategy() : OperationStrategy{"opLssb", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class MssbStrategy : public OperationStrategy {
 public:
  MssbStrategy() : OperationStrategy{"opMssb", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class NeStrategy : public OperationStrategy {
 public:
  NeStrategy() : OperationStrategy{"opNe", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class NegateStrategy : public OperationStrategy {
 public:
  NegateStrategy() : OperationStrategy{"opNegate", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class NoopStrategy : public OperationStrategy {
 public:
  NoopStrategy() : OperationStrategy{"opNoop", 0} {}
  virtual void save_facts(
    std::shared_ptr<prolog::Session> session, std::iostream& out_sstream) const;
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class BvOrStrategy : public OperationStrategy {
 public:
  BvOrStrategy() : OperationStrategy{"opBvOr", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class OrStrategy : public OperationStrategy {
 public:
  OrStrategy() : OperationStrategy{"opOr", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class ReadStrategy : public OperationStrategy {
 public:
  ReadStrategy() : OperationStrategy{"opRead", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class RolStrategy : public OperationStrategy {
 public:
  RolStrategy() : OperationStrategy{"opRol", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class RorStrategy : public OperationStrategy {
 public:
  RorStrategy() : OperationStrategy{"opRor", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class SdivStrategy : public OperationStrategy {
 public:
  SdivStrategy() : OperationStrategy{"opSdiv", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class UdivStrategy : public OperationStrategy {
 public:
  UdivStrategy() : OperationStrategy{"opUdiv", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class SetStrategy : public OperationStrategy {
 public:
  SetStrategy() : OperationStrategy{"opSet", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class SgeStrategy : public OperationStrategy {
 public:
  SgeStrategy() : OperationStrategy{"opSge", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class SgtStrategy : public OperationStrategy {
 public:
  SgtStrategy() : OperationStrategy{"opSgt", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class Shl0Strategy : public OperationStrategy {
 public:
  Shl0Strategy() : OperationStrategy{"opShl0", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class Shl1Strategy : public OperationStrategy {
 public:
  Shl1Strategy() : OperationStrategy{"opShl1", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class Shr0Strategy : public OperationStrategy {
 public:
  Shr0Strategy() : OperationStrategy{"opShr0", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class Shr1Strategy : public OperationStrategy {
 public:
  Shr1Strategy() : OperationStrategy{"opShr1", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class SleStrategy : public OperationStrategy {
 public:
  SleStrategy() : OperationStrategy{"opSle", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class SltStrategy : public OperationStrategy {
 public:
  SltStrategy() : OperationStrategy{"opSlt", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class SmodStrategy : public OperationStrategy {
 public:
  SmodStrategy() : OperationStrategy{"opSmod", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class UmodStrategy : public OperationStrategy {
 public:
  UmodStrategy() : OperationStrategy{"opUmod", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class UgeStrategy : public OperationStrategy {
 public:
  UgeStrategy() : OperationStrategy{"opUge", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class UgtStrategy : public OperationStrategy {
 public:
  UgtStrategy() : OperationStrategy{"opUgt", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class UleStrategy : public OperationStrategy {
 public:
  UleStrategy() : OperationStrategy{"opUle", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class UltStrategy : public OperationStrategy {
 public:
  UltStrategy() : OperationStrategy{"opUlt", 3} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class WriteStrategy : public OperationStrategy {
 public:
  WriteStrategy() : OperationStrategy{"opWrite", 0} {}
  virtual void save_facts(
    std::shared_ptr<prolog::Session> session, std::iostream& out_sstream) const;
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

class ZeropStrategy : public OperationStrategy {
 public:
  ZeropStrategy() : OperationStrategy{"opZerop", 2} {}
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
};

// The context that sets the strategy for operation analysis. The context is used
// to select and eecute a given strategy
class OperationContext {

 private:

  // Map of RISC operation strategies
  std::map<Rose::BinaryAnalysis::SymbolicExpression::Operator, OperationStrategy*> strategies_;

 public:

  ~OperationContext();

  // The constructor for the context installs the available strategies, which are
  // basically one per RISC op
  OperationContext();

  // Analyze the operations by selecting and executing the strategy based on RISC
  // operator
  void assert_operation_fact(Rose::BinaryAnalysis::SymbolicExpression::Operator op,
                             InternalNodePtr tnp,
                             std::shared_ptr<prolog::Session> session);


  // Print asserted operation facts to a string stream. Each strategy must know how to
  // dump itself
  void save_operation_facts(std::shared_ptr<prolog::Session> session, std::iostream &out_sstream);


}; // end OperationContext


// The type solver manages the prolog related aspects of type analysis
class TypeSolver {

 private:

  // The Prolog session handle.
  std::shared_ptr<prolog::Session> session_;

  const DUAnalysis& du_analysis_;

  // This should really be a function finder.
  OOAnalyzer* ooa;

  // The current function being analyzed
  const FunctionDescriptor *current_function_;

  // selects the strategy to use
  OperationContext op_context_;

  typedb::DB typedb_;

  // The name of the typerules to use
  const std::string typerules_;

  // The complete set of treeNodes that are processed
  std::map<uint64_t, TreeNodePtr> tree_nodes_;

  // The name of the fact output file.
  std::string facts_filename_;

  bool save_to_file_; // flag the indicates whether prolog facts should be written to a file

  bool save_facts_to_file(std::string& facts);

  void save_facts_private();

  void update_pointerness();

  void update_typename();

  const std::string select_typename(std::vector<std::string>& candidates);

  void update_signedness();

  void update_objectness();

  void recursively_assert_facts(TreeNodePtr tnp);

  void save_arch_facts(std::iostream &out_sstream);

  // Assert facts about the register width of the architecture. This
  // provides clues for pointerness.
  void assert_arch_fact();

  void assert_initial_facts(TreeNodePtr tnp);

  // Add the memory address facts
  void assert_memory_facts(TreeNodePtr tnp);

  // Assert facts for immediate values
  void assert_value_facts(TreeNodePtr tnp);

  // assert facts about types
  void assert_type_facts(typedb::TypeRef& ref);

  // assert facts concerning the size of tree nodes. The format of this fact is
  // (bitwidth HASH SIZE)
  void assert_bitwidth_fact(TreeNodePtr tnp);

  // Assert facts for function calls. These are tied to calls, not tree nodes
  void assert_function_call_parameter_facts(const CallDescriptor *cd);

  // Assert facts for global variables
  void assert_global_variable_facts();

  void assert_function_call_facts();

  void assert_local_variable_facts();

  void assert_objectness_facts(const CallDescriptor *cd);

  // Assert facts for function calls. These are tied to calls, not tree nodes
  void assert_api_facts(const CallDescriptor *cd);

  // Print the accumulated botwidth factsto a string stream. (bitwidth hash SIZE_VALUE)
  void save_bitwidth_facts(std::iostream &out_sstream);

  // Print the accumulated memory address facts to a string stream. The format is (memaddr hash)
  void save_memory_facts(std::iostream &out_sstream);

  // Print the accumulated memory address facts to a string stream. The format is (memaddr hash)
  void save_api_facts(std::iostream &out_sstream);

  // Print the accumulated function call facts to a string stream. The format is (memaddr hash)
  void save_function_call_facts(std::iostream &out_sstream);

  // Print the accumulated value facts (for numbers)to a string
  // stream. The format is (memaddr hash)
  void save_value_facts(std::iostream &out_sstream);

 public:

  TypeSolver(const DUAnalysis& du, const FunctionDescriptor* f);

  ~TypeSolver();

  bool generate_type_information(const std::map<TreeNode*,TreeNodePtr> &treenodes,
                                 const std::map<TreeNode*,TreeNodePtr> &memory_accesses);

  bool save_facts();

  void generate_type_descriptors();

  void set_output_file(std::string fn);

};

} // namespace pharos

#endif  // Pharos_Type_Descriptor_H
