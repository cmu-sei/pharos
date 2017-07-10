// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.
// Author: Jeff Gennari

#ifndef Pharos_Type_Descriptor_H
#define Pharos_Type_Descriptor_H

#include <vector>
#include <rose.h>

#include "misc.hpp" // Needed mainly for the typedefs to avoid crazy long names
#include "util.hpp"
#include "prolog.hpp"
#include "options.hpp"
#include "typedb.hpp"

namespace pharos {

namespace types {

// The top of the bitwidth lattice. Clearly this is not a proper
// lattice, but it serves its purpose. In reality the bitwidth is
// fairly easy to determine by looking at underlying treenodes
const size_t BitwidthTop = SIZE_MAX;

// The "top" of the type name lattice really means that we know
// nothing about type name; i.e. it is unknown
const std::string TypenameTop = "<unknown>";

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

  void to_facts(TreeNodePtr tn, std::shared_ptr<prolog::Session> session);

  std::string to_string();

  void set_name(std::string n) {
    type_name_ = n;
  }
  std::string get_name() const {
    return type_name_;
  }

  // TypeDescriptor properties

  void bit_width(size_t bw);
  size_t bit_width() const;

  void is_pointer();
  void not_pointer();
  void bottom_pointer();

  types::Pointerness Pointerness() const;

  void is_signed();
  void not_signed();
  void bottom_signed();
  types::Signedness Signedness() const;

}; // TypeDescriptor

   // shared pointer to a TypeDescriptor
typedef boost::shared_ptr< TypeDescriptor > TypeDescriptorPtr;

// Utility functions to fetch type descriptors from tree nodes. Note
// that this method will create a default type descriptor if one isn't
// found
TypeDescriptorPtr fetch_type_descriptor(TreeNodePtr tnp);

// returns true if a tree node has a type descriptor
bool has_type_descriptor(TreeNodePtr tnp);


// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
//
// This is the strategy interface for different commands. Every command must over-ride
// this interface
class OperationStrategy {
 protected:

  // operand name
  std::string op_name_;

 public:

  // The name of the operation; to be defined by extending classes
  const std::string& get_op_name() const;

  // Every strategy for analyzing types must implement this function. The InternalNodePtr
  // in is the (operation) tree node being processed. The session is an active
  // prolog session.
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session)=0;

  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream)=0;

  // Must have a virtual destructor to ensure proper destructor called.
  virtual ~OperationStrategy() { }
};

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
// The concrete strategy definition - shouldn't have to touch these unless they are
// being added to or removed from
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

class SextendStrategy : public OperationStrategy {
 public:
  SextendStrategy() { op_name_ = "opSextend";  }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~SextendStrategy() { }
};

class UextendStrategy : public OperationStrategy {
 public:
  UextendStrategy() { op_name_ = "opUextend"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~UextendStrategy() { }
};

class AddStrategy : public OperationStrategy {
 public:
  AddStrategy() { op_name_ = "opAdd"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~AddStrategy() { }
};

class BvAndStrategy : public OperationStrategy {
 public:
  BvAndStrategy() { op_name_ = "opBvAnd"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~BvAndStrategy() { }
};

class AndStrategy : public OperationStrategy {
 public:
  AndStrategy() { op_name_= "opAnd"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~AndStrategy() { }
};

class SmulStrategy : public OperationStrategy {
 public:
  SmulStrategy() { op_name_ = "opSmul"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~SmulStrategy() { }
};

class UmulStrategy : public OperationStrategy {

 public:
  UmulStrategy() { op_name_ = "opUmul"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~UmulStrategy() { }
};

class AsrStrategy : public OperationStrategy {
 public:
  AsrStrategy() { op_name_ = "opAsr"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~AsrStrategy() { }
};

class BvXorStrategy : public OperationStrategy {
 public:
  BvXorStrategy() { op_name_ = "opBvXor"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~BvXorStrategy() { }
};

class ConcatStrategy : public OperationStrategy {
 public:
  ConcatStrategy() { op_name_ = "opConcat"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~ConcatStrategy() { }
};

class EqStrategy : public OperationStrategy {
 public:
  EqStrategy() { op_name_ = "opEq"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~EqStrategy() { }
};

class ExtractStrategy : public OperationStrategy {
 public:
  ExtractStrategy() { op_name_ = "opExtract"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~ExtractStrategy() { }
};

class InvertStrategy : public OperationStrategy {
 public:
  InvertStrategy() { op_name_ = "opInvert"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~InvertStrategy() { }
};

class IteStrategy : public OperationStrategy {
 public:
  IteStrategy() { op_name_ = "opIte"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~IteStrategy() { }
};

class LssbStrategy : public OperationStrategy {
 public:
  LssbStrategy() { op_name_ = "opLssb"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~LssbStrategy() { }
};

class MssbStrategy : public OperationStrategy {
 public:
  MssbStrategy() { op_name_ = "opMssb"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~MssbStrategy() { }
};

class NeStrategy : public OperationStrategy {
 public:
  NeStrategy() { op_name_ = "opNe"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~NeStrategy() { }
};

class NegateStrategy : public OperationStrategy {
 public:
  NegateStrategy() { op_name_ = "opNegate"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~NegateStrategy() { }
};

class NoopStrategy : public OperationStrategy {
 public:
  NoopStrategy() { op_name_ = "opNoop"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~NoopStrategy() { }
};

class BvOrStrategy : public OperationStrategy {
 public:
  BvOrStrategy() { op_name_ = "opBvOr"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~BvOrStrategy() { }
};

class OrStrategy : public OperationStrategy {
 public:
  OrStrategy() { op_name_ = "opOr"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~OrStrategy() { }
};

class ReadStrategy : public OperationStrategy {
 public:
  ReadStrategy() { op_name_ = "opRead"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~ReadStrategy() { }
};

class RolStrategy : public OperationStrategy {
 public:
  RolStrategy() { op_name_ = "opRol"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~RolStrategy() { }
};

class RorStrategy : public OperationStrategy {
 public:
  RorStrategy() { op_name_ = "opRor"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~RorStrategy() { }
};

class SdivStrategy : public OperationStrategy {
 public:
  SdivStrategy() { op_name_ = "opSdiv"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~SdivStrategy() { }
};

class UdivStrategy : public OperationStrategy {
 public:
  UdivStrategy() { op_name_ = "opUdiv"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~UdivStrategy() { }
};

class SetStrategy : public OperationStrategy {
 public:
  SetStrategy() { op_name_ = "opSet"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~SetStrategy() { }
};

class SgeStrategy : public OperationStrategy {
 public:
  SgeStrategy() { op_name_ = "opSge"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~SgeStrategy() { }
};

class SgtStrategy : public OperationStrategy {
 public:
  SgtStrategy() { op_name_ = "opSgt"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~SgtStrategy() { }
};

class Shl0Strategy : public OperationStrategy {
 public:
  Shl0Strategy() { op_name_ = "opShl0"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~Shl0Strategy() { }
};

class Shl1Strategy : public OperationStrategy {
 public:
  Shl1Strategy() { op_name_ = "opShl1"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~Shl1Strategy() { }
};

class Shr0Strategy : public OperationStrategy {
 public:
  Shr0Strategy() { op_name_ = "opShr0"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~Shr0Strategy() { }
};

class Shr1Strategy : public OperationStrategy {
 public:
  Shr1Strategy() { op_name_ = "opShr1"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~Shr1Strategy() { }
};

class SleStrategy : public OperationStrategy {
 public:
  SleStrategy() { op_name_ = "opSle"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~SleStrategy() { }
};

class SltStrategy : public OperationStrategy {
 public:
  SltStrategy() { op_name_ = "opSlt"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~SltStrategy() { }
};

class SmodStrategy : public OperationStrategy {
 public:
  SmodStrategy() { op_name_ = "opSmod"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~SmodStrategy() { }
};

class UmodStrategy : public OperationStrategy {
 public:
  UmodStrategy() { op_name_= "opUmod";  }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~UmodStrategy() { }
};

class UgeStrategy : public OperationStrategy {
 public:
  UgeStrategy() { op_name_ = "opUge"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~UgeStrategy() { }
};

class UgtStrategy : public OperationStrategy {
 public:
  UgtStrategy() { op_name_ = "opUgt"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~UgtStrategy() { }
};

class UleStrategy : public OperationStrategy {
 public:
  UleStrategy() { op_name_ = "opUle"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~UleStrategy() { }
};

class UltStrategy : public OperationStrategy {
 public:
  UltStrategy() { op_name_ = "opUlt"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~UltStrategy() { }
};

class WriteStrategy : public OperationStrategy {
 public:
  WriteStrategy() { op_name_ = "opWrite"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~WriteStrategy() { }
};

class ZeropStrategy : public OperationStrategy {
 public:
  ZeropStrategy() { op_name_ = "opZerop"; }
  virtual void save_facts(std::shared_ptr<prolog::Session> session, std::iostream& out_sstream);
  virtual void assert_facts(InternalNodePtr in, std::shared_ptr<prolog::Session> session);
  virtual ~ZeropStrategy() { }
};

// The context that sets the strategy for operation analysis. The context is used
// to select and eecute a given strategy
class OperationContext {

 private:

  // Map of RISC operation strategies
  std::map<Rose::BinaryAnalysis::SymbolicExpr::Operator, OperationStrategy*> strategies_;

 public:

  ~OperationContext();

  // The constructor for the context installs the available strategies, which are
  // basically one per RISC op
  OperationContext();

  // Analyze the operations by selecting and executing the strategy based on RISC
  // operator
  void assert_operation_fact(Rose::BinaryAnalysis::SymbolicExpr::Operator op,
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

  void update_signedness();

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

  // assert facts concerning the size of tree nodes. The format of this fact is
  // (bitwidth HASH SIZE)
  void assert_bitwidth_fact(TreeNodePtr tnp);

  // Assert facts for function calls. These are tied to calls, not tree nodes
  void assert_function_call_facts(const CallDescriptor *cd);

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
