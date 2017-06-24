// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Descriptors_H
#define Pharos_Descriptors_H

#include <boost/iterator.hpp>
#include <rose.h>
#include <Partitioner2/Engine.h>

namespace P2 = Rose::BinaryAnalysis::Partitioner2;

namespace pharos {

typedef Rose::BinaryAnalysis::FunctionCall::Graph FCG;

// Some forward declarations of our classes.

class PDG;
class spTracker;
class APIDictionary;

} // namespace pharos

#include "funcs.hpp"
#include "calls.hpp"
#include "imports.hpp"
#include "util.hpp"
#include "globals.hpp"
#include "convention.hpp"
#include "options.hpp"

namespace pharos {

// For mapping the unique variable ids filled in by the loader back to the ImportDescriptor
// objects that describe those values.
typedef std::map<size_t, ImportDescriptor*> ImportVariableMap;
typedef std::map<rose_addr_t, SgAsmInstruction*> AddrInsnMap;

class DescriptorSet: public AstPreOrderTraversal
{

  CallDescriptorMap call_descriptors;
  FunctionDescriptorMap function_descriptors;
  ImportDescriptorMap import_descriptors;
  ImportVariableMap import_variables;
  GlobalMemoryDescriptorMap global_descriptors;
  CallingConventionMatcher calling_conventions;

  // These don't really belong here, but I want reading the program image to be globally
  // accessible, so this is the most convenient place for right now.
  SgAsmInterpretation *interp;
  MemoryMap::Ptr memmap;
  SgAsmGenericFile *file;
  spTracker * sp_tracker;

  // Arguments supplied to this descriptor set
  const ProgOptVarMap& vm;

  // The path to the objdigger library configuration directory.
  boost::filesystem::path lib_path;

  // The Function call graph of this program.
  FCG function_call_graph;

  // A map of addresses to instructions.
  AddrInsnMap insn_map;

  // Architecture word size in bytes.
  size_t arch_bytes;

  // I think that in the new Partitioner 2 world, it will be the most convenient to just have
  // access to the entire Partitioner 2 engine.  We'll eventually probably want to do things
  // like re-invoke the Partitioner to find additional code that might have been missed on the
  // first pass, or to eliminate things that were incorrect.  This pointer is usually a pointer
  // to a CERTEngine object, but it might be a pointer to a stock Partitioner engine (if the
  // user specified --stock, so some care is required when accessing custom extensions to the
  // class.  Hopefully we won't need to do that often.  This pointer is now entirely owned by
  // the descriptor set.
  P2::Engine* engine;

  // The partitioner is _created_ by the engine, but is not contained within it, so we have to
  // keep a copy of the partitioner in the descriptor set as well. Currently this is object is
  // locally allocated by the engine in create_partitioner() and copied into the object stored
  // here.
  P2::Partitioner partitioner;

  void do_update_vf_call_descriptors(CallType t);
  void init();

  void add_function_descriptor(SgAsmFunction * func);
  void add_function_descriptor(rose_addr_t addr, FunctionDescriptor && fd);
public:
  // The API database.
  std::unique_ptr<APIDictionary> apidb;

  // This is the intended (standard) way to construct a descriptor set.
  DescriptorSet(const ProgOptVarMap& povm);
  // Sadly tracesem.cpp expects to pass in it's interp due to some non-standardness in the way
  // that we've munged together ROSE code and Pharos code.
  DescriptorSet(const ProgOptVarMap& povm, SgAsmInterpretation *interp);
  // Wes' indexer program does something very non-standard that requires a function instead.
  DescriptorSet(const ProgOptVarMap& povm, SgAsmFunction *func);

  ~DescriptorSet();
  spTracker * get_spTracker() const;
  void update_connections();
  void validate(std::ostream &o);
  void update_vf_call_descriptors();
  void dump(std::ostream &o) const;
  void preOrderVisit(SgNode* n);

  const ProgOptVarMap& get_arguments() const {
    return vm;
  }

  // Read and write from property tree config files.
  void read_config();
  void read_config(std::string filename);
  void write_config(std::string filename);

  // Load stack deltas for imports.
  void resolve_imports();

  SgAsmInterpretation* get_interp() const { return interp; }
  CallDescriptorMap& get_call_map() { return call_descriptors; }
  FunctionDescriptorMap& get_func_map() { return function_descriptors; }
  ImportDescriptorMap& get_import_map() { return import_descriptors; }
  GlobalMemoryDescriptorMap& get_global_map() { return global_descriptors; }
  const CallingConventionMatcher& get_calling_conventions() const { return calling_conventions; }
  // Ensure that all imports in import_descriptors are also in import_variables.
  void add_import(ImportDescriptor id);

  FunctionDescriptorMap::iterator func_begin() { return function_descriptors.begin(); }
  FunctionDescriptorMap::iterator func_end() { return function_descriptors.end(); }

  // Allow others to benefit from our efforts on figuring out the correct library path.
  const boost::filesystem::path & get_library_path() const { return lib_path; }

  // return a filtered iterator using a supplied predicate
  CallDescriptorMap::filtered_iterator calls_filter_begin(CallDescMapPredicate predicate) {
    return CallDescriptorMap::filtered_iterator(predicate,
                                                call_descriptors.begin(),
                                                call_descriptors.end());
  }

  CallDescriptorMap::filtered_iterator calls_filter_end(CallDescMapPredicate predicate) {
    return CallDescriptorMap::filtered_iterator(predicate,
                                                call_descriptors.end(),
                                                call_descriptors.end());
  }

  ImportDescriptor* get_import(rose_addr_t a) { return import_descriptors.get_import(a); }
  ImportDescriptor* get_import_by_variable(SymbolicValuePtr v);
  FunctionDescriptor* get_func(rose_addr_t a) { return function_descriptors.get_func(a); }

  // Find the function descriptor that contains a given instruction.
  FunctionDescriptor* get_fd_from_insn(const SgAsmInstruction *insn);

  CallDescriptor* get_call(rose_addr_t a) { return call_descriptors.get_call(a); }
  GlobalMemoryDescriptor* get_global(rose_addr_t a) { return global_descriptors.get_global(a); }

  FCG& get_function_call_graph() { return function_call_graph; }
  FuncDescVector funcs_in_bottom_up_order();

  bool memory_initialized(rose_addr_t addr);
  bool memory_in_image(rose_addr_t addr);

  // Here's how you can get access to the new Partitioner 2 engine (maybe)...
  P2::Engine* get_engine() { return engine; }
  P2::Partitioner& get_partitioner() { return partitioner; }
  const RegisterDictionary* get_regdict();

  // These should really be on the MemoryMap...  and are a complete mess by current standards.
  // They should be accessible from the P2::Partitioner once we commit to that approach.
  inline void read_mem(rose_addr_t addr, char *buff, size_t size) {
    file->read_content(memmap, addr, buff, size, true); }

  // Return a pair of count of bits read and the resulting bitvector.  The vector will never be
  // null.  (Vector is passed as a pointer because it does not have working move semantics.)
  std::pair<size_t, std::unique_ptr<Sawyer::Container::BitVector>>
  read_addr_bits(rose_addr_t addr, size_t bits);

  rose_addr_t read_addr(rose_addr_t addr);

  // And this should really be on an instruction provider (from P2::Partitioner).
  SgAsmInstruction* get_insn(rose_addr_t addr) const;
  void add_insn(rose_addr_t addr, SgAsmInstruction* insn);

  // Return the default word size on the architecture.
  size_t get_arch_bytes() const { return arch_bytes; }
  size_t get_arch_bits() const { return arch_bytes * 8; }

  // Find a general purpose register in an semi-architecture independent way.
  const RegisterDescriptor* get_arch_reg(const std::string & name) const;
  // Find the stack pointer or instruction pointer register in an architecture independent way.
  const RegisterDescriptor get_stack_reg() const;
  const RegisterDescriptor get_ip_reg() const;

};

extern DescriptorSet* global_descriptor_set;

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
