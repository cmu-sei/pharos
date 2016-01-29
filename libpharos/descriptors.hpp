// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Descriptors_H
#define Pharos_Descriptors_H

#include <boost/iterator.hpp>
#include <rose.h>

typedef rose::BinaryAnalysis::FunctionCall::Graph FCG;

// Some forward declarations of our classes.

class PDG;
class spTracker;

#include "funcs.hpp"
#include "calls.hpp"
#include "imports.hpp"
#include "util.hpp"
#include "globals.hpp"
#include "convention.hpp"
#include "options.hpp"

#define DEFAULT_LIB "/data/shared/research/pharos"

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
  MemoryMap *memmap;
  SgAsmGenericFile *file;
  spTracker * sp_tracker;

  // Arguments supplied to this descriptor set
  ProgOptVarMap *vm;

  // The path to the objdigger library configuration directory.
  std::string lib_path;

  // The Function call graph of this program.
  FCG function_call_graph;

  // A map of addresses to instructions.
  AddrInsnMap insn_map;

  // We should really be using an instruction provider instead of the map, but this in
  // inconvenient right now.   See comments in misc.cpp where we create the partitioners.
  // rose::BinaryAnalysisInstructionProvider* instruction_provider;

  void do_update_vf_call_descriptors(CallType t);
public:
  DescriptorSet(SgAsmInterpretation *i, ProgOptVarMap *povm = NULL);
  DescriptorSet(SgAsmFunction *func, ProgOptVarMap *povm = NULL);

  ~DescriptorSet();
  spTracker * get_spTracker() const;
  void update_connections();
  void validate(std::ostream &o);
  void update_vf_call_descriptors();
  void dump(std::ostream &o);
  void preOrderVisit(SgNode* n);

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

  // These should really be on the MemoryMap...
  inline void read_mem(rose_addr_t addr, char *buff, size_t size) {
    file->read_content(memmap, addr, buff, size, true); }
  rose_addr_t read32(rose_addr_t addr);

  // And this should really be on an instruction provider...
  SgAsmInstruction* get_insn(rose_addr_t addr) const;
  void add_insn(rose_addr_t addr, SgAsmInstruction* insn);
};

extern DescriptorSet* global_descriptor_set;

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
