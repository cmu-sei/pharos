// Copyright 2016-2021 Carnegie Mellon University.  See LICENSE file for terms.
// Author: Cory Cohen

#ifndef Pharos_OOSolver_H
#define Pharos_OOSolver_H

#include <Sawyer/ProgressBar.h>

#include "prolog.hpp"

namespace pharos {

// Forward declaration for add_msvc_rtti_facts() prototype.
class VirtualFunctionTable;

// Forward declaration of OOAnalyzer
class OOAnalyzer;

struct TreeNodePtrHashCompare {
  bool operator()(const TreeNodePtr & a, const TreeNodePtr & b) const {
    if (!b) {
      return false;
    }
    if (!a) {
      return true;
    }
    return a->hash() < b->hash();
  }
};

// Object Oriented class detection Prolog solver.
class OOSolver {

 private:

  using ProgressBar = Sawyer::ProgressBar<size_t, std::string>;
  static std::unique_ptr<ProgressBar> progress_bar;
  static bool progress(prolog::Args args);

  // The Prolog session handle.
  std::shared_ptr<prolog::Session> session;

  // For dumping Prolog facts to files (if requested) for testing.
  std::string facts_filename;
  std::string results_filename;

  // A set of unique tree nodes representing this-pointers that we should report relationships
  // for.  This set has a custom comparator to prevent duplicate facts from being exported.
  std::set<TreeNodePtr, TreeNodePtrHashCompare> thisptrs;

  // Expanded treenodes; each of these turns into a thisPtrDefinition fact.
  struct ExpandedTreeNodePtr {
    TreeNodePtr ptr;
    rose_addr_t defaddr;
    rose_addr_t funcaddr;
    bool operator<(const ExpandedTreeNodePtr &other) const {
      return std::make_tuple (ptr->hash(), defaddr, funcaddr) < std::make_tuple (other.ptr->hash(), defaddr, other.funcaddr);
    }
  };
  std::set<ExpandedTreeNodePtr> expanded_thisptrs;

  // A list of addreses with exported facts (de-duplicates RTTI information).
  AddrSet visited;

  // Did the user request Prolog mode tracing?
  bool tracing_enabled;

  // Did the user disable use of RTTI?
  bool ignore_rtti;

  // Did the user disable guessing?
  bool no_guessing;

  // This is a little hacky, but we need a way to disable the actual analysis for performance
  // reasons during testing.  So for now, if there's no output, then there's no analysis.
  bool perform_analysis;

  // Location for json output
  boost::optional<std::string> json_path;

  // Private implementation of add_facts() broken into several parts.
  void add_method_facts(const OOAnalyzer& ooa);
  void add_vftable_facts(const OOAnalyzer& ooa);
  void add_msvc_rtti_facts(const VirtualFunctionTable* vft);
  void add_msvc_rtti_chd_facts(const rose_addr_t addr);
  void add_itanium_rtti_facts(const OOAnalyzer& ooa, const VirtualFunctionTable* vft);
  void add_itanium_typeinfo_facts(const OOAnalyzer& ooa, const rose_addr_t addr);
  void add_usage_facts(const OOAnalyzer& ooa);
  void add_call_facts(const OOAnalyzer& ooa);
  void add_thisptroffset_facts();
  void add_thisptrdefinition_facts();
  void add_function_facts(const OOAnalyzer& ooa);
  void add_import_facts(const OOAnalyzer& ooa);
  bool solve();

  // Private implementation of dump_facts() and dump_results().
  void dump_facts_private();

  void dump_results_private();

  DescriptorSet & ds;

 public:

  // Construction based on a user-supplied option.
  OOSolver(DescriptorSet & ds, const ProgOptVarMap& vm);
  ~OOSolver();

  bool analyze(const OOAnalyzer& ooa);

  bool add_facts(const OOAnalyzer& ooa);
  bool dump_facts();
  bool dump_results();
};

} // namespace pharos

#endif

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
