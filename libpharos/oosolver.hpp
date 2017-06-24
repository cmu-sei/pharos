// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.
// Author: Cory Cohen

#ifndef Pharos_OOSolver_H
#define Pharos_OOSolver_H

#include <rose.h>
#include <Sawyer/ProgressBar.h>

#include "prolog.hpp"

namespace pharos {

// Forward declaration for add_rtti_facts() prototype.
class VirtualFunctionTable;

// Object Oriented class detection Prolog solver.
class OOSolver {

private:

  using ProgressBar = Sawyer::ProgressBar<size_t, std::string>;
  static std::unique_ptr<ProgressBar> progress_bar;
  static int progress();

  // The Prolog session handle.
  std::shared_ptr<prolog::Session> session;

  // For dumping Prolog facts to files (if requested) for testing.
  std::string facts_filename;
  std::string results_filename;

  // A set of unique tree nodes representing this-pointers that
  // we should report relationships for.
  TreeNodePtrSet thisptrs;

  // A list of addreses with exported facts (de-duplicates RTTI information).
  AddrSet visited;

  // Private implementation of add_facts() broken into several parts.
  void add_method_facts();
  void add_vftable_facts();
  void add_rtti_facts(const VirtualFunctionTable* vft);
  void add_rtti_chd_facts(const rose_addr_t addr);
  void add_usage_facts();
  void add_call_facts();
  void add_thisptr_facts();
  void add_function_facts();
  void add_import_facts();
  // Private implementation of dump_facts() and dump_results().
  void dump_facts_private();
  void dump_results_private();

public:

  // Construction based on a user-supplied option.
  OOSolver(ProgOptVarMap& vm);
  ~OOSolver();

  bool analyze();

  bool add_facts();
  bool import_results();
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

