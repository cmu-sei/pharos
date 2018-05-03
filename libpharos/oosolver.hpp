// Copyright 2016-2018 Carnegie Mellon University.  See LICENSE file for terms.
// Author: Cory Cohen

#ifndef Pharos_OOSolver_H
#define Pharos_OOSolver_H

#include <rose.h>
#include <Sawyer/ProgressBar.h>

#include "prolog.hpp"

namespace pharos {

// Forward declaration for add_rtti_facts() prototype.
class VirtualFunctionTable;
class OOClassDescriptor;
class OOSolver;

typedef std::shared_ptr<OOClassDescriptor> OOClassDescriptorPtr;

class OOSolverAnalysisPass {
 protected:
  std::string pass_name_;
 public:
  virtual bool solve(std::vector<OOClassDescriptorPtr>& classes)=0;
  virtual void set_name(std::string n);
  virtual std::string get_name();
};

// run a sequence of analysis passes
class OOSolverAnalysisPassRunner {
 private:
  OOSolver *solver_;
  std::vector< std::shared_ptr<OOSolverAnalysisPass> > passes_;
 public:
  OOSolverAnalysisPassRunner() : solver_(NULL) { }
  OOSolverAnalysisPassRunner(OOSolver *s) : solver_(s) { }
  void add_pass(std::shared_ptr<OOSolverAnalysisPass> p);
  void run();
};

class SolveClassesFromProlog : public OOSolverAnalysisPass {
 private:
  std::shared_ptr<prolog::Session> session_;
 public:
  SolveClassesFromProlog(std::shared_ptr<prolog::Session> s) : session_(s) {
    set_name("SolveClassesFromProlog");
  }
  virtual bool solve(std::vector<OOClassDescriptorPtr>& classes);
};

class SolveInheritanceFromProlog : public OOSolverAnalysisPass {
 protected:
  std::shared_ptr<prolog::Session> session_;
 public:
  SolveInheritanceFromProlog(std::shared_ptr<prolog::Session> s) : session_(s) {
    set_name("SolveInheritanceFromProlog");
  }
  virtual bool solve(std::vector<OOClassDescriptorPtr>& classes);
};

class SolveVFTableFromProlog : public OOSolverAnalysisPass {
 protected:
  std::shared_ptr<prolog::Session> session_;
 public:
  SolveVFTableFromProlog(std::shared_ptr<prolog::Session> s) : session_(s) {
    set_name("SolveVFTableFromProlog");
  }
  virtual bool solve(std::vector<OOClassDescriptorPtr>& classes);
};

class SolveMemberAccessFromProlog : public OOSolverAnalysisPass {
 protected:
  std::shared_ptr<prolog::Session> session_;
 public:
  SolveMemberAccessFromProlog(std::shared_ptr<prolog::Session> s) : session_(s) {
    set_name("SolveMemberAccessFromProlog");
  }
  virtual bool solve(std::vector<OOClassDescriptorPtr>& classes);
};

class SolveEmbeddedObjFromProlog : public OOSolverAnalysisPass {
 protected:
  std::shared_ptr<prolog::Session> session_;
 public:
  SolveEmbeddedObjFromProlog(std::shared_ptr<prolog::Session> s) : session_(s) {
    set_name("SolveEmbeddedObjFromProlog");
  }
  virtual bool solve(std::vector<OOClassDescriptorPtr>& classes);
};

class SolveMemberFromProlog : public OOSolverAnalysisPass {
 protected:
  std::shared_ptr<prolog::Session> session_;
 public:
  SolveMemberFromProlog(std::shared_ptr<prolog::Session> s) : session_(s) {
    set_name("SolveMemberFromProlog");
  }
  virtual bool solve(std::vector<OOClassDescriptorPtr>& classes);
};

class SolveMethodPropertyFromProlog : public OOSolverAnalysisPass {
 protected:
  std::shared_ptr<prolog::Session> session_;
 public:
  SolveMethodPropertyFromProlog(std::shared_ptr<prolog::Session> s) : session_(s) {
    set_name("SolveMethodPropertyFromProlog");
  }
  virtual bool solve(std::vector<OOClassDescriptorPtr>& clgasses);
};

class SolveResolvedVirtualCallFromProlog : public OOSolverAnalysisPass {
 protected:
  std::shared_ptr<prolog::Session> session_;
 public:
  SolveResolvedVirtualCallFromProlog(std::shared_ptr<prolog::Session> s) : session_(s) {
    set_name("SolveResolvedVirtualCallFromProlog");
  }
  virtual bool solve(std::vector<OOClassDescriptorPtr>& classes);
};

// End analysis/solve passes

// Forward declaration of OOAnalyzer
class OOAnalyzer;

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

  // list of created classes
  std::vector<OOClassDescriptorPtr> classes;

  // A list of addreses with exported facts (de-duplicates RTTI information).
  AddrSet visited;

  // Did the user request Prolog mode debugging?
  bool debugging_enabled;

  // Did the user request Prolog mode tracing?
  bool tracing_enabled;

  // Did the user request Prolog mode low-level tracing?
  bool low_level_tracing_enabled;

  // Did the user disable use of RTTI?
  bool ignore_rtti;

  // Did the user disable guessing?
  bool no_guessing;

  // Are we emitting facts just for debugging?
  bool debug_sv_facts;

  // This is a little hacky, but we need a way to disable the actual analysis for performance
  // reasons during testing.  So for now, if there's no output, then there's no analysis.
  bool perform_analysis;

  // Private implementation of add_facts() broken into several parts.
  void add_method_facts();
  void add_vftable_facts(OOAnalyzer& ooa);
  void add_rtti_facts(const VirtualFunctionTable* vft);
  void add_rtti_chd_facts(const rose_addr_t addr);
  void add_usage_facts(OOAnalyzer& ooa);
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

  bool analyze(OOAnalyzer& ooa);

  bool add_facts(OOAnalyzer& ooa);
  bool import_results();
  bool dump_facts();
  bool dump_results();
  std::vector<OOClassDescriptorPtr>& get_classes();
};

} // namespace pharos

#endif

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
