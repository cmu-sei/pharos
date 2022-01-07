// Copyright 2018-2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Bua_H
#define Pharos_Bua_H

#include "options.hpp"
#include <atomic>

namespace pharos {

// Forward declarations to reduce the header interdependencies.
class FunctionDescriptor;

class BottomUpAnalyzer {
 public:
  // Cory sees no reason not to make these public.  They're practically global.
  DescriptorSet & ds;
  ProgOptVarMap const & vm;

  BottomUpAnalyzer(DescriptorSet & ds_, ProgOptVarMap const & vm_);
  virtual ~BottomUpAnalyzer() = default;

  enum mode_t {
    SINGLE_THREADED,             // Call visit, single-threaded
    PDG_THREADED_VISIT_SINGLE,   // Calculate PDGs in parallel, then visit single-threaded
    PDG_THREADED_VISIT_THREADED, // Calculate PDGs in parallel, then visit multi-threaded
    MULTI_THREADED               // Call visit, multi-threaded
  };

  void set_mode(mode_t m) {
    mode = m;
  }

  // Call this method to do the actual work.
  void analyze();

  static Sawyer::Message::Facility & initDiagnostics();

  size_t processed_funcs = 0;

 protected:
  // Override this method which is called at the beginning of analyze()
  virtual void start();

  // Override this method which is called at the end of analyze()
  virtual void finish();

  // Override this method, with is invoked for each selected function in the appropriate bottom
  // up order.
  virtual void visit(FunctionDescriptor *fd);

 private:
  static Sawyer::Message::Facility mlog;

  mode_t mode = PDG_THREADED_VISIT_SINGLE;

};

// Function Dependency Graph
class FDG {
 public:
  using Graph = Sawyer::Container::Graph<FunctionDescriptor *, Sawyer::Nothing,
                                         FunctionDescriptor *>;
  FDG(DescriptorSet & ds);

  static FunctionDescriptor *indeterminate() { return indeterminate_; }
  static bool valid_descriptor(FunctionDescriptor const *fd) {
    return fd && fd != indeterminate();
  }

  Graph const & graph() const { return g_; }
  std::vector<FunctionDescriptor *> bottom_up_order() const;

 private:
  static FunctionDescriptor *indeterminate_;

  Graph g_;
};

} // namespace pharos

#endif // Pharos_Bua_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
