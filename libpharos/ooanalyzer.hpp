// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_OOAnalyzer_H
#define Pharos_OOAnalyzer_H

#include "descriptors.hpp"
#include "options.hpp"

class OOAnalyzer : public BottomUpAnalyzer {

private:
  // A list of hashes known to be new() methods.  This should really be read from a JSON config
  // file or something, but for now, we'll just initialize it manually.
  StringSet new_hashes;

  // A list of addresses of known new() methods.  Derived from new_hashes and imports.
  AddrSet new_addrs;

  // The number of new() methods found.
  int new_methods_found;

  timespec start_ts;

  // Initialize the list of known new() methods with some well-known hashes.
  void initialize_new_hashes();
  // Find new methods by examining imports.
  void find_imported_new_methods();
  // Find delete methods by examining imports.
  void find_imported_delete_methods();

public:

  OOAnalyzer(DescriptorSet* ds_, ProgOptVarMap& vm_, AddrSet& new_addrs_);
  void visit(FunctionDescriptor* fd);
  void finish();
};

class RecursiveMethodAnalyzer : public BottomUpAnalyzer {

public:
  RecursiveMethodAnalyzer(DescriptorSet* ds_, ProgOptVarMap& vm_);
  void visit(FunctionDescriptor* fd);
  void finish();
};

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
