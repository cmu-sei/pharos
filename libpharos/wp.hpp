// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Wp_H
#define Pharos_Wp_H

#include "ir.hpp"

using namespace pharos::ir;

namespace pharos {
  IRExprPtr wp_cfg(const IR& prog, const IRExprPtr& post);

  IRExprPtr expand_lets (const IRExprPtr& expr);

  // This function adds a new (or optionally specified) hit_var that
  // is set to true whenever the specified targets are hit.  Returns
  // the instrumented IR, the hit variable, and the vertices
  // containing hits.
  std::tuple<IR, IRExprPtr, std::set<IRCFGVertex>> add_reached_postcondition (const IR& ir,
                                                                            const std::set<rose_addr_t> targets,
                                                                            boost::optional<Register> hit_var = boost::none);

  // This is a helper function that identifies calls to selected
  // external functions and replaces them with a write of EAX with a
  // fresh symbolic variable.
  IR rewrite_imported_calls (const DescriptorSet& ds, IR& prog, const ImportRewriteSet& funcs);
}

#endif
