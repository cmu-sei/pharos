// Copyright 2018-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include "bua.hpp"
#include "descriptors.hpp"
#include "options.hpp"

#include <Sawyer/ProgressBar.h>
#include <Sawyer/ThreadWorkers.h>
#include <Sawyer/GraphTraversal.h>
#include <Sawyer/GraphAlgorithm.h>
#include <Sawyer/GraphIteratorSet.h>
#include <boost/range/adaptor/map.hpp>

#include <atomic>

#define PHAROS_BUA_TESTING 0

namespace pharos {

namespace {

struct ProgressSuffix {
  size_t * total = nullptr;
  ProgressSuffix() {}
  ProgressSuffix(size_t & t): total(&t) {}
  void print(std::ostream &o) const {
    if (total) {
      o << "/" << total;
    }
  }
};

std::ostream& operator<<(std::ostream &o, const ProgressSuffix &suffix) {
  suffix.print(o);
  return o;
}

} // unnamed namespace

Sawyer::Message::Facility BottomUpAnalyzer::mlog;

BottomUpAnalyzer::BottomUpAnalyzer(DescriptorSet & ds_, ProgOptVarMap const & vm_)
  : ds(ds_), vm(vm_)
{}

// The default visitor simply computes the PDG and returns.
void BottomUpAnalyzer::visit(FunctionDescriptor *fd) {
  fd->get_pdg();
}

// The default start is a NOP.
void BottomUpAnalyzer::start() {
  GDEBUG << "Starting bottom up function analysis." << LEND;
}

// The default finish is a NOP.
void BottomUpAnalyzer::finish() {
  GDEBUG << "Finishing bottom up function analysis." << LEND;
}


static std::atomic_flag mlog_initialized = ATOMIC_FLAG_INIT;
Sawyer::Message::Facility & BottomUpAnalyzer::initDiagnostics()
{
  if (!mlog_initialized.test_and_set()) {
    mlog.initialize("BUAD");
    mlog.initStreams(get_logging_destination());
    Sawyer::Message::mfacilities.insert(mlog);
  }
  return mlog;
}

void BottomUpAnalyzer::analyze() {
  // User overridden start() method.
  start();

  auto const level = ds.get_concurrency_level();
  if (level == 1) {
    mode = SINGLE_THREADED;
  }

  AddrSet const selected_funcs = get_selected_funcs (ds, vm);
  size_t const total_funcs = selected_funcs.size();
  processed_funcs = 0;

  FDG fdg{ds};

  // Function to determine whether a function is to be included in the analysis
  auto included = [&selected_funcs](FunctionDescriptor const * fd) {
    if (!FDG::valid_descriptor(fd)) {
      return false;
    }
    if (selected_funcs.find(fd->get_address()) == selected_funcs.end()) {
      GTRACE << "Function " << fd->address_string() << " excluded" << LEND;
      return false;
    }
    return true;
  };

  // Function to create the PDG for a function
  auto get_pdg = [&mlog = this->mlog, &included](size_t, FunctionDescriptor const *fd) {
    if (included(fd)) {
      MDEBUG << "Starting PDG generation for function " << fd->address_string() << LEND;
      auto timer = make_timer();
      fd->get_pdg();
      timer.stop();
      MDEBUG << "Finished PDG generation for function " << fd->address_string()
             << " in " << timer << " seconds." << LEND;
    }
  };

  // Function that calls visit
  auto visit_func = [this, &included](size_t, FunctionDescriptor *fd) {
    if (included(fd)) {
      assert(fd);
      GDEBUG << "Visiting function " << fd->address_string() << LEND;
      // Visit the function.
      auto timer = make_timer();
      visit(fd);
      timer.stop();
      ++processed_funcs;
      GDEBUG << "Finished visiting function " << fd->address_string() << " in "
             << timer << " seconds." << std::endl;
    }
  };

  // Fun function across function descriptors in parallel, with progress bar
  auto run_in_parallel = [&fdg, level, total_funcs](
    auto func, std::string const & title)
  {
    Sawyer::ProgressBar<size_t, ProgressSuffix> progress(
      total_funcs, olog[Sawyer::Message::MARCH], title);
    auto process = [&func, &progress](size_t s, FunctionDescriptor * fd) {
      func(s, fd);
      ++progress;
    };
    Sawyer::workInParallel(fdg.graph(), level, process);
  };

  switch (mode) {
   case PDG_THREADED_VISIT_SINGLE:
    run_in_parallel(get_pdg, "Function PDG analysis");
    // fallthrough
   case SINGLE_THREADED:
    {
      auto ordered_funcs = fdg.bottom_up_order();
      Sawyer::ProgressBar<size_t, ProgressSuffix> progress(
        total_funcs, olog[Sawyer::Message::MARCH], "Function analysis");
      for (FunctionDescriptor* fd : ordered_funcs) {
        visit_func(0, fd);
        ++progress;
      }
    }
    break;
   case PDG_THREADED_VISIT_THREADED:
    run_in_parallel(get_pdg, "Function PDG analysis");
    // fallthrough
   case MULTI_THREADED:
    run_in_parallel(visit_func, "Function analysis");
    break;
  }
  if (total_funcs != processed_funcs) {
    GERROR << "Found only " << processed_funcs << " functions of "
           << total_funcs << " specifically requested for analysis." << LEND;
  }

  // User overridden finish() method.
  finish();
}

FunctionDescriptor * FDG::indeterminate_{
  reinterpret_cast<FunctionDescriptor *>(&FDG::indeterminate_)};

FDG::FDG(DescriptorSet & ds)
{
  // For the V_ constants
  using namespace Rose::BinaryAnalysis::Partitioner2;

  // Get a function descriptor from an address
  auto func = [&ds](auto fn) {
    return ds.get_rw_func(fn->address());
  };

  // Add all functions to the graph
  for (auto & fn : boost::adaptors::values(ds.get_func_map())) {
    g_.insertVertex(ds.get_rw_func(fn.get_address()));
  }

  // Add an indeterminate node to the graph
  auto indeterminate_iter = g_.insertVertex(indeterminate());

  auto insert_edge = [this](auto start, auto tgt) {
    auto vs = g_.insertVertexMaybe(start);
    auto vt = g_.insertVertexMaybe(tgt);
    for (auto & oe : vs->outEdges()) {
      if (oe.target()->id() == vt->id()) {
        return;
      }
    }
    g_.insertEdge(vs, vt);
  };

  // Get the partitioner
  auto & p = ds.get_partitioner();
  // Get the partitioner's CFG
  auto & pcfg = p.cfg();

  // For each edge in the cfg
  for (auto & edge : pcfg.edges()) {
    // If the edge is from a basic block
    if (edge.source()->value().type() == V_BASIC_BLOCK) {

      // Based on the type of the target of the edge
      switch (edge.target()->value().type()) {
       case V_BASIC_BLOCK:
        // If it's a basic block, add an edge to our graph for each function/function pair that
        // those basic blocks are in
        for (auto & source : edge.source()->value().owningFunctions().values()) {
          auto s = func(source);
          if (s) {
            for (auto & target : edge.target()->value().owningFunctions().values()) {
              if (source != target || edge.value().type() == E_FUNCTION_CALL
                  || edge.value().type() == E_FUNCTION_XFER)
              {
                auto t = func(target);
                if (t) {
                  insert_edge(s, t);
                }
              }
            }
          }
        }
        break;
       case V_INDETERMINATE:
        // If it's the indeterminate not, add an edge to our indeterminate node
        for (auto & source : edge.source()->value().owningFunctions().values()) {
          auto s = func(source);
          if (s) {
            insert_edge(s, indeterminate());
          }
        }
        break;
       default:
        break;
      }
    }
  }

  // Find the set of vertices that can reach the indeterminate node.  Do this by doing a
  // reverse depth first search from the indeterminate node, accumulating the vertices reached.
  auto traversal = Sawyer::Container::Algorithm::DepthFirstReverseVertexTraversal<Graph>{
    g_, indeterminate_iter};
  Sawyer::Container::GraphIteratorSet<Graph::VertexIterator> not_simple;
  traversal.mapVertices([&not_simple](auto v) { not_simple.insert(v); });

  // Connect the indeterminate node to all simple nodes that have no non-simple predecessors.
  auto is_simple = [&not_simple](auto vertex) {
    return !not_simple.exists(vertex);
  };
  auto vertices = g_.vertices();
  using std::begin;
  using std::end;
  for (auto v = begin(vertices); v != end(vertices); ++v) {
    if (is_simple(v)
        && std::none_of(begin(v->inEdges()), end(v->inEdges()),
                        [&is_simple](auto & e){ return is_simple(e.source()); }))
    {
      g_.insertEdge(indeterminate_iter, v);
    }
  }

  // Break any cycles remaining
  Sawyer::Container::Algorithm::graphBreakCycles(g_);
}

std::vector<FunctionDescriptor *> FDG::bottom_up_order() const
{
  std::vector<FunctionDescriptor *> result;

  // Copy the graph
  Graph g{graph()};

  // While the graph is not empty...
  while (!g.isEmpty()) {
    std::vector<Graph::VertexIterator> to_erase;
    auto vertices = g.vertices();

    // Build a list of vertices that have no outgoing edges, and add them to the result vector
    using std::end;
    using std::begin;
    for (auto v = begin(vertices); v != end(vertices); ++v) {
      if (v->nOutEdges() == 0) {
        to_erase.push_back(v);
        if (valid_descriptor(v->value())) {
          result.push_back(v->value());
        }
      }
    }

    // Then remove those vertices from the graph
    assert(!to_erase.empty());
    for (auto v : to_erase) {
      g.eraseVertex(v);
    }
  }

  return result;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
