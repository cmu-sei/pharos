// Copyright 2018-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <map>
#include <vector>
#include <numeric>

#include <boost/range/adaptor/map.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/topological_sort.hpp>
#include <boost/filesystem.hpp>

#include <libpharos/rose.hpp>
#include <Rose/BinaryAnalysis/Partitioner2/Partitioner.h>

// For the main pharos infastructure that tracks functions.
#include <libpharos/descriptors.hpp>
// For IR
#include <libpharos/ir.hpp>

// For Z3 stuff...
#include <libpharos/path.hpp>

using namespace pharos;
using namespace pharos::ir;

namespace po = boost::program_options;
namespace bf = boost::filesystem;

std::ostream* getOStream(boost::optional<bf::path> dotdir, std::ofstream* filestream, std::string filename) {
  if (dotdir) {
    bf::path filepath = bf::path(*dotdir) /= filename;
    filestream->exceptions (~std::ofstream::goodbit);
    filestream->open (filepath.native(), std::ofstream::out);
    return filestream;
  }
  else return &std::cout;
}

static int mkir_main(int argc, char **argv)
{
  ProgOptDesc mkiropt("mkir options");
  mkiropt.add_options()
    ("dot,d", po::value<bf::path>(), "directory to write graphviz file(s) instead of stdout");
  mkiropt.add (cert_standard_options ());
  ProgOptVarMap vm = parse_cert_options(argc, argv, mkiropt);

  DescriptorSet ds(vm);

  const FunctionDescriptorMap& fdmap = ds.get_func_map();

  std::string arch_name = ds.get_arch_name();
  //if (arch_name != "i386" && arch_name != "amd64") {
  //  GFATAL << "This tool requires 'i386' or 'amd64' architecture." << LEND;
  //  return(1);
  //}

  std::map<rose_addr_t, FunctionDescriptor const *> selected_fdmap;
  auto selected_funcs = get_selected_funcs (ds, vm);

  std::transform (selected_funcs.begin (), selected_funcs.end (),
                  std::inserter (selected_fdmap, selected_fdmap.begin()),
                  [&fdmap] (rose_addr_t addr) {
                    auto kv = fdmap.find (addr);
                    assert(kv != fdmap.end());
                    return std::make_pair(kv->first, &kv->second);
                  });

  boost::optional<bf::path> dotdir;
  if (vm.count ("dot")) {
    dotdir = vm["dot"].as<bf::path>();

    if (bf::exists (*dotdir)) {
      if (bf::is_directory (*dotdir)) {
        // already exists
      } else {
        throw std::invalid_argument ("dot directory is not a directory");
      }
    }
    else {
      bf::create_directory (*dotdir);
    }
  }

  // First write the callgraph out
  CG cg = CG::get_cg (ds);

  // only write the callgraph if the user doesn't specify any functions
  if (vm.count ("func") == 0) {
    std::ofstream filestream;
    std::cout << "Writing the CG" << std::endl;
    std::ostream *out = getOStream(dotdir, &filestream, std::string ("callgraph.dot"));
    *out << cg;
  }

  for (auto & p : selected_fdmap) {
    FunctionDescriptor const & fd = *p.second;
    rose_addr_t addr = p.first;

    // Get the control flow graph.
    IR ir = IR::get_ir (&fd);

    std::cout << "Writing CFG for function " << std::hex << addr << std::dec << std::endl;

    // Set the ostream
    std::ofstream filestream;
    //filestream.exceptions (~std::ofstream::goodbit);
    std::stringstream filename;
    filename << std::hex << addr << ".dot";
    std::ostream *out = getOStream(dotdir, &filestream, filename.str ());

    // Write the CFG to disk
    *out << ir;
  }

  return 0;
}

int main(int argc, char* argv[]) {
  return pharos_main("MKIR", mkir_main, argc, argv);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
