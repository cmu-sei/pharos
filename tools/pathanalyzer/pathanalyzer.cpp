// Copyright 2018-2023 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/range/adaptor/map.hpp>
#include <libpharos/options.hpp>
#include <libpharos/funcs.hpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/pdg.hpp>
#include <libpharos/defuse.hpp>
#include <libpharos/path.hpp>
#include <libpharos/bua.hpp>

#include <Sawyer/GraphBoost.h>
#include <boost/filesystem.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/algorithm/string/replace.hpp>

const std::string VERSION  = "0.3";

typedef Rose::BinaryAnalysis::ControlFlow::Graph CFG;

namespace bf = boost::filesystem;

using namespace pharos;

struct PathEdgeWriter {
 private:
  PathPtr path_;
 public:
  PathEdgeWriter(PathPtr p) : path_(p) { }

  void operator()(std::ostream &output, const CfgEdge &e) {

    for (auto einfo : path_->traversal) {
      if (einfo.edge == e) {
        output << "[color=green, penwidth=2.0]";
      }
    }
  }
};

struct PathGraphWriter {
 private:
  std::string label_;
 public:
  PathGraphWriter(std::string label) : label_(label) {  }

  void operator()(std::ostream &output) {

    output << "graph [nojustify=true,fontname=courier]\n";
    output << "node [shape=box, style=\"rounded,filled\",fontname=courier]\n";

    std::string gv_label = boost::replace_all_copy(label_,"\n", "\\l");

    output << "label=\"" << std::setw(80) << std::setfill('=') << "\n"
           << gv_label << "\"\n";
  }
};

struct PathVertexWriter {
 private:
  const FunctionDescriptor& fd_;
  rose_addr_t goal_address_, start_address_;

 public:
  PathVertexWriter(const FunctionDescriptor &fd,
                   rose_addr_t start,
                   rose_addr_t goal)
    : fd_(fd), goal_address_(goal), start_address_(start) { }

  void operator()(std::ostream &output, const CfgVertex &v) {

    const CFG& cfg = fd_.get_pharos_cfg();
    SgAsmBlock* vtx_bb = isSgAsmBlock(boost::get(boost::vertex_name, cfg, v));

    if (!vtx_bb) return;

    // The CFG is displayed in terms of Basic blocks, so we have to
    // label vertices based on containing

    P2::BasicBlockPtr goal_bb = fd_.ds.get_block(goal_address_);

    bool is_goal=false, is_start=false;

    if (goal_bb) {
      if (vtx_bb->get_address() == goal_bb->address()) {
        is_goal = true;

      }
    }

    P2::BasicBlockPtr start_bb = fd_.ds.get_block(start_address_);

    if (start_bb) {
      if (vtx_bb->get_address() == start_bb->address()) {
        is_start = true;
      }
    }
    output << "[label=\""
           << addr_str(vtx_bb->get_address())
           << "\"";

    if (is_goal) {
      output << ", color=red";
    }
    if (is_start) {
      output << ", color=green";
    }
    output << "]";
  }
};

class PathAnalyzer : public BottomUpAnalyzer {

 private:
  std::string exe_file_name_, dot_output_dir_, z3_file_;
  bool save_graphviz_, save_z3_;
  rose_addr_t goal_address_, start_address_;
  PathFinder path_finder_;

  // Generate the proper DOT files in the output directory
  void
  save_graphviz_file() {

    bf::path exe_name(exe_file_name_);

    const PathPtrList& path = path_finder_.get_path();

    std::stringstream output_msg;
    output_msg << "There are " << path.size()
               << " functions between the start and tho goal:"
               << path_finder_.get_goal_addr() << std::dec
               << "\n";

    for (PathPtr traversal : path) {
      if (traversal && traversal->call_trace_desc) {

        const FunctionDescriptor& fd = traversal->call_trace_desc->get_function();
        std::stringstream dot_ss;
        dot_ss << dot_output_dir_
               << bf::path::preferred_separator
               << exe_name.stem().string() << "-"
               << std::hex
               << fd.get_address() << "-" << traversal->call_trace_desc->get_index()
               << std::dec
               << ".dot";

        std::ofstream dot_fstream(dot_ss.str().c_str());

        boost::write_graphviz(dot_fstream,
                              fd.get_pharos_cfg(),
                              PathVertexWriter(fd,
                                               path_finder_.get_start_addr(),
                                               path_finder_.get_goal_addr()),
                              PathEdgeWriter(traversal),
                              PathGraphWriter(to_string()));

        output_msg << " * created DOT file: " <<  dot_ss.str() << "\n";
        dot_fstream.close();

      }
      else {
        output_msg << "Error: Invalid traversal, cannot generate DOT file\n";
      }
    }
    std::cout << output_msg.str() << std::endl;
  }

  // Format the call trace as a string
  std::string to_string() {

    std::stringstream ss;
    Rose::BinaryAnalysis::SymbolicExpression::Formatter fmt;
    fmt.use_hexadecimal = false;
    fmt.show_type = false;
    fmt.show_flags = false;

    const PathPtrList& path = path_finder_.get_path();
    unsigned count=0;

    for (PathPtr traversal : path) {
      if (traversal && traversal->call_trace_desc) {

        CallTraceDescriptorPtr & ctd = traversal->call_trace_desc;

        ss << "Call trace element [" << ctd->get_index() << "]\n";
        ss << "Function: " << addr_str(ctd->get_function().get_address()) << "\n";
        if (ctd->get_call())
          ss << "Called from: " << addr_str(ctd->get_call()->get_address()) << "\n";
        else
          ss << "Starting point: " << addr_str(start_address_) <<"\n";

        if (traversal->required_stkvar_values.size() > 0) {

          ss << "Stack variables:\n";

          // If there are concrete stack variables used, report them
          for (ConcreteStackVariable const & csv : traversal->required_stkvar_values) {
            StackVariable const & stkvar = csv.element;
            boost::uint64_t stkvar_val = csv.concrete_value;
            TreeNodePtr stkvar_memaddr_tnp = stkvar.get_memory_address()->get_expression();
            ss << "   ";
            stkvar_memaddr_tnp->print(ss, fmt);
            ss << " = " << stkvar_val
               << " (" << static_cast<int>(stkvar_val) << ")\n";
          }
        }
        if (traversal->required_param_values.size() > 0) {
          ss << "Input parameters:\n";

          // If there are concrete stack variables used, report them
          for (ConcreteParameter const & cp : traversal->required_param_values) {
            ParameterDefinition const & param = cp.element;
            boost::uint64_t param_val = cp.concrete_value;

            ss << "   " << param.get_num() << ": ";
            if (param.get_address()) {
              TreeNodePtr param_memaddr_tnp = param.get_address()->get_expression();
              param_memaddr_tnp->print(ss, fmt);
            }
            else {
              // TODO: actually print the register-based param
              ss << "reg-param";
            }
            ss << " = " << param_val
               << " (" << static_cast<int>(param_val) << ")\n";
          }
        }
        if (traversal->required_ret_values.size() > 0) {
          ss << "Return value: ";
          // If there are concrete stack variables used, report them
          for (ConcreteParameter cp : traversal->required_ret_values) {
            // ParameterDefinition & ret = cp.element;
            boost::uint64_t ret_val = cp.concrete_value;
            ss << ret_val <<  " (" << static_cast<int>(ret_val) << ")\n";
          }
        }
        if (count+1 < path.size()) {
          ss << std::setw(80) << std::setfill('-') << "\n";
        }
        ++count;
      }
    }
    return ss.str();
  }

  // Save the generated Z3 underlying the analysis
  void
  generate_z3_file() {
    std::ofstream z3_fstream(z3_file_.c_str());
    z3_fstream << path_finder_.get_z3_output() << "\n";
    z3_fstream.close();

    OINFO << "Saved SMT to " << z3_file_ << LEND;
  }

 public:

  PathAnalyzer(DescriptorSet& _ds, ProgOptVarMap& opts) :
    BottomUpAnalyzer(_ds, opts), path_finder_(ds) {

    save_z3_ = false;
    save_graphviz_ = false;
    if (opts.count("dot")>0) {
      save_graphviz_ = true;
      dot_output_dir_ =  opts["dot"].as<bf::path>().native();
      OINFO << "DOT file will be generated in " << dot_output_dir_ << LEND;
    }

    if (opts.count("z3")>0) {
      save_z3_ = true;
      path_finder_.save_z3_output();
      z3_file_ =  opts["z3"].as<bf::path>().native();
      OINFO << "Z3 file will be generated " << z3_file_ << LEND;
    }

    exe_file_name_ = opts["file"].as<Specimens>().name();

    if (vm.count("start")) {

      std::stringstream start_ss;
      start_ss << std::hex << opts["start"].as<std::string>();
      start_ss >> start_address_;
    }

    if (vm.count("goal")) {

      std::stringstream goal_ss;
      goal_ss << std::hex << opts["goal"].as<std::string>();
      goal_ss >> goal_address_;

    }
  }

  void
  visit(FunctionDescriptor* fd) {
    // every function must be pharos-analyzed
    fd->get_pdg();
  }

  // This is where path finding really happens
  void finish() {

    path_finder_.find_path(start_address_, goal_address_);

    if (path_finder_.path_found())  {
      OINFO << "There is a path from " << addr_str(start_address_)
            << " to " << addr_str(goal_address_) << ". Well done!"
            << LEND;

      if (save_graphviz_) {
        save_graphviz_file();
      }
    }
    else {
      OERROR << "There is no feasible path from "
             << addr_str(start_address_) << " to "
             << addr_str(goal_address_) << ". Better luck next time!"
             << LEND;
    }
    if (save_z3_) {
      generate_z3_file();
    }

    std::cout << std::setfill('=') << std::setw(80) << "\n"
              << to_string() << "\n"
              << std::setfill('=') << std::setw(80) << "\n";
  }
};

ProgOptDesc pathanalyzer_options() {
  namespace po = boost::program_options;

  ProgOptDesc pathopt("PathAnalyzer version " + VERSION + " options");
  pathopt.add_options()
    ("dot,d", po::value<bf::path>(),   "The directory to write DOT file(s)")
    ("z3,z", po::value<bf::path>(),    "Save z3 output file (for troubleshooting)")
    ("goal,g", po::value<std::string>(),  "The goal address")
    ("start,s", po::value<std::string>(), "The starting address");

  return pathopt;
}

int pathanalyzer_main(int argc, char **argv) {
  set_glog_name("PTH");
  // Handle options
  ProgOptDesc pathod = pathanalyzer_options();
  ProgOptDesc csod = cert_standard_options();
  pathod.add(csod);
  ProgOptVarMap vm = parse_cert_options(argc, argv, pathod);

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);

  if (vm.count("propagate-conditions") == 0) {
    OWARN << "Pathanalyzer generally requires condition propogation to work, please consider running with the '--propogate-conditions' flag" << LEND;
  }

  // Resolve imports, load API data, etc.
  ds.resolve_imports();

  PathAnalyzer pa(ds, vm);
  pa.analyze();

  return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
  return pharos_main("PTHA", pathanalyzer_main, argc, argv);
}
