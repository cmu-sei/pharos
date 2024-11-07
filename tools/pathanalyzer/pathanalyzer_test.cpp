// Copyright 2020-2024 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/filesystem.hpp>

#include <libpharos/bua.hpp>
#include <libpharos/spacer.hpp>
#include <libpharos/wp.hpp>
#include <libpharos/path.hpp>

using namespace pharos;

namespace bf = boost::filesystem;

ProgOptDesc pathanalyzer_test_options() {
  namespace po = boost::program_options;

  ProgOptDesc ptopt("PathAnalyzer Test options");
  ptopt.add_options()
    ("seed,s", po::value<int>(), "The random seed for Z3")
    ("smt-file", po::value<bf::path>(),
     "The name of the file to save goal SMT output")
    ("method,m", po::value<std::string>()->required(),
     "The analysis method to use (fs, wp or spacer)")
    ("goal", "search for goal address")
    ("nongoal", "search for non-goal address")
    ("z3-log", po::value<bf::path>(), "z3 log file")
    ;

  return ptopt;
}

using PathAnalyzer = std::unique_ptr<Z3PathAnalyzer>;

class PATestAnalyzer : public BottomUpAnalyzer {
 private:
  rose_addr_t start_addr = INVALID_ADDRESS;
  rose_addr_t goal_addr = INVALID_ADDRESS;
  rose_addr_t nongoal_addr = INVALID_ADDRESS;

  PharosZ3Solver solver;
  PathAnalyzer analyzer;
  std::string test_name;

 public:

  PATestAnalyzer(DescriptorSet & ds_, ProgOptVarMap const & vm_);

  void start () override;
  void visit(FunctionDescriptor *fd) override;
  [[noreturn]] void finish () override;

};

using AnalyzerMap = std::map<
  std::string,
  std::function<PathAnalyzer(DescriptorSet &, ProgOptVarMap const &, PharosZ3Solver &)>>;


// Shared by wp and spacer.
ImportRewriteSet const imports = {
  // Because of in-lining, we may need to jump over a call to path_goal to reach the one we
  // selected.  As a result we need to include time.
  ImportCall{"ELF", "__assert_symbolic_dummy_import"},
  ImportCall{"ELF", "time"},
  ImportCall{"ELF", "rand"},
  ImportCall{"ELF", "random"},
  ImportCall{"ELF", "_Znwm"},
  ImportCall{"ELF", "_Znwj"},
  ImportCall{"MSVCR100D.dll", "rand"},
  ImportCall{"ucrtbased.dll", "rand"},
  // Additions for cyber grand challenge tests.
  ImportCall{"ELF", "cgc__terminate"},
  ImportCall{"ELF", "cgc_transmit"},
  ImportCall{"ELF", "cgc_random"},
  ImportCall{"ELF", "cgc_receive"},
};

PathAnalyzer create_spacer_analyzer(
  DescriptorSet const & ds, ProgOptVarMap const &vm, PharosZ3Solver & solver)
{
  if (vm.count("seed")) {
    auto seed = vm["seed"].as<int>();
    OINFO << "Setting seed to " << seed << LEND;
    solver.set_seed(seed);
  }

  return make_unique<SpacerAnalyzer>(ds, solver, imports, "spacer");
}

PathAnalyzer create_wp_analyzer(
  DescriptorSet const & ds, ProgOptVarMap const &, PharosZ3Solver & solver)
{
  return make_unique<WPPathAnalyzer>(ds, solver, imports);
}

PathAnalyzer create_fs_analyzer(
  DescriptorSet const & ds, ProgOptVarMap const &, PharosZ3Solver & solver)
{
  return make_unique<PathFinder>(ds, solver);
}

// Map of method names to Z3PathAnalyzer creation functions
AnalyzerMap analyzer_map = {
  {"spacer", create_spacer_analyzer },
  {"wp", create_wp_analyzer },
  {"fs", create_fs_analyzer }
};

PATestAnalyzer::PATestAnalyzer(DescriptorSet& ds_, ProgOptVarMap const & vm_)
  : BottomUpAnalyzer(ds_, vm_)
{
  if (vm.count("goal") && vm.count("nongoal")) {
    OFATAL << "Only one of --goal or --non-goal may be specified" << LEND;
    exit(EXIT_FAILURE);
  }
  if (!vm.count("goal") && !vm.count("nongoal")) {
    OFATAL << "One of --goal or --non-goal must be specified" << LEND;
    exit(EXIT_FAILURE);
  }

  test_name = bf::path(vm["file"].as<Specimens>().name()).stem().native();

  if (vm.count("z3-log")) {
    Z3_open_log(vm["z3-log"].as<bf::path>().c_str());
  }

  std::string method;
  assert(vm.count("method") == 1);
  method = vm["method"].as<std::string>();
  auto found = analyzer_map.find(method);
  if (found == analyzer_map.end()) {
    OFATAL << "Unknown method: '" << method << '\'' << LEND;
    exit(EXIT_FAILURE);
  }
  OINFO << "Analyzing '" << test_name << "' using method '" << method << '\'' << LEND;
  analyzer = found->second(ds, vm, solver);
}

void PATestAnalyzer::visit(FunctionDescriptor *fd) {
  fd->get_pdg();

  // Ick.  This was much nicer back when we were calling fd->get_outgoing_calls(), but not
  // all of the calls are actually CALL instructions in -O2 in g++, so we need an approach
  // that works for finding all instructions and their control flow targets.  This is
  // probably a sign that get_outgoing_calls() is broken and needs some work, but that's
  // a bigger change.
  const CFG& cfg = fd->get_rose_cfg();
  for (auto vertex : fd->get_vertices_in_flow_order(cfg)) {
    SgNode *n = get(boost::vertex_name, cfg, vertex);
    SgAsmBlock *blk = isSgAsmBlock(n);
    assert(blk != NULL);
    for (SgAsmStatement *stmt : blk->get_statementList()) {
      SgAsmInstruction *insn = isSgAsmInstruction(stmt);
      SgAsmX86Instruction *xinsn = isSgAsmX86Instruction(stmt);
      // We're only interested in calls and jumps.
      if (!insn_is_call_or_jmp(xinsn)) continue;

      bool complete;
      auto successors = insn->architecture()->getSuccessors(insn, complete);
      for (rose_addr_t target : successors.values()) {
        //OINFO << "Call/Jump from " << addr_str(insn->get_address()) << " to " << addr_str(target) << LEND;
        const FunctionDescriptor* tfd = ds.get_func(target);
        if (tfd) {
          const SgAsmFunction* func = tfd->get_func();
          if (func) {
            std::string name = func->get_name();
            //OINFO << "Found call to " << name << " at " << addr_str(insn->get_address()) << LEND;
            if (name == "_Z10path_startv" || name == "path_start") {
              OINFO << "Found path_start() call at " << addr_str(insn->get_address()) << LEND;

              // If we've already seen a call to path_start(), mark the test invalid and
              // return.
              if (start_addr != INVALID_ADDRESS) {
                OINFO << "Found duplicate path_start() call at "
                      << addr_str(insn->get_address()) << LEND;
                start_addr = INVALID_ADDRESS;
                return;
              }

              // We used to start at the instruction following the call to path_start().  That
              // doesn't really work because if we're going to be using the stack, we'll need
              // to have a proper setup of the RSP & RBP registers.  So instead, we're just
              // going to use the path_start() call to mean that the start location is at the
              // beginning of the current function!  Hopefully this retroactive redefinition
              // won't cause too many problems, and if it does we may have to use something
              // better defined like that path_start() is always main().

              // auto start_addr = insn->get_address () + insn->get_size ();
              start_addr = fd->get_address();
            }
            if (name == "_Z9path_goalv" || name == "path_goal") {
              OINFO << "Found path_goal() call at " << addr_str(insn->get_address()) << LEND;
              // If we've already seen a call to path_goal(), mark the test invalid and
              // return.
              if (goal_addr != INVALID_ADDRESS && goal_addr != target) {
                OINFO << "Found duplicate path_goal() call at "
                      << addr_str(insn->get_address()) << LEND;
                goal_addr = INVALID_ADDRESS;
                return;
              }
              //config_->goal = insn->get_address();
              goal_addr = target;
            }
            if (name == "_Z12path_nongoalv" || name == "path_nongoal") {
              OINFO << "Found path_nongoal() call at " << addr_str(insn->get_address()) << LEND;
              // If we've already seen a call to path_nongoal(), mark the test invalid and
              // return.
              if (nongoal_addr != INVALID_ADDRESS && nongoal_addr != target) {
                OINFO << "Found duplicate path_nongoal() call at "
                      << addr_str(insn->get_address()) << LEND;
                nongoal_addr = INVALID_ADDRESS;
                return;
              }
              nongoal_addr = target;
            }
          }
        }
      }
    }
  }
}

void PATestAnalyzer::start()
{
  OINFO << "Analyzing '" << test_name << '\'' << LEND;
}

[[noreturn]]
void PATestAnalyzer::finish()
{
  if (start_addr == INVALID_ADDRESS) {
    OFATAL << "Unable to find a start address" << LEND;
    exit(EXIT_FAILURE);
  }

  std::string goal_string;
  rose_addr_t target;
  if (vm.count("goal")) {
    target = goal_addr;
    goal_string = "goal";
  } else {
    target = nongoal_addr;
    goal_string = "nongoal";
  }

  if (target == INVALID_ADDRESS) {
    OFATAL << "Unable to find a " << goal_string << " address" << LEND;
    exit(EXIT_FAILURE);
  }

  OINFO << "Searching for " << goal_string << " address " << addr_str(target)
        << " from start address " << addr_str(start_addr) << LEND;

  auto setup_timer = make_timer();
  OINFO << "Setting up problem" << std::flush;
  analyzer->setup_path_problem(start_addr, target);
  OINFO << "...done" << LEND;
  OINFO << "Setting up problem took " << setup_timer << " seconds." << LEND;

  if (vm.count("smt-file")) {
    auto filename = vm["smt-file"].as<bf::path>().native();
    OINFO << "Writing problem to " << filename << LEND;
    std::ofstream out{filename};
    analyzer->output_problem(out);
  }

  auto solve_timer = make_timer();
  OINFO << "Finding path";
  auto result = analyzer->solve_path_problem();
  OINFO << "..done" << LEND;
  OINFO << "Attempting to find the path took " << solve_timer << " seconds." << LEND;

  if (target == goal_addr) {
    switch (result) {
     case z3::sat:
      OINFO << "Correctly found path to goal." << LEND;
      exit(EXIT_SUCCESS);
     case z3::unsat:
      OERROR << "Failed to find path to goal." << LEND;
      exit(EXIT_FAILURE);
     default:
      OERROR << "Unexpected analyzer result: " << result << LEND;
      exit(EXIT_FAILURE);
    }
  } else {
    switch (result) {
     case z3::sat:
      OERROR << "Found invalid path to nongoal." << LEND;
      exit(EXIT_FAILURE);
     case z3::unsat:
      OINFO << "Path to nongoal was correctly unsatisfiable." << LEND;
      exit(EXIT_SUCCESS);
     default:
      OINFO << "Unexpected analyzer result: " << result << LEND;
      exit(EXIT_FAILURE);
    }
  }
}

[[noreturn]]
static int pathanalyzer_test_main(int argc, char **argv) {

  // Handle options
  ProgOptDesc pathod = pathanalyzer_test_options();
  ProgOptDesc csod = cert_standard_options();
  pathod.add(csod);
  ProgOptVarMap ovm = parse_cert_options(argc, argv, pathod);

  if (ovm.count("file") != 1) {
    OFATAL << "Must produce a single executable to analyze" << LEND;
    exit(EXIT_FAILURE);
  }

  DescriptorSet ds(ovm);
  // Resolve imports, load API data, etc.
  ds.resolve_imports();

  PATestAnalyzer pa(ds, ovm);
  pa.analyze();

  // Should never get here
  abort();
}

int main(int argc, char **argv) {
  return pharos_main("PATH", pathanalyzer_test_main, argc, argv, STDERR_FILENO);
}


/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
