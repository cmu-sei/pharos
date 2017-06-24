// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/visitors.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/property_map/property_map.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/algorithm/string.hpp>
#include <fstream>
#include <dirent.h>

#include "sptrack.hpp"

namespace pharos {

typedef Rose::BinaryAnalysis::ControlFlow::Graph CFG;
typedef Rose::BinaryAnalysis::FunctionCall::Graph FCG;
typedef boost::graph_traits<CFG>::vertex_iterator CFGIter;
typedef boost::graph_traits<CFG>::vertex_descriptor CFGVertex;

// A hackish help function for negative hex stack deltas.
std::string neghex(int x) {
  std::string result;
  if (x >= 0) {
    result = str(boost::format("+%04X") % x);
  }
  else {
    result = str(boost::format("-%04X") % -x);
  }
  return result;
}

void spTracker::update_delta(rose_addr_t addr, StackDelta sd) {
  StackDelta current = get_delta(addr);

  // This status reporting is substantially more verbose than we will need after we've
  // debugged this throughly.  In the mean time, I'd like to log every questionable update.
  if (sd.confidence < current.confidence) {
    SDEBUG << "Improving stack delta confidence: addr=" << addr_str(addr)
           << " new=" << sd << " old=" << current << LEND;
  }
  else if (sd.confidence == current.confidence) {
    // No change is one case we certainly don't care about.
    if (sd.delta == current.delta) return;
    // We also don't want to report replacing "non" values.
    if (current.confidence == ConfidenceNone) return;

    // If we are merging a missing stack delta with a better-than-missing stack delta, use the
    // better value.  This is because the missing stack delta is represented by a variable,
    // which we can say takes on the value of the better delta.  If we had done stack call
    // analysis in a separate pass, we could have already resolved this.  We should probably do
    // that in the near future.
    if (sd.confidence == ConfidenceMissing && current.confidence >= ConfidenceMissing) {
      return;
    }
    if (current.confidence == ConfidenceMissing && sd.confidence >= ConfidenceMissing) {
      current.confidence = sd.confidence;
      current.delta = sd.delta;
      deltas[addr] = current;
      return;
    }

    // If we reached here, something is definitely wrong.  This message should be be "error"
    // level, but it's still spewing frequently enough that for the time being Cory reduced it
    // back to debug so as not to annoy general users of the tool.  Instead, we ticking
    // recent_failures each time, and that allows us to test for stack delta analysis failures
    // in general at the end of the function.
    SDEBUG << "Attempt to alter stack delta value: addr=" << addr_str(addr)
           << " new=" << sd << " old=" << current << LEND;
    recent_failures++;
    // Force the confidence down to Wrong.
    current.confidence = ConfidenceWrong;
    deltas[addr] = current;
    return;
  }
  else {
    if (current.confidence != ConfidenceNone) {
      SDEBUG << "Lowering stack delta confidence: addr=" << addr_str(addr)
             << " new=" << sd << " old=" << current << LEND;
    }
  }
  deltas[addr] = sd;
}

const StackDelta spTracker::get_delta(rose_addr_t addr) {
  StackDeltaMap::iterator finder = deltas.find(addr);
  if (finder == deltas.end()) return StackDelta(0, ConfidenceNone);
  else return finder->second;
}

StackDelta spTracker::get_call_delta(rose_addr_t addr) {
  CallDescriptor* cd = descriptor_set->get_call(addr);
  SDEBUG << "Getting stack delta for call " << addr_str(addr) << LEND;

  if (cd == NULL) {
    recent_failures++;
    SERROR << "Unable to find call descriptor for address: " << addr_str(addr) << LEND;
    return StackDelta(0, ConfidenceWrong);
  }
  else {

    StackDelta delta = cd->get_stack_delta();
    // If our call descriptor returned no delta, upgrade the answer to a guess on account of
    // how guessing zero isn't all that horrible, and we want to reserve some space for other
    // kinds of failures.  In a proper bottom up configuration, this is probably where we
    // invoke the solver, or at least issue an error.
    if (delta.confidence == ConfidenceNone)
      delta.confidence = ConfidenceMissing;
    SDEBUG << "Call descriptor for address: " << addr_str(addr)
           << " returned stack delta: " << delta << LEND;
    return delta;
  }
}

#if 0
// Returns paramCombos and populates the list of push instructions.
// Neither is currently used since Cory commented out the only call to this method.
// paramCombos is a list of integers representing the stack top of each contiguous block of
// pushes prior to the call.  e.g. "push, mov, push, push, call" returns 8 & 12.
std::vector<int> getParameterCombinations(SgAsmBlock *block, InsnIntPairVector &push_ins) {
  std::vector<int> paramCombos;
  SgAsmStatementPtrList & bbf_ins = block->get_statementList();

  int bytesPushed = 0;
  for (int x = bbf_ins.size()-1; x >= 0; x--) {
    SgAsmx86Instruction *ins = isSgAsmx86Instruction(bbf_ins[x]);
    if (!ins || ins->get_kind() != x86_push) {
      if (bytesPushed > 0) {
        int prev = 0;
        if (paramCombos.size() > 0) prev = paramCombos[paramCombos.size()-1];
        paramCombos.push_back(bytesPushed+prev);
      }
      bytesPushed = 0;
    } else if (ins->get_kind() == x86_push){

      SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::instance();
      rops->get_state()->set_operators(rops);
      size_t arch_bits = global_descriptor_set->get_arch_bits();
      DispatcherPtr dispatcher = RoseDispatcherX86::instance(entry_rops, arch_bits, NULL);
      const RegisterDescriptor& esp_rd = global_descriptor_set->get_stack_reg();
      const RegisterDescriptor& eip_rd = global_descriptor_set->get_ip_reg();
      entry_rops->writeRegister(esp_rd, entry_rops->number_(arch_bits, 0));
      entry_rops->writeRegister(eip_rd, entry_rops->number_(arch_bits, ins->get_address()));
      dispatcher->processInstruction(ins);

      SymbolicState<SymbolicValue> state = rops.get_state();
      if (state.DU_REG_ESP.is_known() && ((int)state.DU_REG_ESP.known_value()) > 0) {
        SDEBUG << "Fail " << debug_instruction(ins) << LEND;
        SDEBUG << state.DU_REG_ESP << LEND;
        assert(state.DU_REG_ESP.is_known() && ((int)state.DU_REG_ESP.known_value()) < 0);
      }

      bytesPushed += -1*(int)state.DU_REG_ESP.known_value();
      push_ins.push_back(InsnIntPair(ins,-1*(int)state.DU_REG_ESP.known_value()));
    }
  }

  if (bytesPushed > 0) {
    int prev = 0;
    if (paramCombos.size() > 0) prev = paramCombos[paramCombos.size()-1];
    paramCombos.push_back(bytesPushed+prev);
  }

  if (SDEBUG) {
    SDEBUG << "Param combos for " << std::hex << block->get_address() << std::dec << ":";
    for (size_t w = 0; w < paramCombos.size(); w++)
      SDEBUG << paramCombos[w] << " ";
    SDEBUG << LEND;
  }

  return paramCombos;
}

// Find the push instructions that setup the stack before each call
// Uses the paramCombos and push_params fields populated by getParameterCombos.
// Cory commented out the only call to this method, so it's currently unused.
ParameterMap getParameterPushers(Block2IntPairMap &spBeforeAfterBlock,
                                 CallBlockMap endsWithCall, BlockDeltas block_deltas) {
  ParameterMap out;

  for (CallBlockMap::iterator it = endsWithCall.begin(); it != endsWithCall.end(); it++) {
    // Get the call instruction
    SgAsmStatementPtrList & bbf_ins = it->first->get_statementList();
    assert(bbf_ins.size() > 0);
    SgAsmx86Instruction * callins = NULL;
    int c = bbf_ins.size()-1;
    int parambytes = 0;

    do {
      callins = isSgAsmx86Instruction(bbf_ins[c]);
      c--;
      if (callins && callins->get_kind() == x86_call)
        break;
    } while(c >= 0);
    if (!callins) {
      SERROR << "Call not found" << LEND;
      continue;
    }

    if (it->second.hasKnownParamBytes || it->second.callerCleanupBytes > 0) {
      if(it->second.paramCombos.size() == 0 || it->second.push_params.size() == 0) {
        // SWARN << "Warning: no push instructions found for block with known param "
        //       << "bytes or caller cleanup bytes " << addr_str(it->first->get_address()) << LEND;
        continue;
      }
      it->second.hasKnownParamBytes ? parambytes = it->second.knownParamBytes : parambytes = it->second.callerCleanupBytes;
    } else if (spBeforeAfterBlock.find(it->first) != spBeforeAfterBlock.end() &&
               block_deltas.find(it->first) != block_deltas.end()) {
      // SP After Call - SP @ basic block start = Change in SP due to all instructions in block -
      // # bytes popped off in call (params and return address)
      int lhs = spBeforeAfterBlock[it->first].second - spBeforeAfterBlock[it->first].first;
      size_t arch_bytes = global_descriptor_set->get_arch_bytes();
      parambytes = -1*block_deltas[it->first] - lhs - arch_bytes;
    }

    if (parambytes <= 0) continue;

    int sz = 0;
    X86InsnSet pushers;

    for (size_t t = 0; t < it->second.push_params.size() && sz != parambytes; t++) {
      sz += it->second.push_params[t].second;
      pushers.insert(it->second.push_params[t].first);
    }

    if (sz != parambytes)
      SWARN << "Warning: push sizes did not match expected param bytes "
            << addr_str(it->first->get_address()) << LEND;
    else {
      out[callins] = pushers;
    }
  }

  return out;
}

int getCleanupSize(BlockSet &ret_blocks) {
  if (ret_blocks.size() == 0) {
    SWARN << "Warning: No return blocks found. Assuming stack neutrality" << LEND;
    return 0;
  }

  // We only look at the first return block.  I'd prefer to check them all for consistency,
  // but I don't want to do it in multiple places.
  SgAsmBlock *bb = *(ret_blocks.begin());
  SgAsmStatementPtrList & bbf_ins = bb->get_statementList();
  for (int b = bbf_ins.size()-1; b >= 0; b--) {
    SgAsmx86Instruction *retins = isSgAsmx86Instruction(bbf_ins[b]);
    if (!retins || retins->get_kind() != x86_ret) continue;
    SgAsmExpressionPtrList &ops = retins->get_operandList()->get_operands();
    if (ops.size() > 0 && isSgAsmIntegerValueExpression(ops[0])) {
      return isSgAsmIntegerValueExpression(ops[0])->get_absolute_value();
      break;
    } else return 0;
  }

  return 0;
}

#if 0

#include "z3++.h"

class Z3StackSolver {

private:

  z3::expr build_literal(int term1, int term2, std::string desc, std::string oper) {
    std::stringstream convert;
    convert << std::dec << desc << " " << term1 << " " << oper << " " << term2;
    std::string literal = convert.str().c_str();
    SDEBUG << literal << LEND;
    z3::expr q = c.bool_const(convert.str().c_str());
    return q;
  }

public:

  z3::context c;
  z3::solver s;
  z3::expr_vector variables;
  z3::expr_vector literals;
  std::vector<std::string> vnames;

  Z3StackSolver(): s(c), variables(c), literals(c) {
    // Everything's already initialized?
  }

  void add_constraint(z3::expr &e, int term1, int term2, std::string desc, std::string oper) {
    s.add(e);
    z3::expr q = build_literal(term1, term2, desc, oper);
    s.add(implies(q, e));
    literals.push_back(q);
  }

  void add_delta_constraint(int bid, std::string oper, int term, std::string desc) {
    z3::expr e(c);

    // If I can learn to extract the operator from the expression, we won't need this sillyness.
    // Also, variables[bid+1] - variables[bid] basically means "out - in".
    if (oper == "==")
      e = variables[bid+1] - variables[bid] == term;
    else if (oper == "<=")
      e = variables[bid+1] - variables[bid] <= term;
    else if (oper == ">=")
      e = variables[bid+1] - variables[bid] >= term;

    s.add(e);

    std::string lit = str(boost::format("Adding constraint for block %s %s - %s %s %d") \
                          % desc % vnames[bid+1] % vnames[bid] % oper % term);
    SDEBUG << lit << LEND;
    z3::expr q = c.bool_const(lit.c_str());
    s.add(implies(q, e));
    literals.push_back(q);
  }

  void make_vars(SgAsmBlock *bb) {
    // Stack depth before the first instruction of the block
    std::string name = str(boost::format("%x_in") % bb->get_address());
    z3::expr stack_in = c.int_const(name.c_str());
    variables.push_back(stack_in);
    vnames.push_back(name);

    // Stack depth after the last instruction of the block (i.e., after a call has returned)
    name = str(boost::format("%x_out") % bb->get_address());
    z3::expr stack_out = c.int_const(name.c_str());
    variables.push_back(stack_out);
    vnames.push_back(name);
  }

};

Insn2IntMap solveConstraintProblem(FunctionDescriptor *fd,
                                   BlockDeltas block_deltas,
                                   BlockDeltas block_ids,
                                   CallBlockMap endsWithCall,
                                   size_t dimension,
                                   Block2IntPairMap &spBeforeAfterBlock) {

  // Our return value
  Insn2IntMap ret;

  SgAsmFunction* func = fd->get_func();

  // Formulate the constraints and problem
  // Each basic block generates two variables sp_in and sp_out,
  // the depths of the stack into and coming out of the stack respectively.
  // The constraint is that the stack depth coming out of any two blocks
  // must be equal if they flow into the same block.
  // We assume an initial stack depth of architecture size (for the return address),
  // unless we can find a callee clean up return (i.e., retn XX,
  // in which case XX+arch_bytes was the initial depth)

  bool solutionFound = false;
  size_t arch_bytes = global_descriptor_set->get_arch_bytes();
  int initial_stack_depth = arch_bytes;

  // Make a list of the return blocks.
  //BinaryAnalysis::ControlFlow cfg_analyzer;
  //CFG cfg = cfg_analyzer.build_block_cfg_from_ast<CFG>(func);
  CFG& cfg = fd->get_cfg();
  BlockSet& ret_blocks = fd->get_return_blocks();
  initial_stack_depth += getCleanupSize(ret_blocks);

  // Create variables representing the depth of the stack at the beginning and end of each basic block
  SgAsmStatementPtrList & bb_list = func->get_statementList();

  Z3StackSolver z3sd;

  try{
    for (size_t x = 0; x < dimension; x++) {
      SgAsmBlock *bb = isSgAsmBlock(bb_list[x]);
      if (!bb) continue;
      z3sd.make_vars(bb);
    }

    // x+1 is the out edge
    // x+0 is the in edge

    // Set the lower bounds for each of the inner variables (i.e. the stack depths of all basic blocks EXCEPT)
    // for the entry block and return blocks
    for (size_t x = 1; x < dimension; x++) {
      SgAsmBlock *bb = isSgAsmBlock(bb_list[x]);
      if (!bb) continue;
      if (ret_blocks.find(bb) == ret_blocks.end()) {
        z3::expr e = z3sd.variables[2*x+1] >= 0;
        //z3sd.add_constraint(e, 2*x+1, 0, "Adding lower bounds for id", ">=");
      }

      z3::expr e = z3sd.variables[2*x] >= 0;
      //z3sd.add_constraint(e, 2*x, 0, "Adding lower bounds for id", ">=");
    }

    std::pair<CFGIter, CFGIter> vp;
    // Set the constraints based on the control flow edges for all blocks except ones that end with a call
    for (vp = vertices(cfg); vp.first != vp.second; ++vp.first) {
      SgAsmBlock *block = get(boost::vertex_name,cfg,*vp.first);
      if (block && block_ids.find(block) != block_ids.end()) {
        SDEBUG << "Processing block @" << addr_str(block->get_address()) << LEND;

        // Are we the entry block
        // Wes changed this to isSgAsmBlock(bb_list[0]), why?
        if (block == func->get_entry_block()) {
          // Assume the depth at the start of the function is 0
          z3::expr e = z3sd.variables[0] == 0;
          z3sd.add_constraint(e, 0, 0, "Adding lower bounds for id", "==");
        }

        int bid = 2*block_ids[block];

        // Are we a return block
        if (ret_blocks.find(block) != ret_blocks.end()) {
          z3::expr e = z3sd.variables[bid + 1] == -initial_stack_depth;
          z3sd.add_constraint(e, bid + 1, -initial_stack_depth,
                         "Setting return block stack depth out for id", "==");
        }

        // Insert the constraint for the delta within the block
        if (endsWithCall.find(block) == endsWithCall.end()) {
          z3sd.add_delta_constraint(bid, "==", -block_deltas[block], "without call:");
        }
        else {
          int normaldelta = -1*block_deltas[block] - arch_bytes;
          if (endsWithCall[block].callerCleanupBytes == 0) {
            if (endsWithCall[block].hasKnownParamBytes) {
              int term = normaldelta - endsWithCall[block].knownParamBytes;
              z3sd.add_delta_constraint(bid, "==", term, "with call (from dll):");
            }
            // This branch of the code now disabled because paramCombos is never populated.
            else if (endsWithCall[block].paramCombos.size() > 0) {
              std::string desc = "with call (with observed pushes):";
              z3sd.add_delta_constraint(bid, "<=", normaldelta, desc);
              int ls = endsWithCall[block].paramCombos.size()-1;
              int term = normaldelta - endsWithCall[block].paramCombos[ls];
              z3sd.add_delta_constraint(bid, ">=", term, desc);
            }
            else {
              z3sd.add_delta_constraint(bid, "<=", normaldelta, "with call (no CallerCleanup):");
            }
          } else {
            z3sd.add_delta_constraint(bid, "==", normaldelta, "with call (with CallerCleanup):");
          }
        }

        // Add constraints based upon the in-edges of the block
        boost::graph_traits<CFG>::in_edge_iterator ei, ei_end;
        for (boost::tie(ei, ei_end)=in_edges(*vp.first, cfg); ei!=ei_end; ++ei) {
          CFGVertex predecessor = source(*ei, cfg);
          SgAsmBlock *pblock = get(boost::vertex_name, cfg, predecessor);
          assert(pblock);

          //s.add(z3sd.variables[2*block_ids[pblock]+1] == z3sd.variables[bid]);

          SDEBUG << "Setting constraint for in edge between " << addr_str(pblock->get_address())
                 << " " << addr_str(block->get_address()) << " to 0 "
                 << " IDS: " << 2*block_ids[pblock]+1 << " " << bid << LEND;

          std::stringstream convert;
          convert.str("");
          convert << "Assertion: Setting constraint for in edge between "
                  << std::hex << pblock->get_address()
                  << " " << block->get_address() << " to 0 " << " IDS: "
                  << 2*block_ids[pblock]+1 << " " << 2*block_ids[block];
          z3::expr qe = z3sd.c.bool_const(convert.str().c_str());
          z3sd.s.add(implies(qe, z3sd.variables[2*block_ids[pblock]+1] == z3sd.variables[bid]));
          z3sd.literals.push_back(qe);
        }
      }
    }

    // Make possible solutions from parameter combinations
    // BlockDeltas curSolution;
    // BlockDeltasVector possibleDeltas;
    // CallBlockMap endsWithCallNoCallerCleanup;
    // makePossibleCallDeltas(endsWithCallNoCallerCleanup, curSolution, possibleDeltas);

    SDEBUG << "Model before solving:" << LEND;
    SDEBUG << z3sd.s << LEND;

    Block2IntPairMap minsol;
    // Something related to our return value
    Insn2IntMap minret;
    int max_it = 3;
    int tries = 0;
    bool unsatisfied = z3sd.s.check(z3sd.literals);
    while (unsatisfied != z3::unsat && tries < max_it) {
      if (tries > 0) z3sd.s.pop();
      z3sd.s.push();

      z3::model m = z3sd.s.get_model();
      SDEBUG << "Possible solution found Sol # " << tries << LEND;
      solutionFound = true;
      int sp_sum = 0;

      SDEBUG << z3sd.s << LEND;

      assert(bb_list.size() > 0);
      z3::expr delta_constraint = z3sd.variables[2*block_ids[isSgAsmBlock(bb_list[0])]+1];

      for (size_t w = 0; w < m.size(); w++) {
        std::string varname = m[w].name().str();
        //SDEBUG << "Varname: " << varname << LEND;

        if (varname.find("_out") == std::string::npos && varname.find("_in") == std::string::npos)
          continue;

        int delta = 0;
        Z3_get_numeral_int(z3sd.c, m.get_const_interp(m[w]),&delta);

        for (size_t x = 0; x < dimension; x++) {
          SgAsmBlock *bb = isSgAsmBlock(bb_list[x]);
          if (!bb) continue;

          if (varname == z3sd.vnames[2*x]) {
            if (spBeforeAfterBlock.find(bb) == spBeforeAfterBlock.end())
              spBeforeAfterBlock[bb] = IntPair(delta,-1);
            else spBeforeAfterBlock[bb].first = delta;
          }
          else if (varname == z3sd.vnames[2*x+1]) {
            sp_sum += delta;

            if (spBeforeAfterBlock.find(bb) == spBeforeAfterBlock.end())
              spBeforeAfterBlock[bb] = IntPair(-1,delta);
            else spBeforeAfterBlock[bb].second = delta;

            if (endsWithCall.find(bb) != endsWithCall.end()) {
              SgAsmStatementPtrList & bbf_ins = bb->get_statementList();

              assert(bbf_ins.size() > 0 && isSgAsmx86Instruction(bbf_ins[bbf_ins.size()-1])->get_kind() == x86_call);
              SgAsmx86Instruction *call = isSgAsmx86Instruction(bbf_ins[bbf_ins.size()-1]);
              ret[call] = delta;
            }
          }

          if (x > 0) delta_constraint = delta_constraint + z3sd.variables[2*block_ids[isSgAsmBlock(bb_list[x])]+1];
        }
      }

      z3sd.s.add(delta_constraint < sp_sum);
      minsol = spBeforeAfterBlock;
      minret = ret;
      spBeforeAfterBlock.clear();
      ret.clear();
      tries++;
    }

    if (unsatisfied == z3::unsat) {
      z3::expr_vector core = z3sd.s.unsat_core();

      SDEBUG << "Core size " << core.size() << " Total number of literals " << z3sd.literals.size() << LEND;
      SDEBUG << "Unsat core:" << LEND;
      for (size_t f = 0; f < core.size(); f++)
        SDEBUG << core[f] << LEND;
    }

    if (tries >= max_it)
      SWARN << "Gave up looking for a better stack delta solution for function "
                 << fd->address_string() << " after " << tries << " iterations." << LEND;

    spBeforeAfterBlock = minsol;
    ret = minret;
  } catch(z3::exception e) {
    SERROR << "caught z3 exception: " << e << LEND;
  }

  if (!solutionFound)
    SWARN << "Could not find stack delta solution for function " << fd->address_string() << LEND;

  return ret;
}

#endif // Z3SOLVER

bool getCallerCleanupSize(SgAsmBlock *blockAfterCall, int *cleanupsize) {
  if (blockAfterCall) {
    SgAsmStatementPtrList & next_ins = isSgAsmBlock(blockAfterCall)->get_statementList();
    for (size_t q = 0; q < next_ins.size(); q++) {
      SgAsmx86Instruction *ni = isSgAsmx86Instruction(next_ins[q]);
      if (!ni) continue;
      if (ni->get_kind() == x86_add) {
        SgAsmExpressionPtrList &ops = ni->get_operandList()->get_operands();
        if (ops.size() >= 2 && isSgAsmRegisterReferenceExpression(ops[0]) &&
            unparseX86Register(isSgAsmRegisterReferenceExpression(ops[0])->get_descriptor(), NULL) == "esp" &&
            isSgAsmIntegerValueExpression(ops[1])) {

          if (q+1 < next_ins.size() &&
              isSgAsmx86Instruction(next_ins[q+1])->get_kind() == x86_ret)
            return false;

          *cleanupsize = isSgAsmIntegerValueExpression(ops[1])->get_absolute_value();
          SDEBUG << "Caller cleanup bytes " << *cleanupsize << LEND;
          return true;
        }
      }
    }
  }

  return false;
}

// A mapping between the address of a call instruction and the SP immediately following its return
Insn2IntMap spTracker::getStackDepthAfterCalls(FunctionDescriptor* fd) {

  BlockDeltas block_deltas;
  Insn2IntMap call_deltas;
  BlockDeltas block_ids;
  CallBlockMap endsWithCall;
  int dimension = 0;

  SgAsmFunction* func = fd->get_func();

  SgAsmStatementPtrList & bb_list = func->get_statementList();

  // Evaluate each basic block and get the value in ESP (the stack delta after each basic block)
  // If there
  for (size_t x = 0; x < bb_list.size(); x++) {
    SgAsmBlock *block = isSgAsmBlock(bb_list[x]);
    if (!block) continue;
    SgAsmStatementPtrList & bbf_ins = block->get_statementList();
    if (bbf_ins.size() == 0) continue;
    bool hasValidInstructions = false;

    SymbolicRiscOperatorsPtr rops = SymbolicRiscOperators::instance();
    size_t arch_bits = global_descriptor_set->get_arch_bits();
    DispatcherPtr dispatcher = RoseDispatcherX86::instance(rops, arch_bits, NULL);
    rops.writeRegister("esp",SymbolicValue<arch_bits>(0));

    for (size_t y = 0; y < bbf_ins.size(); y++) {
      try {
        SgAsmx86Instruction *ins = isSgAsmx86Instruction(bbf_ins[y]);
        if (!ins) break;

        hasValidInstructions = true;

        if (ins->get_kind() == x86_mov) {
          SgAsmExpressionPtrList &ops = ins->get_operandList()->get_operands();
          if (ops.size() >= 2 && isSgAsmRegisterReferenceExpression(ops[0]) &&
              unparseX86Register(isSgAsmRegisterReferenceExpression(ops[0])->get_descriptor(), NULL) == "esp") {
            continue;
          }
        }

        rops.writeRegister("eip",SymbolicValue<arch_bits>(ins->get_address()));
        dispatcher.processInstruction(ins);

        SDEBUG << "Insn: " << debug_instruction(ins) << LEND;

        if (ins->get_kind() == x86_call) {
          SDEBUG << "Block " << addr_str(block->get_address()) << " ends with a call" << LEND;
          callBlock cb;
          cb.callerCleanupBytes = 0;
          //cb.paramCombos = getParameterCombinations(block,cb.push_params);
          cb.hasKnownParamBytes = false;
          cb.knownParamBytes = 0;

          // Write an entry into the endsWithCall map.  We'll overwrite it later if we don't
          // premateurely exit...
          endsWithCall[block] = cb;

          // Am I call to a known API
          SgAsmExpressionPtrList &callops = ins->get_operandList()->get_operands();
          rose_addr_t target = 0;
          assert(callops.size() > 0);
          SgAsmMemoryReferenceExpression* memref = isSgAsmMemoryReferenceExpression(callops[0]);
          if (memref && isSgAsmIntegerValueExpression(memref->get_address())) {
            target = isSgAsmIntegerValueExpression(memref->get_address())->get_absolute_value();
          } else if (isSgAsmRegisterReferenceExpression(callops[0])) {
            RegisterDescriptor cdesc = isSgAsmRegisterReferenceExpression(callops[0])->get_descriptor();
            SymbolicState<SymbolicValue> state = ops.get_state();
            for (const AbstractAccess& aa : ops.reads) {
              if (!aa.is_reg(cdesc)) continue;
              if (aa.value.is_known()) target = aa.value.known_value();
            }
          } else if (isSgAsmIntegerValueExpression(callops[0])) {
            target = isSgAsmIntegerValueExpression(callops[0])->get_absolute_value();
          }

          if (target) {
            SDEBUG << "Call targets: " << addr_str(target) << LEND;

            // Find the import descriptor for this call target.
            ImportDescriptor* id = descriptor_set->get_import(target);
            if (id != NULL) {
              cb.hasKnownParamBytes = true;
              // Get the stack delta from the import descriptor.
              cb.knownParamBytes = id->get_stack_parameters().delta;
              SDEBUG << "Known param bytes " << cb.knownParamBytes << LEND;
            } else {
              FunctionDescriptor* tfd = descriptor_set->get_func(target);
              if (tfd != NULL) {
                cb.hasKnownParamBytes = true;
                BlockSet ret_blocks = tfd->get_return_blocks();
                cb.knownParamBytes = getCleanupSize(ret_blocks);
                //break;
              }
            }
          }

          // Check for caller cleanup
          if (x+1 < bb_list.size()) {
            SgAsmBlock *nextblock = isSgAsmBlock(bb_list[x+1]);
            if (nextblock) {
              SgAsmStatementPtrList & next_ins = isSgAsmBlock(nextblock)->get_statementList();
              for (size_t q = 0; q < next_ins.size(); q++) {
                SgAsmx86Instruction *ni = isSgAsmx86Instruction(next_ins[q]);
                if (!ni) continue;
                if (ni->get_kind() == x86_add) {
                  SgAsmExpressionPtrList &ops = ni->get_operandList()->get_operands();
                  if (ops.size() >= 2 && isSgAsmRegisterReferenceExpression(ops[0]) &&
                      unparseX86Register(isSgAsmRegisterReferenceExpression(ops[0])->get_descriptor(), NULL) == "esp" &&
                      isSgAsmIntegerValueExpression(ops[1])) {

                    if (q+1 < next_ins.size() &&
                        isSgAsmx86Instruction(next_ins[q+1])->get_kind() == x86_ret)
                      continue;

                    cb.callerCleanupBytes = isSgAsmIntegerValueExpression(ops[1])->get_absolute_value();
                    SDEBUG << "Caller cleanup bytes " << cb.callerCleanupBytes << LEND;
                    break;
                  }
                }
              }
            }
          }
          endsWithCall[block] = cb;
        }
      } catch(...) {
        // Probably just ignoring unimplemented instructions...
        continue;
      }
    }

    if (!hasValidInstructions) break;
    dimension++;

    SymbolicState<SymbolicValue> state = rops.get_state();
    if (!state.DU_REG_ESP.is_known()) {
      SWARN << "Lost track of stack pointer within basic block " << x
            << " in function " << fd->address_string() << LEND;
      SDEBUG << state.DU_REG_ESP << LEND;
      return call_deltas;
    }
    block_deltas[block] = state.DU_REG_ESP.known_value();
    block_ids[block] = x;
    SDEBUG << "Setting block delta for block (id=" << x << ") at 0x" << std::hex
           << block->get_address() << std::dec << " to " << block_deltas[block] << LEND;
  }

  SDEBUG << "Creating constraint problem for " << fd->address_string() << LEND;

  call_deltas = solveConstraintProblem(fd,block_deltas,block_ids,endsWithCall,dimension,spBeforeAfterBlock);
  //pushParams = getParameterPushers(spBeforeAfterBlock, endsWithCall, block_deltas);

  return call_deltas;

  // end of getStackDepthAfterCalls
}

// Note bDeltas contain SP deltas which are relative to the functions that they belong.
// In order to use the information in other function, this offset must be added to the value of
// the stack pointer at the call destination from the other function
bool spTracker::getBlockDeltas(FunctionDescriptor* fd,  SymbolicRiscOperators *ropsFromCall) {
  SgAsmFunction *func = fd->get_func();
  if (func == NULL) return false;
  if (functionDeltas.find(func) != functionDeltas.end()) return true;
  else if (processed.find(func) != processed.end()) return false;
  processed.insert(func);

  SDEBUG << "Starting symbolic SP analysis for @" << fd->address_string() << LEND;

  SymbolicRiscOperatorsPtr rops;
  size_t arch_bits = global_descriptor_set->get_arch_bits();
  DispatcherPtr dispatcher = RoseDispatcherX86::instance(rops, arch_bits, NULL);
  if (ropsFromCall == NULL) {
    rops = SymbolicRiscOperators::instance();
    rops->writeRegister(rops->findRegister("esp", arch_bits), rops->number<arch_bits>(0));
    rops->writeRegister(rops->findRegister("ebp", arch_bits), rops->number<arch_bits>(0));
    // The segment registers are always 16 bits...
    rops->writeRegister(rops->findRegister("es", 16), rops->number<16>(0));
    rops->writeRegister(rops->findRegister("cs", 16), rops->number<16>(0));
    rops->writeRegister(rops->findRegister("ss", 16), rops->number<16>(0));
    rops->writeRegister(rops->findRegister("ds", 16), rops->number<16>(0));
    rops->writeRegister(rops->findRegister("fs", 16), rops->number<16>(0));
    rops->writeRegister(rops->findRegister("gs", 16), rops->number<16>(0));
  } else rops = ropsFromCall;

  if (!rops->get_state().DU_REG_ESP.is_known()) {
    SWARN << "Lost track of stack pointer at the beginning of function @"
          << func->address_string() << LEND;
    return false;
  }

  int initial_sp = (int)rops->get_state().DU_REG_ESP.known_value();

  SDEBUG << "Initial SP " << initial_sp << LEND;

  SgAsmStatementPtrList & bb_list = func->get_statementList();
  if (bb_list.size() == 0) return false;

  BinaryAnalysis::ControlFlow cfg_analyzer;
  CFG cfg = cfg_analyzer.build_block_cfg_from_ast<CFG>(func);
  std::vector<CFGVertex> flowlist = cfg_analyzer.flow_order(cfg,0);
  std::map<CFGVertex, SymbolicRiscOperatorsPtr> blockPolicies;
  bool retFound = false;

  for (size_t z = 0; z < flowlist.size(); ++z) {
    bool hasRet = false;
    CFGVertex vertex = flowlist[z];
    SgAsmBlock *bb = get(boost::vertex_name, cfg, vertex);
    assert(bb!=NULL);

    SDEBUG << "Processing block " << addr_str(bb->get_address()) << LEND;


    // Skip padding blocks
    if (bb->get_reason() & SgAsmBlock::BLK_PADDING) {
      // is this debug, warning, or info?
      SDEBUG << "Skipping padding block @" << bb->get_address() << LEND;
      continue;
    }
    boost::graph_traits<CFG>::out_edge_iterator oi, oi_end;

    if (bb == NULL) {
      SWARN << "Warning: Empty basic block found" << LEND;
      continue;
    }

    SymbolicRiscOperatorsPtr p = SymbolicRiscOperators::instance();
    if (z == 0) p = *rops;
    else {
      boost::graph_traits<CFG>::in_edge_iterator ei, ei_end;

      bool found = false;
      for (boost::tie(ei, ei_end)=in_edges(vertex, cfg); ei!=ei_end; ++ei) {
        CFGVertex predecessor = source(*ei, cfg);
        if (blockPolicies.find(predecessor) != blockPolicies.end()) {
          SgAsmBlock *pb = get(boost::vertex_name, cfg, predecessor);
          SDEBUG << "Using rops from block " << std::hex << pb->get_address() << std::dec << LEND;
          p = blockPolicies[predecessor];
          found = true;
          break;
        }
      }
      assert(found);
    }

    size_t arch_bits = global_descriptor_set->get_arch_bits();
    size_t arch_bytes = global_descriptor_set->get_arch_bytes();
    DispatcherPtr dispatcher = RoseDispatcherX86::instance(p, arch_bits, NULL);

    // This code is old, messy, and might be broken post 64-bit update.
    uint64_t known_esp_value = state.DU_REG_ESP.known_value();

    SgAsmStatementPtrList & ins_list = bb->get_statementList();
    SgAsmx86Instruction *insn = NULL;
    for (size_t q = 0; q < ins_list.size(); q++) {
      try {
        insn = isSgAsmx86Instruction(ins_list[q]);
        if (insn == NULL) continue;

        // Evaluate the instruction
        p.writeRegister("eip",SymbolicValue<arch_bits>(insn->get_address()));
        dispatcher.processInstruction(insn);

        if (insn->get_kind() == x86_ret) hasRet = true;

        // Handle calls to local functions recursively if we haven't already done so
        // Sub in the results from IDA if we have them
        if (insn->get_kind() == x86_call || insn->get_kind() == x86_jmp) {


          // Get the call destination
          //      bool complete = false;
          rose_addr_t branch_target = 0;
          //      AddrSet callTargets = insn->get_successors(&complete);
          //      complete = false;


          SymbolicState<SymbolicValue> & state = p.get_state();
          if (!state.DU_REG_ESP.is_known()) {
            SWARN << "Lost track of stack pointer while processing block "
                       << addr_str(bb->get_address()) << LEND;
            return false;
          }



          if (insn->get_kind() == x86_jmp) {
            if (fd->is_thunk()) {
              SDEBUG << "Sptracker following thunk " << debug_instruction(insn) << LEND;
              branch_target = fd->get_jmp_addr();
              SDEBUG << "Thunk target " << branch_target << LEND;
            }
            else continue;
            // Check to see if the jump target is an address before the first instruction
            // or after the last instruction of the function
            /*
            rose_addr_t dest = branch_target > 0 ? branch_target : *(callTargets.begin());

            FunctionDescriptor* dfd = descriptor_set->get_func(dest);
            if (dfd == NULL) {

              SDEBUG << "Jmp to " << std::hex << dest << std::dec << LEND;

              rose_addr_t lastBBAddr = isSgAsmBlock(bb_list[bb_list.size()-1])->get_address();
              if (dest == 0) {
                SWARN << "Warning jmp destination is 0" << LEND;
                return false;
              } else if (dest >= func->get_entry_va() && dest <= lastBBAddr) {
                // should be debug?
                SDEBUG << "jmp destination is to a local address" << LEND;
              } else {
                // debug, warning, error, or info?
                SDEBUG << "Found jump to a function that wasn't in funcList: "
                            << std::hex << dest << std::dec << LEND;
                return false;
              }
              continue;
            }
            else SDEBUG << "Found jmp to other function " << addr_str(dest) << LEND;
            */
          } else {

            CallDescriptor* cd = global_descriptor_set->get_call(insn->get_address());
            if (!cd) {
              SDEBUG << "Couldn't find the call descriptor" << LEND;
              return false;
            }

            FunctionDescriptor *srcFd = cd->get_function_descriptor();
            if (srcFd == NULL || srcFd->get_func() == NULL) {

              // Last chance... check for caller cleanup
              bool cleanupFound = false;
              for (boost::tie(oi, oi_end)=out_edges(vertex, cfg); oi!=oi_end; ++oi) {
                CFGVertex successor = target(*oi, cfg);
                int cleanupSize = 0;
                SgAsmBlock *nb = get(boost::vertex_name, cfg, successor);
                if (getCallerCleanupSize(nb, &cleanupSize)) {
                  cleanupFound = true;
                  break;
                }
              }

              if (cleanupFound) {
                // Cleanup found, we just need to correct for the pushed return address
                LeafNodePtr new_val =  LeafNode::create_integer(arch_bits, known_esp_value + arch_bytes);
                state.DU_REG_ESP.set_expression(new_val);
                continue;
              }

              SDEBUG << "Unknown branch " << debug_instruction(insn)
                          << " No known successors..." << LEND;
              return false;
            }

            branch_target = srcFd->get_func()->get_entry_va();
          }


          if (branch_target == 0) {
            // debugging? error? warning?
            SDEBUG << "Unknown branch " << debug_instruction(insn) << LEND;
            return false;
          } else {
            // debugging?
            SDEBUG << "Branch target = " << addr_str(branch_target) << LEND;
          }

          // Call to known API, check for caller cleanup
          ImportDescriptor* id = descriptor_set->get_import(branch_target);
          if (id) {
            StackDelta sd = id->get_stack_delta();
            SDEBUG << "Found call to API " << debug_instruction(insn)
                        << " " << addr_str(branch_target) << LEND
                        << "Param bytes " << sd.delta << LEND;
            int cleanupSize = 0;

            bool cleanupFound = false;
            for (boost::tie(oi, oi_end)=out_edges(vertex, cfg); oi!=oi_end; ++oi) {
              CFGVertex successor = target(*oi, cfg);
              SgAsmBlock *nb = get(boost::vertex_name, cfg, successor);
              if (getCallerCleanupSize(nb, &cleanupSize)) {
                cleanupFound = true;
                break;
              }
            }

            if (cleanupFound) {
              // Cleanup found, we just need to correct for the pushed return address
              LeafNodePtr new_val =  LeafNode::create_integer(arch_bits, known_esp_value + arch_bytes);
              state.DU_REG_ESP.set_expression(new_val);
            } else {
              LeafNodePtr new_val =  LeafNode::create_integer(arch_bits,
                                                              known_esp_value + arch_bytes + sd.delta);
              // Assume callee cleanup
              state.DU_REG_ESP.set_expression(new_val);
            }

            //      complete = true;
          }
          else {
            FunctionDescriptor* bfd = descriptor_set->get_func(branch_target);
            if (bfd != NULL) {
              SgAsmFunction* bfunc = bfd->get_func();
              //else if (funcList.find(branch_target) != funcList.end()) {
              if (functionDeltas.find(bfunc) == functionDeltas.end()) {
                bool complete = getBlockDeltas(bfd, &p);

                // error? warning? debug?
                if (!complete) SDEBUG << "Symbolic analysis stopped while processing call to "
                                      << addr_str(bfunc->get_entry_va()) << LEND;
              } else {
                SDEBUG << "Using cached function delta for destination "
                            << addr_str(branch_target) << " Delta = "
                            << functionDeltas[bfunc] << LEND;
                LeafNodePtr new_val =  LeafNode::create_integer(arch_bits,
                                                                known_esp_value + functionDeltas[bfunc]);
                state.DU_REG_ESP.set_expression(new_val);
                //                complete = true;
              }
            }
            else {
              // debug, error, warn?
              SDEBUG << "Branch destination not found" << addr_str(branch_target) << LEND;
            }
          }

        }
      } catch(...) {
        if (insn != NULL) {
          SERROR << "ROSE Exception while processing " << debug_instruction(insn) << LEND;
        }
        SERROR << std::dec << "Instruction " << q << " of " << ins_list.size() << LEND;
      }
    }

    SymbolicState<SymbolicValue> state = p.get_state();

    if (!state.DU_REG_ESP.is_known()) {
      // error? warning? debug?
      SDEBUG << "Lost track of stack pointer after processing block "
                  << addr_str(bb->get_address()) << LEND;
      return false;
    }

    bDeltas[bb] = (int)state.DU_REG_ESP.known_value() - (int)initial_sp;

    SDEBUG << "Delta after basic block (non-z3) " << addr_str(bb->get_address()) << " "
                << (int)bDeltas[bb] << LEND;

    blockPolicies[vertex] = p;
    if (hasRet) {
      if (ropsFromCall != NULL) *ropsFromCall = p;
      functionDeltas[func] = (int)state.DU_REG_ESP.known_value()-initial_sp;
      retFound = true;
    }
  }

  if (!retFound && flowlist.size() > 0 &&
      blockPolicies.find(flowlist[flowlist.size()-1]) != blockPolicies.end()) {
    if (ropsFromCall != NULL) *ropsFromCall = blockPolicies[flowlist[flowlist.size()-1]];
    functionDeltas[func] = (int)blockPolicies[flowlist[flowlist.size()-1]].get_state().DU_REG_ESP.known_value()-initial_sp;
  }

  SDEBUG << "Function delta " << addr_str(func->get_entry_va()) << " "
         << (int)functionDeltas[func] << LEND;

  return true;
  // End of GetBlockDeltas
}
#endif

spTracker::spTracker(DescriptorSet* ds) {
  descriptor_set = ds;
  recent_failures = 0;
}

void spTracker::dump_deltas(std::string filename) {
  FILE *csv = fopen(filename.c_str(), "w");
  for (const FunctionDescriptorMap::value_type& pair : descriptor_set->get_func_map()) {
    rose_addr_t faddr = pair.first;
    const FunctionDescriptor& fd = pair.second;
    for (SgAsmx86Instruction* insn : fd.get_insns_addr_order()) {
      rose_addr_t iaddr = insn->get_address();
      StackDelta current = get_delta(iaddr);
      fprintf(csv, "%08x,%08x,%d\n", (unsigned int)faddr, (unsigned int)iaddr, -current.delta);
    }
  }
  fclose(csv);
}

bool spTracker::validate_func_delta(FunctionDescriptor *fd) {
  // Ensure that every return block for the function has the same stack delta.
  bool first = true;
  int delta = 0;
  BlockSet& ret_blocks = fd->get_return_blocks();
  for (SgAsmBlock *bb : ret_blocks) {
    SDEBUG << "Return block for func " << fd->address_string()
                << std::hex << " at " << bb->get_address() << std::dec;

    Block2IntPairMap::iterator pit = spBeforeAfterBlock.find(bb);
    if (pit != spBeforeAfterBlock.end()) {
      IntPair ip = pit->second;
      SDEBUG << " has in stack of " << ip.first;
      SDEBUG << " and out stack of " << ip.second;
      if (!first && delta != ip.second) SDEBUG << " DOES NOT MATCH!";
      delta = ip.second;
      first = false;
    }
    SDEBUG << LEND;
  }

  // If we there were no return blocks, we failed.
  if (first) return false;

  // Now we just need to store the function delta for future reference.
  SgAsmFunction* func = fd->get_func();
  if (func == NULL) return false;

  // We succeeded.
  functionDeltas[func] = delta;
  return true;
}

#if 0
void spTracker::analyzeFunc(SgAsmFunction *func) {
  FunctionDescriptor *fd = descriptor_set->get_func(func->get_entry_va());

  SDEBUG << "Starting stack depth analysis for: " << fd->address_string() << LEND;

  // This is the only non-debug line in analyzeFunc!
  spAfterCalls = getStackDepthAfterCalls(fd);
  //validate_func_delta(fd);

  if (SDEBUG) {
    SDEBUG << std::hex;
    SDEBUG << "Stack analysis summary: " << func->get_entry_va() << LEND;
    for (const Block2IntPairMap::value_type &pair : spBeforeAfterBlock) {
      SDEBUG << "  BeforeAfterBlock: block=0x" << pair.first->get_id()
             << std::dec << " before=" << pair.second.first
             << " after=" << pair.second.second << std::hex << LEND;
    }

    for (const Insn2IntMap::value_type &pair : spAfterCalls) {
      SgAsmx86Instruction* insn = pair.first;
      SDEBUG << "  Stack depth after " << debug_instruction(insn) << ": "
             << std::dec << pair.second << LEND;

      if (pushParams.find(insn) != pushParams.end()) {
        SDEBUG << "  Possible parameter pushers:" << LEND;
        for (const SgAsmx86Instruction* p : pushParams[insn]) {
          SDEBUG << "    " << debug_instruction(p) << LEND;
        }
      }
    }
    SDEBUG << std::dec;
  }
}

void spTracker::analyzeFunctions() {
  size_t size = 0;
  for (const FunctionDescriptorMap::value_type &pair : descriptor_set->get_func_map()) {
    // Get the function from the function descriptor (second half the pair), icky. :-(
    const FunctionDescriptor & fd = pair.second;

    SgAsmFunction* func = fd.get_func();
    // If we've already processed the entry continue.
    if (processed.find(func) != processed.end()) continue;


    if (!getBlockDeltas(&fd, NULL)) {
      // warnding, error, debug?
      SDEBUG << "Symbolic static analysis was unable to resolve deltas for all functions "
                  << "in call chains starting " << fd->address_string() << LEND;
      if (functionDeltas.size() > size) {
        SDEBUG << "Calculated deltas for " << functionDeltas.size() - size << " functions" << LEND ;
        size = functionDeltas.size();
      }

      // Symbolic analysis failed. Try using Ilfak's method
      //Insn2IntMap spAfterCalls;
      //Block2IntPairMap spBeforeAfterBlock;
      //ParameterMap pushParams;

      analyzeFunc(func);

      for (auto it = spBeforeAfterBlock.begin(); it != spBeforeAfterBlock.end(); ++it) {
        bDeltas[it->first] = it->second.second;
        SDEBUG << "Block Delta after " << addr_str(it->first->get_entry_va()) << " "
                    << it->second.second << LEND;
      }
    }
  }
}

#endif  // #if 0

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
