// Copyright 2015-2023 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/range/numeric.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/algorithm/reverse.hpp>
#include <boost/range/algorithm/set_algorithm.hpp>
#include <boost/optional/optional_io.hpp>

#include "znode.hpp"
#include "znode_boost.hpp"

#include "spacer.hpp"

// For expand_lets
#include "wp.hpp"

namespace pharos {

SpacerAnalyzer::SpacerAnalyzer(const DescriptorSet& ds,
                               PharosZ3Solver& z3,
                               std::string const & engine) :
  SpacerAnalyzer(ds, z3, ImportRewriteSet{}, engine)
{}

SpacerAnalyzer::SpacerAnalyzer(const DescriptorSet& ds,
                               PharosZ3Solver& z3,
                               ImportRewriteSet import_set,
                               std::string const & engine)
  :  ds_(ds), z3_(z3), import_set_(std::move(import_set))
{
  // Set the fixed point engine to use spacer and CHC
  fp_ = std::make_unique<PharosZ3Solver::Fixedpoint> (z3);
  auto params = z3_.mk_params();

  params.set("fp.engine", engine.c_str ());

  // Optionally uncomment this out for slower
  // solving, but more readable output
  // params.set ("fp.xform.slice", false);
  // params.set ("fp.xform.inline_eager", false);
  // params.set ("fp.xform.inline_linear", false);

  // Arie suggested the following options may help us
  // params.set ("fp.spacer.ground_pobs", false);
  params.set ("fp.spacer.use_euf_gen", true);

  fp_->set(params);
}

std::tuple <Z3RegMap, z3::func_decl, z3::func_decl>
SpacerAnalyzer::encode_cfg(const IR &ir,
                           const z3::expr &z3post_input,
                           const z3::expr &/*_z3post_output*/,
                           bool propagate_input,
                           std::string name,
                           boost::optional <std::vector<Register>> regsIn,
                           boost::optional <z3::func_decl> entry_relation,
                           boost::optional <z3::func_decl> exit_relation,
                           boost::optional <std::function<bool(const IRCFGVertex &)>> short_circuit,
                           ConvertCallFun convert_call) {
  auto cfg = ir.get_cfg ();
  auto mem = ir.get_mem ();
  auto bb_map = boost::get (boost::vertex_name_t (), cfg);
  auto irmap = boost::get (boost::vertex_ir_t (), cfg);
  auto cond_map = boost::get (boost::edge_name_t (), cfg);
  z3::context& ctx = *z3_.z3Context();
  SpacerRelationsMap relations;

  // XXX: This could use IRCFGVertexName
  auto bb_name = [&bb_map] (const IRCFGVertex v) {
    std::stringstream ss;
    ss << bb_map [v];
    return ss.str ();
  };

  // Build the sort (type) that will represent the state of the
  // program.  In this first implementation we will always use the
  // same type, but later we might omit inputs that are not relevant
  // at that location

  std::vector<Register> regs;
  if (regsIn) {
    regs = *regsIn;
  } else {
    boost::copy (get_all_registers (ir),
                 std::back_inserter (regs));
  }

  Z3RegMap z3nodes;
  boost::copy (regs |
               boost::adaptors::transformed(
                 [this] (const Register &x) {
                   return std::make_pair (x, z3_.treenode_to_z3(x)); }),
               std::inserter (z3nodes, z3nodes.end ()));

  // We need an extra mapping so that we can pass along the original input state through the
  // rules
  Z3RegMap z3inputnodes;
  if (propagate_input) {
    boost::copy (z3nodes |
                 boost::adaptors::transformed([] (const auto &x) {
                   Register r = x.first;
                   z3::expr e = x.second;

                   return std::make_pair (
                     r, z3::function ((r->toString() + "_input").c_str (), 0, NULL,
                                      e.get_sort ()) ());
                 }),
                 std::inserter (z3inputnodes, z3inputnodes.end ()));
  }

  // Build sort and expr vectors which we will use to construct z3
  // relations and rules
  z3::expr_vector ev (ctx);
  z3::expr_vector evinput (ctx);
  z3::expr_vector evboth (ctx);
  z3::sort_vector sv (ctx);
  z3::sort_vector svinput (ctx);
  z3::sort_vector svboth (ctx);

  // This is only used for the entry node
  z3::expr_vector evdbl (ctx);

  boost::for_each (z3inputnodes | boost::adaptors::map_values,
                   [&evinput, &evboth, &svinput, &svboth] (const z3::expr &exp) {
                     evinput.push_back (exp);
                     evboth.push_back (exp);
                     svinput.push_back (exp.get_sort ());
                     svboth.push_back (exp.get_sort ());
                   });

  boost::for_each (z3nodes | boost::adaptors::map_values,
                   [&ev, &evdbl, &evboth, &sv, &svboth] (const z3::expr &exp) {
                     ev.push_back (exp);
                     evdbl.push_back (exp);
                     evboth.push_back (exp);
                     sv.push_back (exp.get_sort ());
                     svboth.push_back (exp.get_sort ());
                   });

  if (propagate_input) {
    boost::copy (z3nodes | boost::adaptors::map_values,
                 z3_vector_back_inserter (evdbl));
  }

  // The following two functions make the z3 before and after
  // relations for the given BB

  auto make_before = [&] (const CFGVertex &v) {
    std::stringstream ss;
    ss << std::hex << std::showbase << name << ": " << bb_name (v) << " before";
    z3::func_decl before = z3::function (ss.str (), svboth, ctx.bool_sort ());
    fp_->register_relation (before);
    return before;
  };

  auto make_after = [&] (const CFGVertex &v, Z3RegMap intra_substs) {
    std::stringstream ss;
    ss << std::hex << std::showbase << name << ": " << bb_name (v) << " after";

    // We need to add any intra-block variables to the after
    // state here.  We need this specifically because outgoing edge
    // conditions may refer to these variables, even though
    // subsequent basic blocks will not.
    z3::sort_vector svafter (ctx);

    boost::copy (svboth,
                 z3_vector_back_inserter (svafter));

    boost::copy (intra_substs
                 | boost::adaptors::map_values
                 | boost::adaptors::transformed ([] (const auto &exp) {
                   return exp.get_sort ();
                 }),
                 z3_vector_back_inserter (svafter));

    z3::func_decl after = z3::function (ss.str (), svafter, ctx.bool_sort ());
    fp_->register_relation (after);
    return after;
  };

  // Now we add rules that describe the transition from a _before
  // location to an _after location
  // z3::expr r1 = z3::forall(i,j, z3::implies(loop(i,j) && i<10, loop(i+1,j+2)));

  for (const auto &v : boost::make_iterator_range (boost::vertices (cfg))) {
    z3::func_decl before = make_before (v);

    const Stmts& stmts = *irmap[v];

    // av are the after exps. first half are the original input
    // variables. second half are the modified expressions from this
    // BB (e.g., eax + 2)
    z3::expr_vector av (ctx);
    boost::copy (z3inputnodes | boost::adaptors::map_values,
                 z3_vector_back_inserter (av));

    // Bind before expression here. We use this inside convert_call
    // to create rules saying that the entrance to a function is
    // reachable.
    z3::expr before_applied = before (evboth);

    auto convert_call_partial = [&v, &convert_call] (const CallStmt &callstmt,
                                                     const z3::expr_vector &call_input_args) {
      return convert_call (callstmt, v, call_input_args);
    };
    auto substs_output = subst_stmts (stmts, mem, z3nodes, convert_call_partial);
    Z3RegMap substs = std::get<0> (substs_output);
    Z3RegMap intra_substs = std::get<1> (substs_output);
    auto fresh_vars = std::get<2> (substs_output);
    z3::expr constraints = std::get<3> (substs_output);

    boost::copy (substs | boost::adaptors::map_values,
                 z3_vector_back_inserter (av));
    boost::copy (intra_substs | boost::adaptors::map_values,
                 z3_vector_back_inserter (av));

    // The after relation consists of inter-block regs followed by
    // intra-block regs at the end.  This is necessary because
    // conditions may refer to the intra-block regs (e.g.,
    // temporaries).  Here we keep a list of the intraprocedural
    // regs used in the after relation to make using it easier
    // later.

    Z3RegMap intra_regs;
    // Create fresh variables for the intra-block registers
    boost::copy (intra_substs
                 | boost::adaptors::map_keys
                 | boost::adaptors::transformed([this] (const Register &x) {
                   return std::make_pair (x, z3_.treenode_to_z3 (x)); }),
                 std::inserter (intra_regs, intra_regs.end ()));

    z3::func_decl after = make_after (v, intra_substs);

    // We also need to store these intra-block registers with the
    // relations so that we can use them below as we create rules
    // transitioning from one block to another
    relations.emplace (v, SpacerRelations { before, after, intra_regs });

    z3::expr after_applied = after (av);

    // Quantify over the variables in the rule.  Note that we do not
    // need to quantify over intra_regs here because their initial
    // value should never be used in these rules.  They are always
    // use to save the state of another register at a particular
    // time.
    z3::expr_vector quantified_vars (ctx);
    boost::copy (z3nodes | boost::adaptors::map_values,
                 z3_vector_back_inserter (quantified_vars));
    boost::copy (z3inputnodes | boost::adaptors::map_values,
                 z3_vector_back_inserter (quantified_vars));
    // We also need to quantify over any new variables introduced
    // for the output variables of the summary call
    boost::copy (fresh_vars,
                 z3_vector_back_inserter (quantified_vars));

    z3::expr rule = z3::forall (quantified_vars,
                                z3::implies (before_applied && constraints, after_applied));
    std::stringstream ss;
    ss << std::hex << std::showbase << name << ": " << bb_name (v) << " body";
    fp_->add_rule (rule, ctx.str_symbol(ss.str ().c_str ()));
  }

  // And (any) exit point

  // Note: This must come before the transition rules
  if (exit_relation == boost::none) {
    exit_relation = z3::function (name + ": exit", svboth, ctx.bool_sort ());
    fp_->register_relation (*exit_relation);
  }

  // Now we add rules describing the transition from one basic block to another
  for (const auto &e : boost::make_iterator_range (boost::edges (cfg))) {
    // The source relation is after the source BB
    auto source = boost::source (e, cfg);
    auto source_relation = relations.at (source).after;

    // Here we need to build the source arguments, which consist of
    // the normal args from evboth and the intra-block registers
    z3::expr_vector source_args (ctx);
    // Copy the normal regs from evboth
    boost::copy (evboth,
                 z3_vector_back_inserter (source_args));
    // And then copy the intra-block regs
    boost::copy (relations.at (source).intra_regs | boost::adaptors::map_values,
                 z3_vector_back_inserter (source_args));

    auto source_app = source_relation (source_args);
    // The target relation is before the destination BB
    auto target = boost::target (e, cfg);
    auto target_relation = relations.at (target).before;
    auto target_app = target_relation (evboth);
    auto cond = z3_.to_bool (
      z3_.treenode_to_z3 (
        boost::get_optional_value_or (cond_map[e], SymbolicExpr::makeBooleanConstant (true))));

    z3::expr rule = z3::forall (source_args,
                                z3::implies (source_app && cond,
                                             target_app));

    std::stringstream ss;
    ss << std::hex << std::showbase
       << name
       << ": "
       << bb_name (source)
       << " to "
       << bb_name (target);
    fp_->add_rule (rule, ctx.str_symbol (ss.str ().c_str ()));

    // Also create a short-circuit rule when the goal is hit to jump directly to the exit
    if (short_circuit && (*short_circuit) (source)) {
      z3::expr short_circuit_rule = z3::forall (source_args,
                                                z3::implies (source_app && z3post_input,
                                                             (*exit_relation) (evboth)));
      fp_->add_rule (
        short_circuit_rule,
        ctx.str_symbol ((name + ": goal short-circuit from " + bb_name (source)).c_str ()));
    }
  }

  // Next we add a fact for the entry point
  if (entry_relation == boost::none) {
    entry_relation = z3::function (name + ": entry", svinput, ctx.bool_sort ());
    fp_->register_relation (*entry_relation);
  }

  // And we add a rule connecting the entry relation to the before entry BB
  auto entry_bb = ir.get_entry ();
  auto entry_bb_before = relations.at (entry_bb).before;
  // \forall A B C. entry_bb_before (A, B, C, A, B, C).
  z3::expr erule = z3::forall (ev,
                               entry_bb_before (evdbl));
  fp_->add_rule (erule, ctx.str_symbol ((name + ": entry rule").c_str ()));

  // Connect each exit to the any_exit relations
  auto exits = ir.get_exits ();
  for (IRCFGVertex exit : exits) {
    auto an_exit_relation = relations.at (exit).after;
    z3::expr exit_rule = z3::forall (evboth,
                                     z3::implies (an_exit_relation (evboth),
                                                  (*exit_relation) (evboth)));
    fp_->add_rule (exit_rule,
                   ctx.str_symbol ((name + ": exit from " + bb_name (exit)).c_str ()));
  }

  return std::make_tuple (z3nodes, *entry_relation, *exit_relation);

}

void
SpacerAnalyzer::setup_path_problem(rose_addr_t srcaddr, rose_addr_t tgtaddr)
{
  CG cg = CG::get_cg (ds_);
  const CGG& cgg = cg.get_graph ();
  auto vertex_name_map = boost::get (boost::vertex_name_t (), cgg);
  z3::context& ctx = *z3_.z3Context();
  const FunctionDescriptor *fromfd = cg.get_ds ()->get_func_containing_address (srcaddr);
  const FunctionDescriptor *tofd = cg.get_ds ()->get_func_containing_address (tgtaddr);
  assert (fromfd && tofd);

  CGVertex fromcgv = cg.findfd (fromfd);
  CGVertex tocgv = cg.findfd (tofd);
  assert (fromcgv != boost::graph_traits<CGG>::null_vertex ());
  assert (tocgv != boost::graph_traits<CGG>::null_vertex ());

  cutf_ (cg, fromcgv, tocgv);

  // XXX: Add input state
  goal_expr_ = ctx.constant ("hierarchical goal", ctx.bool_sort ());
  z3::func_decl goal_relation = goal_expr_->decl ();
  fp_->register_relation (goal_relation);

  // Save targetbbs so we know where to add short-circuits
  std::map<CGVertex, std::set<IRCFGVertex>> vertices_to_short_circuit;

  // First make a map from each function to its IR
  std::map<CGVertex, IR> func_to_ir;
  Register hit_var = SymbolicExpr::makeIntegerVariable (1, "hit_target")->isLeafNode ();
  boost::copy (boost::vertices (cgg) |
               boost::adaptors::transformed([&vertex_name_map, &hit_var, &fromcgv,
                                             srcaddr, tgtaddr, &vertices_to_short_circuit]
                                            (const auto &cgv) {
                 IR ir = IR::get_ir (vertex_name_map [cgv]);
                 // Ensure that CallStmts can only appear at the
                 // start of a basic block.  This may simplify the
                 // encoding of calls a little bit, especially if
                 // there are a lot of operations in the same BB
                 // before the call.

                 // This is currently disabled because split_calls
                 // breaks targetOfCallStmt because it doesn't move
                 // the label statement containing the instruction
                 // address which targetOfCallStmt looks for.

                 // ir = split_calls (ir);

                 // Entry specific changes
                 if (cgv == fromcgv) {
                   ir = change_entry (ir, srcaddr);
                   ir = init_stackpointer (ir);
                 }

                 // Remove undefined expressions
                 ir = rm_undefined (ir);

                 // Add data blocks
                 ir = add_datablocks (ir);

                 // In general we don't want to rewrite calls using rewrite_imported_calls.
                 // But it was easier for Ed to also put the logic for rewriting calls to
                 // __assert_symbolic_dummy_import into AssertStmt in that function.  So we
                 // call that here, but only rewrite __assert_symbolic_dummy_import.
                 ir = rewrite_imported_calls (ir, ImportRewriteSet {ImportCall{"ELF", "__assert_symbolic_dummy_import"}});

                 // Add reached variables
                 std::set<IRCFGVertex> vertices;
                 std::tie (ir, std::ignore, vertices) = add_reached_postcondition (
                   ir, {tgtaddr}, hit_var);
                 if (vertices.size ()) {
                   assert (vertices.size () == 1);
                   vertices_to_short_circuit [cgv].insert (*vertices.begin ());
                 }

                 return std::make_pair (cgv, ir);
               }),
               std::inserter (func_to_ir, func_to_ir.end ()));
  z3::expr z3post_input = z3_.to_bool (z3_.treenode_to_z3 (hit_var));

  IR fromir = func_to_ir.at (fromcgv);

  // Find all registers across all functions
  std::set<Register> regs;
  boost::for_each (func_to_ir | boost::adaptors::map_values,
                   [&regs] (const IR &ir) {
                     boost::copy (get_all_registers (ir),
                                  std::inserter (regs, regs.end ()));
                   });
  // Make sure mem is included
  regs.insert (fromir.get_mem ());

  // Build the sort (type) that will represent the state of the
  // program.  In this first implementation we will always use the
  // same type, but later we might omit inputs that are not relevant
  // at that location
  Z3RegMap z3inputnodes;
  boost::copy (regs |
               boost::adaptors::transformed([this] (const Register &x) {
                 return std::make_pair (x, z3_.treenode_to_z3(x)); }),
               std::inserter (z3inputnodes, z3inputnodes.end ()));

  // We need an extra mapping so that we can represent input and output states
  Z3RegMap z3outputnodes;
  boost::copy (z3inputnodes |
               boost::adaptors::transformed([] (const auto &x) {
                 Register r = x.first;
                 z3::expr e = x.second;

                 std::ostringstream ss;
                 ss << *r << "_output";

                 return std::make_pair (
                   r, z3::function (ss.str ().c_str (), 0, NULL, e.get_sort ()) ());
               }),
               std::inserter (z3outputnodes, z3outputnodes.end ()));

  z3::expr z3post_output = z3_.to_bool (z3outputnodes.at (hit_var));

  // Build vector of registers to pass to encode_cfg
  std::vector<Register> regsvec;
  boost::copy (z3inputnodes | boost::adaptors::map_keys,
               std::back_inserter (regsvec));

  // Build sort and expr vectors which we will use to construct z3
  // relations and rules
  z3::expr_vector evin (ctx);
  z3::expr_vector evout (ctx);
  z3::expr_vector evboth (ctx);
  z3::sort_vector svin (ctx);
  z3::sort_vector svboth (ctx);

  boost::copy (z3inputnodes | boost::adaptors::map_values,
               z3_vector_back_inserter (evin));

  auto get_sort = [] (const z3::expr &exp) { return exp.get_sort (); };
  boost::copy (z3inputnodes
               | boost::adaptors::map_values
               | boost::adaptors::transformed (get_sort),
               z3_vector_back_inserter (svin));

  boost::copy (z3outputnodes | boost::adaptors::map_values,
               z3_vector_back_inserter (evout));

  // Populate evboth and svboth
  boost::copy (z3inputnodes | boost::adaptors::map_values,
               z3_vector_back_inserter (evboth));
  boost::copy (z3outputnodes | boost::adaptors::map_values,
               z3_vector_back_inserter (evboth));
  boost::copy (z3inputnodes
               | boost::adaptors::map_values
               | boost::adaptors::transformed (get_sort),
               z3_vector_back_inserter (svboth));
  boost::copy (z3outputnodes
               | boost::adaptors::map_values
               | boost::adaptors::transformed (get_sort),
               z3_vector_back_inserter (svboth));

  // Then we'll make a map from each function to its summary and entry relations
  struct Relations {
    z3::func_decl summary;
    z3::func_decl entry;
  };
  std::map<CGVertex, Relations> func_to_relations;

  boost::copy (
    boost::vertices (cgg) |
    boost::adaptors::transformed([&vertex_name_map, &svboth, &svin, &ctx, this]
                                 (const auto &v) {
      std::stringstream ss;

      // Summary relation
      ss << std::hex << std::showbase << vertex_name_map[v]->get_name () << " summary";
      z3::func_decl summary = z3::function (ss.str (), svboth, ctx.bool_sort ());
      fp_->register_relation (summary);

      // Entry relation
      ss.str ("");
      ss << std::hex << std::showbase << vertex_name_map[v]->get_name () << " entry";
      z3::func_decl entry = z3::function (ss.str (), svin, ctx.bool_sort ());
      fp_->register_relation (entry);

      Relations r {summary, entry};
      return std::make_pair (v, r);
    }),
    std::inserter (func_to_relations, func_to_relations.end ()));

  // Create a fake function summary for each call to a selected
  // import function, which will return a fresh value of eax.
  std::map<ImportCall, Relations> import_to_relations;

  boost::copy (import_set_ |
               boost::adaptors::transformed([&fromir, &z3inputnodes, &svboth,
                                             &svin, &ctx, this] (const ImportCall &import)
               {
                 std::stringstream ss;
                 // Summary relation
                 ss << import << " import summary";
                 z3::func_decl summary = z3::function (ss.str (), svboth, ctx.bool_sort ());
                 fp_->register_relation (summary);

                 // Entry relation
                 ss.str ("");
                 ss << import << " import entry";
                 z3::func_decl entry = z3::function (ss.str (), svin, ctx.bool_sort ());
                 fp_->register_relation (entry);

                 // Summary rule

                 // Note: The calling code will decrement the stack
                 // pointer.  As part of our synthetic summary, we
                 // must increment the stack pointer to maintain
                 // stack neutrality.

                 // \forall EAX EBX ECX ESP EAX'. summary(EAX EBX ECX ESP EAX' EBX ECX ESP+delta)

                 // Step 1: Identify eax and esp.
                 // XXX: We should do this once in the outer function

                 auto find_reg = [&fromir, &z3inputnodes, this] (const std::string &regname)
                                 -> boost::optional<z3::expr> {
                   auto it = boost::find_if (
                     z3inputnodes,
                     [&regname, &fromir, this] (const auto &p) {
                       // XXX: Platform specific
                       return p.first == fromir.get_reg (ds_.get_arch_reg(regname));
                     });
                   if (it == z3inputnodes.end ()) {
                     GWARN << ("Unable to produce summary for imported function"
                               " because we were unable to find register ") << regname << LEND;
                     return boost::none;
                   } else {
                     return it->second;
                   };
                 };

                 boost::optional<z3::expr> eax, esp, fresh_eax;
                 eax = find_reg ("eax");

                 if (eax) {
                   fresh_eax = z3::function (
                     (eax->decl ().name ().str () + "_summary_output").c_str (), 0,
                     NULL, eax->get_sort ()) ();
                 }

                 esp = find_reg ("esp");
                 assert (esp);


                 // Step 2: Create varlists
                 z3::expr_vector quantified_vars (ctx);
                 boost::copy (z3inputnodes
                              | boost::adaptors::map_values,
                              z3_vector_back_inserter (quantified_vars));

                 if (fresh_eax)
                   quantified_vars.push_back (*fresh_eax);

                 z3::expr_vector summary_args (ctx);
                 boost::copy (z3inputnodes
                              | boost::adaptors::map_values,
                              z3_vector_back_inserter (summary_args));
                 // If we don't have eax, the summary turns into a noop.
                 boost::copy (z3inputnodes
                              | boost::adaptors::map_values
                              | boost::adaptors::transformed
                              ([&] (const auto &exp) {
                                if (eax && exp.id () == eax->id ()) {
                                  return *fresh_eax;
                                } else if (exp.id () == esp->id ()) {
                                  // Here is where we increment the stack pointer
                                  // XXX: We should actually determine the stack delta by
                                  // searching CallStmt for the appropriate import
                                  auto delta = esp->get_sort ().bv_size () / 8;
                                  z3::expr delta_const = z3_.z3Context ()->bv_val (
                                    delta, esp->get_sort ().bv_size ());
                                  return exp + delta_const;
                                } else {
                                  return exp;
                                }
                              }),
                              z3_vector_back_inserter (summary_args));

                 // Step 3: Make the rule
                 z3::expr rule = z3::forall (quantified_vars,
                                             summary (summary_args));

                 ss.str ("");
                 ss << "Summary for " << import;
                 fp_->add_rule (rule, ctx.str_symbol (ss.str ().c_str ()));

                 // Finally, return the summary and entry rules to
                 // refer to in convert_call

                 Relations r {summary, entry};

                 return std::make_pair (import, r);
               }),
               std::inserter (import_to_relations, import_to_relations.end ()));



  // Create summary rules for each function
  boost::for_each (
    func_to_ir,
    [&vertex_name_map, &z3post_input, &z3post_output, &func_to_relations,
     &import_to_relations, &ctx, &goal_expr = *goal_expr_, &z3inputnodes, &z3outputnodes,
     &regsvec, &cg, &fromcgv, &evboth, &vertices_to_short_circuit, this]
    (const decltype(func_to_ir)::value_type &v) {

      // Call encode_cfg to get the encoded version of the CFG and we'll go from there.
      auto cgv = v.first;
      auto ir = v.second;
      std::string name = vertex_name_map [cgv]->get_name ();

      Relations relations = func_to_relations.at (cgv);

      // This function tells us which functions to
      // add a short circuit rule when encoding them.
      std::function<bool(const IRCFGVertex &)> short_circuit =
        [&vertices_to_short_circuit, &cgv] (const IRCFGVertex &shortv) {
          return vertices_to_short_circuit [cgv].count (shortv);
        };

      // Create convert_call function to pass to encode_cfg.
      // convert_call maps a CallStmt to its summary rule in z3.
      auto convert_call = [&cg,
                           &cgv,
                           &func_to_relations,
                           &import_to_relations,
                           &vertices_to_short_circuit,
                           this] (const CallStmt &cs,
                                  const IRCFGVertex &srcv,
                                  const z3::expr_vector &) -> boost::optional<z3::func_decl> {

        boost::optional<Relations> r;

        auto is_import = boost::get<ImportCall> (&(std::get<1> (cs)));
        if (is_import) {
          auto it = import_to_relations.find (*is_import);

          if (it != import_to_relations.end ()) {
            r = import_to_relations.at (*is_import);
          } else {
            GWARN << "Found an unexpected call to import " << cs << LEND;
            return boost::none;
          }
        }
        else if (boost::optional<rose_addr_t> call_target = targetOfCallStmt (cs))
        {                       // Non-import
          const FunctionDescriptor *targetfd = ds_.get_func_containing_address (*call_target);

          if (!targetfd) {
            GWARN << "Found an unresolved direct call" << cs << " " << call_target << LEND;
            return boost::none;
          }

          CGVertex targetcgv = cg.findfd (targetfd);

          if (targetcgv == boost::graph_traits<CGG>::null_vertex ()) {
            GWARN << "Found an unresolved direct call" << cs << " " << call_target << LEND;
            return boost::none;
          }

          r = func_to_relations.at (targetcgv);
        }

        if (r) {
          // Create a rule saying that the called function's entry is reachable
          // z3::expr rule = z3::forall (bb_vars,
          //                             z3::implies (bb_before,
          //                                          r->entry (call_input_args)));
          // // XXX: Pass more information to make a better rule name
          // std::stringstream ss;
          // ss << "Call makes called function's entry reachable";
          // fp_->add_rule (rule, ctx.str_symbol (ss.str ().c_str ()));

          // This is really ugly but we'll mark the calling vertex as needing a short circuit
          vertices_to_short_circuit [cgv].insert (srcv);

          return r->summary;
        } else {
          return boost::none;
        }
      };

      auto cfg_relations = encode_cfg (ir,
                                       z3post_input,
                                       z3post_output,
                                       true,
                                       name,
                                       regsvec,
                                       relations.entry,
                                       boost::none,
                                       //boost::none,
                                       short_circuit,
                                       convert_call);
      auto evfunc = std::get<0> (cfg_relations);
      auto summary_relation = relations.summary;
      z3::func_decl entry_relation = std::get<1> (cfg_relations);
      z3::func_decl any_exit_relation = std::get<2> (cfg_relations);
      //z3::func_decl func_goal_relation = std::get<3> (cfg_relations);

      // We have reached our goal when the hit
      // variable has been set at the end of the exit
      // relation for the source function.
      if (cgv == fromcgv) {
        z3::expr global_goal_rule = z3::forall (
          evboth, z3::implies (any_exit_relation (evboth) && z3post_output, goal_expr));
        fp_->add_rule (global_goal_rule, ctx.str_symbol ("global goal rule"));
      }

      // Let's say we have a state with four variables
      // Let A B C D be the input state, and E F G H be the output state.
      // Let's say that the current function only accesses three variables, A, B and D.
      // Then we want to make a rule like:
      // \forall A B C D E F G H. fun_any_exit (A B D E F H) => summary_fun (A B C D E F G H) /\ C = G
      // But this isn't a horn clause.  Doh!

      // This is, but I can't figure out if it's equivalent or not.
      // \forall A B C D E F G H. fun_any_exit (A B D E F H) /\ C = G => summary_fun (A B C D E F G H)
      // I think it is...

      // Build the fun_any_exit expr
      // This is a little more complicated because we
      // need to extract the matching registers from
      // the output state.
      z3::expr_vector fun_any_exit_ev (ctx);
      boost::copy (evfunc
                   | boost::adaptors::map_keys
                   | boost::adaptors::transformed([&z3inputnodes] (const Register &r) {
                     return z3inputnodes.at (r);
                   }),
                   z3_vector_back_inserter (fun_any_exit_ev));
      boost::copy (evfunc
                   | boost::adaptors::map_keys
                   | boost::adaptors::transformed([&z3outputnodes] (const Register &r) {
                     return z3outputnodes.at (r);
                   }),
                   z3_vector_back_inserter (fun_any_exit_ev));
      z3::expr fun_any_exit = any_exit_relation (fun_any_exit_ev);

      // summary_fun expr
      z3::expr_vector summary_fun_ev (ctx);
      boost::copy (z3inputnodes
                   | boost::adaptors::map_values,
                   z3_vector_back_inserter (summary_fun_ev));
      boost::copy (z3outputnodes
                   | boost::adaptors::map_values,
                   z3_vector_back_inserter (summary_fun_ev));

      z3::expr summary_fun = summary_relation (summary_fun_ev);

      // eq expr
      std::set<Register> dont_appear;
      std::vector<z3::expr> equalities;
      // Compute the registers that don't appear in this function
      boost::set_difference (z3inputnodes
                             | boost::adaptors::map_keys,
                             evfunc
                             | boost::adaptors::map_keys,
                             std::inserter (dont_appear, dont_appear.end ()));

      // And map them to equalities
      boost::copy (
        dont_appear
        | boost::adaptors::transformed ([&z3inputnodes, &z3outputnodes] (const Register &r) {
          z3::expr t = z3inputnodes.at (r) == z3outputnodes.at (r);
          return z3inputnodes.at (r) == z3outputnodes.at (r);
        }),
        std::back_inserter (equalities));

      // Accumulate the equalities into one expression
      z3::expr equalities_expr = boost::accumulate (
        equalities,
        ctx.bool_val (true),
        [] (const z3::expr &e1, const z3::expr &e2) {
          return e1 == e2;
        });

      z3::expr rule = z3::forall (summary_fun_ev,
                                  z3::implies (fun_any_exit && equalities_expr,
                                               summary_fun));
      std::stringstream ss;
      ss << std::hex << std::showbase << vertex_name_map [cgv]->get_name () << "_summary_rule";
      fp_->add_rule (rule, ctx.str_symbol (ss.str ().c_str ()));

    });
}

std::ostream &
SpacerAnalyzer::output_problem(std::ostream & stream) const
{
  z3_.output_options(stream);
  stream << to_string();
  stream << "(query |hierarchical goal|)" << std::endl;
  return stream;
}

z3::check_result
SpacerAnalyzer::solve_path_problem()
{
  z3::check_result result = fp_->query (*goal_expr_);

  if (result == z3::sat) {
    Z3_ast a = Z3_fixedpoint_get_ground_sat_answer(*z3_.z3Context(), *fp_);
    answer_ = z3::to_expr(*z3_.z3Context(), a);
    return result;
  }
  if (result == z3::unsat) {
    answer_ = fp_->get_answer();
    return result;
  }
  answer_ = boost::none;
  return z3::unknown;
}

std::ostream &
SpacerAnalyzer::output_solution(std::ostream & stream) const
{
  if (answer_) {
    stream << *answer_;
  }
  return stream;
}

// This needs to be rewritten if we're going to use it.  I've changed encode_cfg quite a bit
// since it was written.

// SpacerResult
// SpacerAnalyzer::find_path(rose_addr_t srcaddr, rose_addr_t tgtaddr) {

//     // this will almost certainly change in the future as we consider
//     // interprocedural paths
//     IR ir = get_inlined_cfg (CG::get_cg (ds_), srcaddr, tgtaddr);

//     // Handle known imports
//     if (import_set_.size () > 0) {
//       ir = rewrite_imported_calls (ds_, ir, import_set_);
//     }

//     // set up the post condition (i.e. the hit target)
//     IRExprPtr post;
//     std::tie(ir, post) = add_reached_postcondition (ir, {tgtaddr});
//     auto z3post = z3_.to_bool (z3_.treenode_to_z3 (post));
//     //z3::context& ctx = *z3_.z3Context ();

//     auto cfg_relations = encode_cfg (ir, z3post, false);
//     z3::func_decl entry_relation = std::get<1> (cfg_relations);

//     // Add a starting fact/rule
//     z3::expr entry_expr = entry_relation ();
//     fp_->add_fact (entry_relation, nullptr);

//     z3::func_decl goal_relation = std::get<3> (cfg_relations);
//     auto goal_expr = goal_relation ();

//     z3::check_result result = fp_->query (goal_expr);

//     if (result == z3::sat) {
//       Z3_ast a = Z3_fixedpoint_get_ground_sat_answer(*z3_.z3Context(), *fp_);
//       z3::expr sat_answer = z3::to_expr(*z3_.z3Context(), a);
//       return SpacerResult(result, sat_answer);
//     }
//     else if (result == z3::unsat) {
//       return SpacerResult(result, fp_->get_answer());
//     }

//     // fall through to unknown / no answer
//     return SpacerResult(z3::unknown, boost::optional<z3::expr>());
// }

std::string
SpacerAnalyzer::to_string() const {
  return fp_->to_string();
}

TupleState
SpacerAnalyzer::subst_stmt(const Stmt& s, const Register& mem, TupleState &state,
                           PartialConvertCallFun convert_call)
{
  struct StmtVisitor : public boost::static_visitor<TupleState> {
    const Register& mem;
    PharosZ3Solver &z3_;
    z3::context &ctx;
    TupleState &state;
    PartialConvertCallFun  &convert_call;
    StmtVisitor(const Register& mem_, TupleState &state_, PharosZ3Solver &z3__,
                PartialConvertCallFun &convert_call_)
      : mem(mem_), z3_(z3__), ctx(*z3_.z3Context ()),
        state(state_), convert_call(convert_call_) {}

    auto operator()(const RegWriteStmt &rs) {
      // Substitute each value in state in rs.second
      z3::expr_vector src (ctx);
      z3::expr_vector dst (ctx);

      auto var_to_z3 = [this] (const Register &r) {
        return z3_.to_bv (z3_.treenode_to_z3 (r));
      };

      auto & interregstate = std::get<0> (state);
      auto & intraregstate = std::get<1> (state);

      // First copy the inter regstate
      boost::copy (interregstate | boost::adaptors::map_keys
                   | boost::adaptors::transformed (var_to_z3),
                   z3_vector_back_inserter (src));
      boost::copy (interregstate | boost::adaptors::map_values,
                   z3_vector_back_inserter (dst));

      // Then the intra regstate
      boost::copy (intraregstate | boost::adaptors::map_keys
                   | boost::adaptors::transformed (var_to_z3),
                   z3_vector_back_inserter (src));
      boost::copy (intraregstate | boost::adaptors::map_values,
                   z3_vector_back_inserter (dst));

      // Conver to z3 and substitute
      auto z3_expr = z3_.to_bv (z3_.treenode_to_z3 (rs.second));
      // std::cout << "Setting " << *rs.first << " to " << z3_expr.to_string ()
      //           << " before subst " << std::endl;
      z3_expr = z3_expr.substitute (src, dst);
      // std::cout << "Setting " << *rs.first << " to " << z3_expr.to_string () << std::endl;

      // boost::for_each (state | boost::adaptors::map_keys,
      //                       [] (Register r) {
      //                         std::cout << " z3inputs " << *r << std::endl;
      //                      });

      // If rs.first is a real register, store it in inter regstate.
      if (interregstate.count (rs.first) > 0) {
        interregstate.at (rs.first) = z3_expr;
      } else {
        // This is a new register, so it must be a temporary.  Put it in the intra regstate.
        map_add_or_replace (intraregstate, rs.first, z3_expr);
      }

      return state;
    }
    auto operator()(const MemWriteStmt &ms) {
      // Update memory

      z3::expr_vector src (ctx);
      z3::expr_vector dst (ctx);

      auto var_to_z3 = [this] (const Register &r) {
        return z3_.to_bv (z3_.treenode_to_z3 (r));
      };

      auto & interregstate = std::get<0> (state);
      auto & intraregstate = std::get<1> (state);

      // First copy the inter regstate
      boost::copy (interregstate | boost::adaptors::map_keys
                   | boost::adaptors::transformed (var_to_z3),
                   z3_vector_back_inserter (src));
      boost::copy (interregstate | boost::adaptors::map_values,
                   z3_vector_back_inserter (dst));

      // Then the intra regstate
      boost::copy (intraregstate | boost::adaptors::map_keys
                   | boost::adaptors::transformed (var_to_z3),
                   z3_vector_back_inserter (src));
      boost::copy (intraregstate | boost::adaptors::map_values,
                   z3_vector_back_inserter (dst));

      IRExprPtr newmem = SymbolicExpr::makeWrite (mem, ms.first, ms.second);

      // Convert to Z3 and substitute
      auto z3_expr = z3_.to_bv (z3_.treenode_to_z3 (newmem));
      z3_expr = z3_expr.substitute (src, dst);

      // Memory is always a register, so use the inter regstate
      interregstate.at (mem) = z3_expr;

      return state;
    }
    auto operator()(UNUSED const SpecialStmt &ss) {
      // Return false? It's not clear what the best thing to do here is.
      return state;
    }
    auto operator()(const AssertStmt &as) {
      auto & interregstate = std::get<0> (state);
      auto & intraregstate = std::get<1> (state);
      auto & fresh_vars = std::get<2> (state);
      auto & constraints = std::get<3> (state);

      auto e = static_cast<IRExprPtr> (as);
      auto z3_e = z3_.to_bool (z3_.treenode_to_z3 (e));
      auto new_constraints = z3_e && constraints;

      return std::make_tuple (interregstate, intraregstate, fresh_vars, new_constraints);
    }
    auto operator()(UNUSED const CommentStmt &cs) {
      return state;
    }
    auto operator()(UNUSED const CallStmt &cs) {

      // Now we need to connect the summary to the state.  Remember
      // that summary is broken into input and output values.  So
      // logically it represents summary(inputs, outputs).  Inputs is
      // easy to compute, since state_ is already in the right format.
      // We need to create fresh variables representing the output
      // state.  So basically we want to create a z3::expression that
      // looks like summary(state_, fresh_vars).

      Z3RegMap fresh_output_vars;
      z3::expr_vector summary_args (ctx);
      z3::expr_vector input_args (ctx);

      // At a call, all temporaries in the intra regstate can be
      // ignored.  Just use the inter regstate.
      auto & interregstate = std::get<0> (state);
      auto & fresh_vars = std::get<2> (state);
      auto constraints = std::get<3> (state);

      // Make the fresh output vars
      boost::copy (interregstate
                   | boost::adaptors::transformed([] (const auto &x) {
                     Register r = x.first;
                     z3::expr e = x.second;

                     return std::make_pair (
                       r, z3::function ((r->toString() + "_summary_output").c_str (),
                                        0, NULL, e.get_sort ()) ());
                   }),
                   std::inserter (fresh_output_vars, fresh_output_vars.end ()));

      // Copy the fresh output vars to the output
      boost::copy (fresh_output_vars | boost::adaptors::map_values,
                   std::inserter (fresh_vars, fresh_vars.end ()));

      // Build the summary_args and input_args vector
      boost::copy (interregstate | boost::adaptors::map_values,
                   z3_vector_back_inserter (summary_args));
      boost::copy (interregstate | boost::adaptors::map_values,
                   z3_vector_back_inserter (input_args));
      boost::copy (fresh_output_vars | boost::adaptors::map_values,
                   z3_vector_back_inserter (summary_args));

      // Use the provided std::function convert_call to obtain the
      // function summary predicate for the callee.

      const boost::optional<z3::func_decl> summary = convert_call (cs, input_args);
      // std::cout << summary << std::endl;

      // If convert_call fails, we'll never allow the transition to happen.
      z3::expr summary_fact = ctx.bool_val (false);
      if (summary) {
        summary_fact = (*summary) (summary_args);
      }

      // No need to reuse intraregstate
      return std::make_tuple (fresh_output_vars, Z3RegMap (), fresh_vars,
                              constraints && summary_fact);
    }
    auto operator()(UNUSED const InsnStmt &is) {
      return state;
    }
  };

  StmtVisitor vis(mem, state, z3_, convert_call);
  return boost::apply_visitor(vis, s);
}

TupleState
SpacerAnalyzer::subst_stmts (const Stmts& stmts, const Register& mem,
                             const Z3RegMap &z3inputs, PartialConvertCallFun convert_call)
{
  auto my_subst_stmt = [&mem, &convert_call, this] (TupleState &state, const Stmt& s) {
    return subst_stmt (s, mem, state, convert_call);
  };

  // This state will be passed on to other blocks and functions
  Z3RegMap inter_state (z3inputs);

  // This state is only for temporaries and are only valid inside this block
  Z3RegMap intra_state;

  // This will keep track of any constraints from invoking function summaries
  z3::context& ctx = *z3_.z3Context ();
  z3::expr constraints = ctx.bool_val (true);

  auto start_state = std::make_tuple (inter_state, intra_state, std::vector<z3::expr> (),
                                      constraints);

  auto out_state = boost::accumulate (stmts, start_state, my_subst_stmt);

  return out_state;
}

} // end pharos
