// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include "ir.hpp"
#include "util.hpp"
#include "masm.hpp"
#include "descriptors.hpp"
#include "graph.hpp"

#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/range/numeric.hpp>
#include <boost/range/adaptors.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/adaptor/sliced.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/copy.hpp>
#include <boost/property_map/property_map.hpp>

#include <limits>

using namespace pharos;
using namespace pharos::ir;

namespace {
namespace IRSemantics2 = Rose::BinaryAnalysis::InstructionSemantics;

using SymValue = IRSemantics2::SymbolicSemantics::SValue;
using SymValuePtr = IRSemantics2::SymbolicSemantics::SValuePtr;

using InteriorPtr = SymbolicExpr::InteriorPtr;
using Operator = SymbolicExpr::Operator;
using Nodes = SymbolicExpr::Nodes;

// A list of variable to memory expression mappings that are still valid because memory hasn't
// been overwritten yet.
struct Mem {};
using GenDescriptor = boost::variant<RegisterDescriptor, Mem>;
using Subst = std::pair<IRExprPtr, GenDescriptor>;
using Substs = std::map<IRExprPtr, Subst>;

using IRMap = std::map<const SgAsmInstruction*, Stmts>;
using EdgeCondMap = std::map<const SgAsmInstruction*, IRExprPtr>;

using RegisterStateGeneric = IRSemantics2::BaseSemantics::RegisterStateGeneric;
using RegisterStateGenericPtr = IRSemantics2::BaseSemantics::RegisterStateGenericPtr;

using SymValue = IRSemantics2::SymbolicSemantics::SValue;
using SymValuePtr = IRSemantics2::SymbolicSemantics::SValuePtr;
using SymMemoryMapState = IRSemantics2::SymbolicSemantics::MemoryMapState;
using SymMemoryMapStatePtr = IRSemantics2::SymbolicSemantics::MemoryMapStatePtr;
using SymState = IRSemantics2::SymbolicSemantics::State;
using SymStatePtr = IRSemantics2::SymbolicSemantics::StatePtr;
using SymRiscOperators = IRSemantics2::SymbolicSemantics::RiscOperators;
using SymRiscOperatorsPtr = IRSemantics2::SymbolicSemantics::RiscOperatorsPtr;
using BaseDispatcher = Rose::BinaryAnalysis::InstructionSemantics::BaseSemantics::Dispatcher;
using BaseDispatcherPtr = Rose::BinaryAnalysis::InstructionSemantics::BaseSemantics::DispatcherPtr;

using IRRegisterStatePtr = boost::shared_ptr<class IRRegisterState>;
using IRRiscOperatorsPtr = boost::shared_ptr<class IRRiscOperators>;

using SemanticsException = Rose::BinaryAnalysis::InstructionSemantics::BaseSemantics::Exception;

// Stub implementation
bool is_register(Register r) {
  return r->comment () != "";
}

std::set<Register> get_all_registers (const Stmts &stmts) {
  std::set<Register> regs;

  boost::for_each (stmts,
                   [&regs](const Stmt &stmt) {
                     std::set<IRExprPtr> exps = expsFromStmt (stmt, true);
                     std::for_each (exps.begin (), exps.end (),
                                    [&regs](const IRExprPtr &exp) {
                                      std::set<SymbolicLeafPtr> allvars = exp->getVariables ();
                                      boost::copy (allvars
                                                   | boost::adaptors::filtered (is_register),
                                                   std::inserter (regs, regs.end ()));
                                    });
                   });

  return regs;
}
}

namespace pharos {
namespace ir {

std::set<Register> get_all_registers (const IR &ir) {
  auto cfg = ir.get_cfg ();
  auto ir_map = boost::get (boost::vertex_ir_t (), cfg);
  std::set<Register> regs;

  BGL_FORALL_VERTICES (v, cfg, IRCFG) {
    boost::copy (::get_all_registers (*(ir_map [v])),
                 std::inserter (regs, regs.end ()));
  }

  return regs;
}

IR init_stackpointer (const IR& ir_) {
  IR ir = ir_;
  IRCFG cfg = ir.get_cfg ();
  IRCFGVertex entry = ir.get_entry ();
  auto stmts = boost::get (boost::vertex_ir_t (), cfg, entry);
  auto sp = ir.get_reg (ir.get_ds ()->get_arch_reg ("esp"));

  // Write a constant value to the stack pointer
  int64_t constant;
  switch (sp->nBits ()) {
   case 32:
    constant = 0xbfff0000L;
    break;
   case 64:
    constant = 0x7fffffff0000L;
    break;
   default:
    assert (false);
    abort ();
  }

  auto stmt = RegWriteStmt (sp, SymbolicExpr::makeIntegerConstant (sp->nBits (), constant));

  // Prepend stmt to the entry block
  stmts->insert (stmts->begin (), stmt);

  boost::put (boost::vertex_ir_t (), cfg, entry, stmts);

  return ir;
}
}
}

namespace {
IRExprPtr rm_undefined_in_exp (const IRExprPtr &e) {
  if (e->flags () & SymbolicExpr::Node::UNSPECIFIED) {
    return SymbolicExpr::makeIntegerConstant (e->nBits (), 0, "rm_undefined");
  }

  InteriorPtr i = e->isInteriorNode ();
  // Defined leafs are ok
  if (!i) return e;

  auto children = i->children ();
  std::vector <IRExprPtr> new_children;

  std::transform (children.begin (), children.end (),
                  std::back_inserter (new_children),
                  [] (IRExprPtr childe) {
                    return rm_undefined_in_exp (childe);
                  });
  auto inew = SymbolicExpr::Interior::instance (i->getOperator (),
                                                new_children);

  if (inew != i) return inew;
  else return i;
}

}

namespace pharos {
namespace ir {
IR rm_undefined (const IR& ir_) {
  IR ir = ir_;
  IRCFG cfg = ir.get_cfg ();
  auto ir_map = boost::get (boost::vertex_ir_t (), cfg);

  struct StmtVisitor : public boost::static_visitor<Stmt> {

    StmtVisitor() {}

    Stmt operator()(RegWriteStmt &rs) const {
      return RegWriteStmt (rs.first,
                           rm_undefined_in_exp (rs.second));
    }
    Stmt operator()(MemWriteStmt &ms) const {
      return MemWriteStmt (rm_undefined_in_exp (ms.first),
                           rm_undefined_in_exp (ms.second));
    }
    Stmt operator()(SpecialStmt &ss) const {
      return ss;
    }
    Stmt operator()(AssertStmt &as) const {
      return AssertStmt (rm_undefined_in_exp (static_cast <IRExprPtr> (as)));
    }
    Stmt operator()(CallStmt &cs) const {
      return CallStmt (rm_undefined_in_exp (std::get<0> (cs)),
                       std::get<1> (cs),
                       std::get<2> (cs));
    }
    Stmt operator()(InsnStmt &is) const {
      return is;
    }
    Stmt operator()(CommentStmt &cs) const {
      return cs;
    }
  };

  BGL_FORALL_VERTICES (v, cfg, IRCFG) {
    auto stmts = ir_map [v];
    std::transform (stmts->begin (),
                    stmts->end (),
                    stmts->begin (),
                    [] (Stmt &stmt) {
                      return boost::apply_visitor (StmtVisitor (), stmt);
                    });
  }

  return ir;

}

IR add_datablocks (const IR& ir_) {
  IR ir = ir_;
  IRCFG cfg = ir.get_cfg ();
  auto name_map = boost::get (boost::vertex_name_t (), cfg);
  auto ir_map = boost::get (boost::vertex_ir_t (), cfg);

  std::set<BasicBlockPtr> basicblocks;
  std::set <DataBlockPtr> datablocks;
  std::map <DataBlockPtr, std::set <std::pair<rose_addr_t, uint8_t>>> data;

  // I wish this could be done as one range sequence, but there could be multiple
  // datablocks per basic block, and so it would require a flattening adaptor which boost
  // doesn't have.

  // Maybe we should add it?
  // https://stackoverflow.com/questions/44508979/boost-range-adaptor-flattened

  // Populate the set of BBs
  boost::copy (boost::vertices (cfg)
               // Map from vertex to BB
               | boost::adaptors::transformed ([&] (const auto &v) -> boost::optional<BasicBlockPtr> {
                   auto addr = name_map [v].get_insn_addr ();
                   if (addr) {
                     auto block = ir.get_ds ()->get_block (*addr);
                     assert (block);
                     return block;
                   } else
                     return boost::none;
                 })
               | boost::adaptors::filtered ([] (const auto &bb) {
                 return bb != boost::none;
               })
               | boost::adaptors::transformed ([] (const auto &bb) {
                 return *bb;
               }),
               std::inserter (basicblocks, basicblocks.end ()));

  // Then copy data blocks
  boost::for_each (basicblocks,
                   [&] (const auto &bb) {
                     boost::copy (bb->dataBlocks (),
                                  std::inserter (datablocks, datablocks.end ()));
                   });

  // And convert to bytes
  boost::copy (datablocks
               | boost::adaptors::transformed (
                 [&] (const auto &db) {
                   decltype(data)::mapped_type tmpset;
                   boost ::copy (db->read (ir.get_ds ()->get_partitioner ().memoryMap ())
                                 | boost::adaptors::indexed (db->address ())
                                 // Convert index_value to pair
                                 | boost::adaptors::transformed ([&] (const auto &iv) {
                                   return std::make_pair (iv.index (), iv.value ());
                                 }),
                                 std::inserter (tmpset, tmpset.end ()));

                   return std::make_pair (db, tmpset);
                 }),
               std::inserter (data, data.end ()));


  // Ideally it would be nice to make a new vertex for each data block initialization, but
  // a limitation of the current IRCFG is that the entry must be tied to a SgAsmStatement,
  // which would make that awkward.

  Stmts new_stmts;

  boost::for_each (
    data,
    [&] (const auto &p) {
      auto db = p.first;
      auto m = p.second;

      std::stringstream ss;
      ss << "Initialization of " << db->printableName ();
      new_stmts.push_back (CommentStmt (ss.str ()));

      boost::copy (
        m
        | boost::adaptors::transformed ([&] (const auto &p2) {
          auto addr = SymbolicExpr::makeIntegerConstant (
            ir.get_ds ()->get_ip_reg ().nBits (), p2.first);
          auto v = SymbolicExpr::makeIntegerConstant (8, p2.second);
          return MemWriteStmt (addr, v);
        }),
        std::back_inserter (new_stmts));
    });

  // Prepend new statements to entry block
  auto entryv = ir.get_entry ();
  auto stmts = ir_map [entryv];
  // Is this horribly inefficient?
  stmts->insert (stmts->begin (), new_stmts.begin (), new_stmts.end ());

  return ir;
}

}
}

namespace {
// Remove temporary variables that aren't used anymore
Stmts remove_unused_statements(Stmts &stmts_, std::vector<IRExprPtr> exps) {
  Stmts livestmts = stmts_;
  Stmts stmts;

  do {
    stmts = livestmts;
    livestmts.clear();
    std::set<Register> usedvars;

    auto process_exp = [&usedvars] (const IRExprPtr &exp) {
      std::set<SymbolicLeafPtr> newusedvars = exp->getVariables ();
      boost::copy (newusedvars,
                   std::inserter(usedvars, usedvars.end()));

    };

    boost::for_each (exps,
                     process_exp);

    boost::for_each (stmts,
                     [&process_exp] (Stmt &stmt) {
                       std::set<IRExprPtr> myexps = expsFromStmt(stmt, false);
                       boost::for_each(myexps,
                                       process_exp);
                     });

    // std::cout << "recorded " << usedvars.size() << " variables" << std::endl;

    struct StmtVisitor : public boost::static_visitor<bool> {

      std::set<Register> usedvars;

      StmtVisitor(std::set<Register> &usedvars_) : usedvars(usedvars_) {}

      // Only keep RegWriteStmt if the variable is used XXX or a reg
      bool operator()(RegWriteStmt &rs) const {
        return is_register(rs.first) || usedvars.count(rs.first);
      }
      bool operator()(UNUSED MemWriteStmt &ms) const {
        return true;
      }
      bool operator()(UNUSED SpecialStmt &ss) const {
        return true;
      }
      bool operator()(UNUSED AssertStmt &as) const {
        return true;
      }
      bool operator()(UNUSED CallStmt &cs) const {
        return true;
      }
      bool operator()(UNUSED InsnStmt &is) const {
        return true;
      }
      bool operator()(UNUSED CommentStmt &cs) const {
        return true;
      }
    };

    StmtVisitor sv(usedvars);
    boost::copy (stmts | boost::adaptors::filtered (boost::apply_visitor (sv)),
                 std::back_inserter (livestmts));
    // Keep running as long as we decreased the number of statements.  By removing one
    // statement, we may remove uses that were keeping around another statement
  } while (livestmts.size() < stmts.size());

  return livestmts;

}

void substituteExpression(SymValuePtr &svalue, Substs &substs) {

  // This visitor visits the expression in svalue and creates a list of any substitutions to be
  // applied.  This is probably slightly more efficient than just trying all the substitutions
  // all the time.
  class Visitor : public SymbolicExpr::Visitor {

   private:
    Substs substs;

   public:
    Substs usedsubsts;

    // I LOVE C++ AND ITS LACK OF CLOSURES!!!!!
    Visitor() {}
    Visitor(Substs &substs_) : substs(substs_) { }

    virtual SymbolicExpr::VisitAction preVisit (const SymbolicExprPtr &ptr) {

      SymbolicLeafPtr leaf;
      if ((leaf = ptr->isLeafNode()) && (substs.count(leaf) == 1)) {
        auto c = substs.find(leaf);
        assert (c != substs.end ());
        usedsubsts.insert (*c);
      }

      return SymbolicExpr::VisitAction::CONTINUE;
    }
    virtual SymbolicExpr::VisitAction postVisit (UNUSED const SymbolicExprPtr &ptr) {
      return SymbolicExpr::VisitAction::CONTINUE;
    }
  };

  Visitor v;
  bool cont = true;
  // Keep applying substitutions until we run out. We need to do this multiple times because a
  // substitution v->e e could refer to other variables that could be further simplified.
  while (v = Visitor(substs), svalue->get_expression()->depthFirstTraversal(v), cont) {
    // Visitor v(substs);
    // svalue->get_expression()->depthFirstTraversal(v);

    cont = false;
    for (auto& kv : v.usedsubsts) {

      // We were accessing kv.first, but it hasn't changed, so use kv.second in its place.
      SymbolicExprPtr newexp = svalue->get_expression()->substitute(kv.first, kv.second.first);
      if (svalue->get_expression() != newexp) {
        //std::cout << "Substitution of " << *kv.second.first << " for " << *kv.first << std::endl;
        cont = true;
        svalue->set_expression(newexp);
      }
    }
  }
}

class IRRiscOperators: public SymRiscOperators
{

 public:
  IRMap irmap;
  Substs substs;

  // The default implementation of interrupt just clears the state.
  // Instead we throw an exception which will turn into a Special
  // statement
  void interrupt(int majr, int minr) override {
    std::stringstream ss;
    ss << "Interrupt " << majr << ":" << minr;
    throw SemanticsException(ss.str(), NULL);
  }

  static IRRiscOperatorsPtr instance(const SymStatePtr &state) {
    return IRRiscOperatorsPtr(new IRRiscOperators(state));
  }

  static IRRiscOperators* promote(BaseRiscOperators *ops) {
    IRRiscOperators *r = dynamic_cast<IRRiscOperators*> (ops);
    assert (r);
    return r;
  };

  static IRRiscOperatorsPtr promote(const BaseRiscOperatorsPtr &ops) {
    IRRiscOperatorsPtr retval = boost::dynamic_pointer_cast<IRRiscOperators>(ops);
    assert (retval);
    return retval;
  }

 protected:
  explicit IRRiscOperators(const SymStatePtr &state)
    : SymRiscOperators(state, {}) {};
};

// Define how we want to represent a register state.
class IRRegisterState: public RegisterStateGeneric
{
  // Create the register state and initialize the register values.
  explicit IRRegisterState(
    const BaseSValuePtr& valueProtoval,
    RegisterDictionaryPtrArg rd,
    const RegisterVector init_regs, RegisterDescriptor& ipreg)
    : RegisterStateGeneric(valueProtoval, rd)
  {
    // Create an X86 instruction dispatcher and initialize the "usual" registers with values.
    // Normally these would be the values in the state, here they're just "names" for the
    // registers.  We're never going to overwrite the registers so this is a completely static
    // dictionary of registers.
    initialize_nonoverlapping(init_regs, false);
    Reg_IP = ipreg;
  }

  IRRegisterState(const IRRegisterState &rs)
    : RegisterStateGeneric(rs) {
    Reg_IP = rs.Reg_IP;
  }

 public:

  RegisterDescriptor Reg_IP;

  // Construct an instance of an IR register state.
  static IRRegisterStatePtr instance(const SymValuePtr &proto,
                                     RegisterDictionaryPtrArg rd,
                                     const RegisterVector init_regs,
                                     RegisterDescriptor& ipreg)
  {
    return IRRegisterStatePtr(new IRRegisterState(proto, rd, init_regs, ipreg));
  }

  // Called every time a register is read.
  BaseSValuePtr readRegister(RegisterDescriptor reg, const BaseSValuePtr &dflt,
                             BaseRiscOperators *ops) override {
    // Clone ourselves so that we can read from a
    // register.  This is needed so that when we read from AL, we
    // don't remove the EAX register.  Whoops.

    IRRegisterState aclone(*this);

    BaseSValuePtr value = aclone.RegisterStateGeneric::readRegister(reg, dflt, ops);
    SymValuePtr svalue = SymValue::promote(value);
    SymValuePtr sdflt = SymValue::promote(dflt);

    //std::string regname = unparseX86Register(reg, {});
    //std::cout << *svalue << " = RegRead(" << regname << ")" << std::endl;

    SymbolicLeafPtr leaf = sdflt->get_expression()->isLeafNode();
    assert (leaf);

    IRRiscOperators *irops = IRRiscOperators::promote (ops);

    // We can substitute here.  The expression returned by
    // substitution here is valid for the RegWriteStmt we are going
    // to produce.  However, we need to be careful to store the
    // non-substituted value in substs.  This is because it could
    // become invalidated in the future.

    auto non_subst_expr = svalue->get_expression ();

    substituteExpression (svalue, irops->substs);
    Stmt stmt = RegWriteStmt(leaf, svalue->get_expression());

    irops->irmap[irops->currentInstruction()].push_back(stmt);
    irops->substs[leaf] = std::make_pair (non_subst_expr, reg);;

    return dflt;
  }

  // Called every time a register is written.
  void writeRegister(RegisterDescriptor reg, const BaseSValuePtr &value,
                     BaseRiscOperators *ops) override {
    SymValuePtr svalue = SymValue::promote(value);
    std::string regname = unparseX86Register(reg, {});

    IRRiscOperators *irops = IRRiscOperators::promote (ops);

    if (reg == Reg_IP) {
      substituteExpression(svalue, irops->substs);
      // By writing svalue into eip we basically allow copy
      // propagation of eip.  This is important because je produces
      // a statement like:
      // eip <- if (foo) bar else eip
      RegisterStateGeneric::writeRegister(reg, svalue, ops);
      //std::cout << "writing to rip " << *svalue << std::endl;
    } else {

      // Expand any substitutions that are in irops->substs
      substituteExpression(svalue, irops->substs);

      auto overlaps = overlappingRegisters(reg);
      assert (overlaps.size() == 1);
      RegisterDescriptor fullreg = overlaps[0].desc;
      SymValuePtr dflt = SymValue::instance_undefined (fullreg.get_nbits());
      SymValuePtr regvar = SymValue::promote(RegisterStateGeneric::readRegister(fullreg, dflt, ops));
      SymbolicLeafPtr regleaf = regvar->get_expression()->isLeafNode();
      assert (regleaf);
      //std::cout << "hmm " << unparseX86Register(reg, {}) << svalue->get_width() << *regvar << std::endl;

      // regvar is the full variable we are writing to.  But the
      // original value we are writing here was for a sub-register.
      // Thus we need to combine that value with (possibly) the
      // higher and lower bits from the original full register that
      // are not being modified.

      // Here's a crappy diagram, where ---- represents the original
      // value of the register.  This assumes fullreg.get_offset()
      // is 0, which isn't always true (i.e. for OF)

      // v fullreg.nbits() v reg.nbits + off v reg.off    0
      // ------------------|     svalue      |-------------
      const int int_width = 32;
      IRExprPtr exp = svalue->get_expression();
      // Add high portion if necessary
      if (reg.get_nbits() + reg.get_offset() < fullreg.get_nbits() + fullreg.get_offset()) {
        // std::cout << "i'm high " << reg.get_nbits() << " " << reg.get_offset() << " " << fullreg.get_nbits() << std::endl;
        IRExprPtr high = SymbolicExpr::makeExtract(
          SymbolicExpr::makeIntegerConstant(int_width, reg.get_nbits() + reg.get_offset()),
          SymbolicExpr::makeIntegerConstant(int_width, fullreg.get_nbits()),
          regleaf);
        exp = SymbolicExpr::makeConcat(high, exp);
      }
      // Add low portion if necessary
      if (reg.get_offset() > fullreg.get_offset()) {
        // std::cout << "i'm low " << fullreg << " " << reg.get_offset() << " " << reg.get_nbits() << std::endl;
        IRExprPtr low = SymbolicExpr::makeExtract(
          SymbolicExpr::makeIntegerConstant(int_width, 0),
          SymbolicExpr::makeIntegerConstant(int_width, reg.get_offset()),
          regleaf);
        exp = SymbolicExpr::makeConcat(exp, low);
      }

      Stmt stmt = RegWriteStmt(regleaf, exp);

      // XXX: Why is ops not in a shared pointer?
      irops->irmap[irops->currentInstruction()].push_back(stmt);

      // Invalidate any substitutions for reg
      Substs validsubsts;
      std::remove_copy_if(irops->substs.begin(),
                          irops->substs.end(),
                          std::inserter(validsubsts, validsubsts.end()),
                          [&reg, &fullreg](Substs::value_type &p) {
                            if (p.second.second.which() == 0) {
                              RegisterDescriptor &rd = boost::get<RegisterDescriptor> (p.second.second);

                              return rd == reg || rd == fullreg;
                            } else return false; // Mem
                          });
      irops->substs = validsubsts;
    }
  }
};

using IRMemoryStatePtr = boost::shared_ptr<class IRMemoryState>;

// Define how we want to represent a memory state.
class IRMemoryState: public SymMemoryMapState
{

  Register mem; // The memory
  bool memset;

  explicit IRMemoryState(const SymValuePtr &addrProto,
                         const SymValuePtr &valueProto):
    SymMemoryMapState(addrProto, valueProto)
  {
    memset = false;
    // Create a dummy memory so we can return something in case
    // there is no memory accesses and someone calls getMemoryVar()
    mem = SymbolicExpr::makeMemoryVariable(addrProto->get_width(),
                                           valueProto->get_width())->isLeafNode();
  }

 public:

  Register getMemoryVar() {
    return mem;
  }

  // Construct an instance of an IR register state.
  static IRMemoryStatePtr instance(const SymValuePtr &addrProto,
                                   const SymValuePtr &valueProto) {
    return IRMemoryStatePtr(new IRMemoryState(addrProto, valueProto));
  }

  // Called every time memory is read.
  BaseSValuePtr readMemory(const BaseSValuePtr &addr, const BaseSValuePtr &dflt,
                           UNUSED BaseRiscOperators *addrOps,
                           BaseRiscOperators *valOps) override {

    if (!memset) {
      // This is the first time that readMemory was called, so let's
      // create a memory with the proper sizes
      mem = SymbolicExpr::makeMemoryVariable(addr->get_width(),
                                             dflt->get_width())->isLeafNode();
      assert (mem);
      mem->comment("M");
      memset = true;
    }

    size_t nbits = dflt->get_width();
    SymValuePtr saddr = SymValue::promote(addr);

    IRRiscOperators *irops = IRRiscOperators::promote (valOps);

    SymValuePtr smemread = SymValue::instance_undefined(nbits);
    smemread->set_expression(SymbolicExpr::makeRead(mem, saddr->get_expression()));

    // We can substitute here.  The expression returned by
    // substitution here is valid for the RegWriteStmt we are going
    // to produce.  However, we need to be careful to store the
    // non-substituted value in substs.  This is because it could
    // become invalidated in the future.

    auto non_subst_expr = smemread->get_expression ();
    substituteExpression (smemread, irops->substs);

    SymValuePtr newvar = SymValue::instance_undefined(nbits);
    SymbolicLeafPtr leaf = newvar->get_expression()->isLeafNode();

    Stmt stmt = RegWriteStmt(leaf, smemread->get_expression());

    irops->irmap[irops->currentInstruction()].push_back(stmt);
    irops->substs[leaf] = std::make_pair (non_subst_expr, Mem());

    return newvar;
  }

  // Called every time memory is written.
  void writeMemory(const BaseSValuePtr &addr, const BaseSValuePtr &value,
                   UNUSED BaseRiscOperators *addrOps,
                   BaseRiscOperators *valOps) override {

    if (!memset) {
      // This is the first time that writeMemory was called, so let's
      // create a memory with the proper sizes
      mem = SymbolicExpr::makeMemoryVariable(addr->get_width(),
                                             value->get_width())->isLeafNode();
      assert (mem);
      mem->comment("M");
      memset = true;
    }

    SymValuePtr saddr = SymValue::promote(addr);
    SymValuePtr svalue = SymValue::promote(value);

    IRRiscOperators *irops = IRRiscOperators::promote (valOps);
    // Expand any substitutions that are in svalue
    substituteExpression(svalue, irops->substs);
    substituteExpression(saddr, irops->substs);

    Stmt stmt = MemWriteStmt(saddr->get_expression(), svalue->get_expression());
    // std::cout << stmt << std::endl;
    irops->irmap[irops->currentInstruction()].push_back(stmt);

    // Invalidate any memory subst
    Substs validsubsts;
    std::remove_copy_if (irops->substs.begin(),
                         irops->substs.end(),
                         std::inserter(validsubsts, validsubsts.end()),
                         [](Substs::value_type &p) { return p.second.second.which() == 1; /* Mem */ });
    irops->substs = validsubsts;
  }
};

}

namespace pharos {
namespace ir {
std::ostream& operator<<(std::ostream &out, const ErrorNode &) {
  out << "ErrorNode";
  return out;
}
std::ostream& operator<<(std::ostream &out, const OtherNode &) {
  out << "OtherNode";
  return out;
}
std::ostream& operator<<(std::ostream &out, const IRVertexName &vn) {

  struct vis : public boost::static_visitor<std::ostream&> {

    std::ostream &out;

    vis (std::ostream &out_) : boost::static_visitor<std::ostream&> (), out (out_) {};

    std::ostream& operator ()(const ErrorNode& op) const {
      out << op;
      return out;
    }

    std::ostream& operator ()(const OtherNode& op) const {
      out << op;
      return out;
    }

    std::ostream& operator ()(const SgAsmStatement * const & op) const {
      out << std::hex << std::showbase << op->get_address ();
      return out;
    }

  };

  return boost::apply_visitor ( vis (out), vn );
}
std::ostream& operator<<(std::ostream &out, const RegWriteStmt &stmt) {
  out << "RegWriteStmt(" << *stmt.first << ", " << *stmt.second << ")";
  return out;
}
std::ostream& operator<<(std::ostream &out, const MemWriteStmt &stmt) {
  out << "MemWriteStmt(" << *stmt.first << ", " << *stmt.second << ")";
  return out;
}
std::ostream& operator<<(std::ostream &out, const InsnStmt &stmt) {
  out << "InsnStmt(" << std::hex << stmt.first << std::dec << ", " << stmt.second << ")";
  return out;
}
std::ostream& operator<<(std::ostream &out, const SpecialStmt &stmt) {
  out << "SpecialStmt(" << (std::string) stmt << ")";
  return out;
}
std::ostream& operator<<(std::ostream &out, UNUSED const InternalCall &c) {
  out << "internal";
  return out;
}
std::ostream& operator<<(std::ostream &out, const ImportCall &c) {
  out << "import, " << c.first << "!" << c.second;
  return out;
}
std::ostream& operator<<(std::ostream &out, const CallStmt &stmt) {
  out << "CallStmt(" << *std::get<0> (stmt) << ", " << std::get<1> (stmt) << ")";
  return out;
}
std::ostream& operator<<(std::ostream &out, const AssertStmt &stmt) {
  out << "AssertStmt(" << *(IRExprPtr) (stmt) << ")";
  return out;
}
std::ostream& operator<<(std::ostream &out, const CommentStmt &stmt) {
  out << "CommentStmt(" << std::string (stmt) << ")";
  return out;
}
std::ostream& operator<<(std::ostream &out, const Stmts &stmts) {
  std::for_each(stmts.begin(), stmts.end(),
                [&out](const Stmt &stmt) { out << stmt << std::endl; });
  return out;
}
std::ostream& operator<<(std::ostream &out, const StmtsPtr &stmtsptr) {
  out << *stmtsptr;
  return out;
}

std::ostream& operator<<(std::ostream &out, const EdgeCond &edgecond) {
  if (edgecond) {
    out << *edgecond.get();
  } else {
    out << "none";
  }
  return out;
}

std::set<IRExprPtr> expsFromStmt(const Stmt &stmt, bool includeWrites) {

  struct StmtVisitor : public boost::static_visitor<std::set<IRExprPtr>> {
    const bool includeWrites;
    StmtVisitor (const bool includeWrites_) : includeWrites (includeWrites_) {}
    std::set<IRExprPtr> operator()(const RegWriteStmt &rs) const {
      if (includeWrites) return { rs.first, rs.second }; else return { rs.second };
    }
    // Should we include Mem here when includeWrites is true?
    std::set<IRExprPtr> operator()(const MemWriteStmt &ms) const { return { ms.first, ms.second }; }
    std::set<IRExprPtr> operator()(UNUSED const InsnStmt &is) const { return {}; }
    std::set<IRExprPtr> operator()(UNUSED const SpecialStmt &ss) const { return {}; }
    std::set<IRExprPtr> operator()(UNUSED const AssertStmt &as) const { return { static_cast<IRExprPtr> (as) }; }
    std::set<IRExprPtr> operator()(const CallStmt &cs) const { return { std::get<0> (cs) }; }
    std::set<IRExprPtr> operator()(UNUSED const CommentStmt &cs) const { return {}; }
  };
  return boost::apply_visitor( StmtVisitor (includeWrites), stmt );
}

// For example, in (ite[32] zf_0[1] 0x00401004<4198404>[32]
// 0x00401022<4198434>[32]), return zf_0, 0x401004 and 0x401022.
boost::optional<std::tuple<IRExprPtr, SymbolicLeafPtr, SymbolicLeafPtr>> get_cjmp_targets(IRExprPtr e) {
  InteriorPtr intnode = e->isInteriorNode();
  if (!intnode) return boost::none;
  Operator op = intnode->getOperator();
  if (op != SymbolicExpr::OP_ITE) return boost::none;
  Nodes nodes = intnode->children();
  IRExprPtr cond = nodes[0];
  SymbolicLeafPtr left = nodes[1]->isLeafNode();
  SymbolicLeafPtr right = nodes[2]->isLeafNode();
  if (!left || !right) return boost::none;

  return std::make_tuple (cond, left, right);
}

// Given a symbolic value of rip and a target address, return the
// proper edge condition. For example, in (ite[32] zf_0[1]
// 0x00401004<4198404>[32] 0x00401022<4198434>[32]) and 0x401004,
// return zf_0.  For 0x401022, return NOT zf_0.
boost::optional<IRExprPtr> get_edge_cond(IRExprPtr rip_exp, rose_addr_t dest) {
  if (auto targets = get_cjmp_targets (rip_exp)) {
    IRExprPtr c;
    SymbolicLeafPtr l, r;
    std::tie(c, l, r) = targets.get();
    if (l->isIntegerConstant() && *l->toUnsigned() == dest) return c;
    else if (r->isIntegerConstant() && *r->toUnsigned() == dest)
      return SymbolicExpr::makeInvert(c);
    else return boost::none;
  } else return boost::none;
}

IR IR::get_ir(const FunctionDescriptor* fd) {
  PD::Graph cfg = fd->ds.get_new_pdg_graph ().getFunctionCfgByReachability (fd);

  // Remove non-instruction vertices
  {
    std::vector<PD::Graph::ConstVertexIterator> remove;

    for (auto vi = cfg.vertices ().begin (); vi != cfg.vertices ().end (); vi++) {
      if (vi->value ().get_type () != PD::V_INSTRUCTION)
        remove.push_back (vi);
    }

    for (auto vi : remove) {
      cfg.eraseVertex (vi);
    }
  }

  //std::cout << "---- Creating analysis domain" << std::endl;
  // Build an instance of our IR analysis domain.  We only need to build it once, because we
  // never actually write to it in any way.
  static SymValuePtr protoval = SymValue::instance();

  RegisterDictionaryPtr regdict = fd->ds.get_regdict();
  const RegisterVector init_regs = fd->ds.get_usual_registers();
  RegisterDescriptor ipreg = fd->ds.get_ip_reg();
  static IRRegisterStatePtr rstate = IRRegisterState::instance(
    protoval, regdict, init_regs, ipreg);
  static IRMemoryStatePtr mstate = IRMemoryState::instance(protoval, protoval);
  SymStatePtr state = SymState::instance(rstate, mstate);
  IRRiscOperatorsPtr rops = IRRiscOperators::instance(state);
  const P2::Partitioner& partitioner = fd->ds.get_partitioner();
  BaseDispatcherPtr dispatcher = partitioner.newDispatcher(rops);

  if (!dispatcher) {
    GFATAL << "This tool requires instruction semantics, which are not currently "
           << "supported for architecture '" << fd->ds.get_arch_name () << "'." << LEND;
    exit (EXIT_FAILURE);
  }

  EdgeCondMap edgecondmap;

  const CallDescriptorMap &calls = fd->ds.get_call_map ();

  // Create the IR
  for (const PD::Graph::Vertex & vertex: cfg.vertices ()) {
    //SgAsmBlock* block = boost::get(boost::vertex_name, cfg, vertex);

    //const SgAsmStatementPtrList & insns = block->get_statementList();

    // for (size_t i=0; i<insns.size(); ++i) {
    const SgAsmInstruction *insn = vertex.value ().get_insn (); //isSgAsmX86Instruction(insns[i]);
    assert (insn);

    // To print boundaries between native instructions.
    //std::cout << "---- Insn: " << debug_instruction(insn) << std::endl;
    // Process the instruction.
    rops->irmap[insn].push_back(InsnStmt(insn->get_address(), debug_instruction(insn)));
    try {
      // processInstruction should probably accept a const
      dispatcher->processInstruction(const_cast<SgAsmInstruction*> (insn));
    } catch (SemanticsException &e) {
      // XXX: HACK
      rops->irmap[insn].push_back(SpecialStmt(e.what()));
    }

    // Is this a call?
    if (calls.count (insn->get_address ())) {
      const CallDescriptor &cd = calls.at (insn->get_address ());
      Call call = InternalCall ();
      BaseSValuePtr cond = rstate->RegisterStateGeneric::readRegister(
        rstate->Reg_IP,
        SymValue::instance_undefined (rstate->Reg_IP.nBits ()),
        boost::static_pointer_cast<BaseRiscOperators> (rops).get());
      IRExprPtr targetexp = SymValue::promote (cond)->get_expression ();

      // This is a hack to detect calls to PLT entries in ELFs
      auto elf_import_hack = [&fd, &cd] () -> boost::optional<std::string> {

        auto range = cd.get_targets ()
        // Only obtain import funcs
        | boost::adaptors::filtered ([&fd] (rose_addr_t target) -> bool {
          const FunctionDescriptor* tfd = fd->ds.get_func(target);
          if (!tfd) return false;
          const SgAsmFunction* func = tfd->get_func ();
          if (!func) return false;

          return func->get_reason () & SgAsmFunction::FUNC_IMPORT;
        })
        // Get the first import func
        // XXX: Ugh this wants a random access range.  But we will probably only have one of these 99.99999% of the time
        //| boost::adaptors::sliced (0, 1)
        // Get its name
        | boost::adaptors::transformed ([fd] (rose_addr_t target) -> std::string {
          // precondition: tfd and func exist
          const FunctionDescriptor* tfd = fd->ds.get_func(target);
          const SgAsmFunction* func = tfd->get_func ();
          std::string import_name = func->get_name();
          // But try to strip off the "@plt" since a better future
          // fix will use the import descriptor that doesn't have it.
          size_t len = import_name.size();
          if (len > 5 && import_name.substr(len-4, 4) == "@plt") {
            import_name = import_name.substr(0, len-4);
          }
          return import_name;
        });
        auto import_name_iter = boost::begin (range);

        if (import_name_iter == boost::end (range)) {
          return boost::none;
        } else {
          return boost::optional<std::string> (*import_name_iter);
        }
      };

      if (boost::optional<std::string> import_name = elf_import_hack ()) {
        call = ImportCall ("ELF", *import_name);
      } else if (cd.get_target_location () == CallInternal) {
        call = InternalCall ();
      } else if (cd.get_target_location () == CallExternal) {
        call = ImportCall (cd.get_import_descriptor ()->get_dll_name (),
                           cd.get_import_descriptor ()->get_name ());
      }
      rops->irmap[insn].push_back (CallStmt (targetexp, call, &cd));
    }

    // } // Each instruction

    BaseSValuePtr cond = rstate->RegisterStateGeneric::readRegister(rstate->Reg_IP,
                                                                    SymValue::instance_undefined (rstate->Reg_IP.nBits ()),
                                                                    boost::static_pointer_cast<BaseRiscOperators> (rops).get());

    SymValuePtr scond = SymValue::promote(cond);
    edgecondmap [insn] = scond->get_expression();

    // Remove unused temporary variables
    rops->irmap [insn] = remove_unused_statements(rops->irmap [insn], {edgecondmap [insn]});

    // std::cout << "rip at end of block " << block->get_id() << " is "
    //        << edgecondmap[block] << std::endl;
  } // Each block

  // We are done creating the IR.  Now create the CFG.

  IRCFG newcfg;

  auto enamemap = boost::get(boost::edge_name_t(), newcfg);
  auto newnamemap = boost::get (boost::vertex_name_t(), newcfg);
  auto newirmap = boost::get (boost::vertex_ir_t(), newcfg);
  std::map <size_t, boost::graph_traits<IRCFG>::vertex_descriptor> vertexmap;

  // Copy vertices
  for (auto vi = cfg.vertices ().begin (); vi != cfg.vertices ().end (); ++vi) {
    auto nv = boost::add_vertex (newcfg); // Create the new vertex for v
    vertexmap [vi->id()] = nv;

    const SgAsmInstruction* insn = vi->value ().get_insn ();
    newnamemap [nv] = insn;

    StmtsPtr stmts(new Stmts());
    std::copy(rops->irmap[insn].begin(),
              rops->irmap[insn].end(),
              std::back_inserter(*stmts));
    newirmap[nv] = stmts;
  }

  // Copy edges
  for (auto e : cfg.edges ()) {
    auto oldsrc = e.source ();
    auto newsrc = vertexmap [oldsrc->id()];
    auto olddst = e.target ();
    auto newdst = vertexmap [olddst->id()];

    auto t = boost::add_edge (newsrc, newdst, newcfg);
    auto ne = t.first;
    assert (t.second);

    EdgeCond cond;

    switch (oldsrc->nOutEdges ()) {
     case 0:
      // If we're copying an edge from oldsrc, how can the
      // outdegree be 0?
      assert(false); abort();
     case 1:
      cond = EdgeCond (); break;
     case 2:
      // JE style?
      {
        auto ipexp = edgecondmap[oldsrc->value ().get_insn ()];
        auto insn_addr = newnamemap [newdst].get_insn_addr ();
        boost::optional<IRExprPtr> econd;
        if (insn_addr && (econd = get_edge_cond (ipexp, *insn_addr))) {
          cond = EdgeCond (econd);
        } else {
          GWARN << "Unable to determine condition for vertex with out degree = 2.  This could be a bug, or an indirect jump with two known destinations." << LEND;
        }
      }
      break;
     default:
      {
        auto ipexp = edgecondmap[oldsrc->value ().get_insn ()];
        auto insn_addr = newnamemap [newdst].get_insn_addr ();

        if (insn_addr) {
          auto sym_insn_addr = SymbolicExpr::makeIntegerConstant (ipexp->nBits (),
                                                                  *insn_addr);
          cond = EdgeCond (SymbolicExpr::makeEq (ipexp, sym_insn_addr));
        } else {
          GERROR << "Unable to determine condition for vertex with out degree > 2.  This is a bug; please report it." << LEND;
        }
      }
      break;
    }

    // Do the assignment
    enamemap[ne] = cond;
  }

  // Search for the vertex whose block says it is the entry point
  boost::graph_traits<IRCFG>::vertex_iterator vi, viend;
  std::tie(vi, viend) = boost::vertices (newcfg);

  auto entry = std::find_if (vi,
                             viend,
                             [&] (IRCFGVertex v) {
                               auto insn_addr = boost::get (boost::vertex_name_t (),
                                                            newcfg,
                                                            v).get_insn_addr ();
                               if (insn_addr)
                                 return fd->get_entry_block ()->get_address () == *insn_addr;
                               else
                                 return false;
                             });
  assert (entry != viend);

  return IR({newcfg, &fd->ds, *entry, rstate, mstate->getMemoryVar(), rops});
}

}
}

namespace pharos {
namespace ir {

IRCFGVertex IR::find_addr (rose_addr_t addr) const {
  SgAsmInstruction* insn = ds->get_partitioner().instructionExists(addr).insn();
  if (!insn)
    return boost::graph_traits<IRCFG>::null_vertex ();

  auto bb_map = boost::get (boost::vertex_name_t (), cfg);

  boost::graph_traits<IRCFG>::vertex_iterator vi, viend;
  std::tie (vi, viend) = boost::vertices (cfg);

  auto r = std::find_if (vi, viend,
                         [&] (IRCFGVertex v) {
                           auto vaddr = bb_map[v].get_insn_addr ();
                           return vaddr && *vaddr == insn->get_address ();
                         });
  if (r == viend) return boost::graph_traits<IRCFG>::null_vertex ();
  else return *r;

}

Register IR::get_reg(RegisterDescriptor rd) const {
  auto regs = rstate->get_stored_registers ();
  auto reg_it = std::find_if(regs.begin(),
                             regs.end(),
                             [&] (RegPair pair) {
                               return pair.desc == rd;
                             });
  if (reg_it == regs.end()) {
    GFATAL << "Unable to find register " << rd << LEND;
    exit(EXIT_FAILURE);
  }
  Register exp = Rose::BinaryAnalysis::InstructionSemantics::SymbolicSemantics::SValue::promote(reg_it->value)->get_expression()->isLeafNode();
  assert (exp);

  return exp;
}

IR filter_backedges(const IR& ir) {

  IRCFG g = ir.get_cfg();

  std::vector<IRCFGEdge> back_edges;
  depth_first_search (g,
                      boost::visitor(boost::make_dfs_visitor (boost::write_property (boost::typed_identity_property_map<IRCFGEdge> (),
                                                                                     std::back_inserter (back_edges),
                                                                                     boost::on_back_edge ()))).
                      root_vertex (ir.get_entry ()));

  for (const IRCFGEdge &e : back_edges) {
    boost::remove_edge (e, g);
  }

  return IR(ir, g);
}

IR split_call_helper (const IR& ir, IRCFGVertex v) {
  IRCFG g = ir.get_cfg ();
  auto ir_map = boost::get (boost::vertex_ir_t (), g);
  auto edgecond_map = boost::get (boost::edge_name_t (), g);

  StmtsPtr irptr = ir_map [v];
  assert (irptr);
  Stmts & origir = *irptr;

  auto call_needing_split = std::find_if (++ (origir.cbegin ()), origir.cend (),
                                          [&] (const Stmt &stmt) {
                                            return (boost::get<CallStmt> (&stmt) != NULL);
                                          });

  if (call_needing_split == origir.cend ()) {
    // No calls needing split
    return ir;
  } else {
    // Do the split

    // Create the new vertex
    IRCFGVertex nv = boost::add_vertex (g);

    // The new vertex gets all statements including and after the CallStmt
    ir_map [nv] = boost::make_shared<Stmts> ();
    std::copy (call_needing_split, origir.cend (), std::back_inserter (*ir_map [nv]));

    // The old vertex has those statements removed
    origir.erase (call_needing_split, origir.cend ());

    // Edges coming into v stay there.  But edges leaving from v
    // should now leave from nv instead.
    std::vector<IRCFGEdge> out_edges;
    boost::copy (boost::out_edges (v, g), std::back_inserter (out_edges));

    for (auto e : out_edges) {
      IRCFGVertex dv = boost::target (e, g);
      IRCFGVertex sv = nv;
      IRCFGEdge ne;
      bool succ;
      // Create the new edge
      std::tie (ne, succ) = boost::add_edge (sv, dv, g);
      assert (succ);
      // Copy the condition from the old edge
      edgecond_map[ne] = edgecond_map[e];
      // Delete the old edge
      boost::remove_edge (e, g);
    }

    // Add an unconditional edge from v to nv
    IRCFGEdge ne;
    bool succ;
    std::tie (ne, succ) = boost::add_edge (v, nv, g);
    assert (succ);

    IR new_ir = IR (ir, g);
    return split_call_helper (new_ir, nv);
  }
}

IR split_calls (const IR& ir_) {
  IRCFG g = ir_.get_cfg ();
  IR ir = ir_;

  return boost::accumulate (boost::vertices (g),
                            ir,
                            [] (const IR &accum_ir, const IRCFGVertex &v) {
                              return split_call_helper (accum_ir, v);
                            });

  return ir;
}

IR split_edges(const IR& ir) {
  IRCFG g = ir.get_cfg ();
  auto edgecond_map = boost::get (boost::edge_name_t (), g);
  auto ir_map = boost::get (boost::vertex_ir_t (), g);

  for (auto v : boost::make_iterator_range (boost::vertices (g))) {
    auto in_edges = boost::in_edges (v, g);
    std::vector <IRCFGEdge> edges_with_conditions;

    std::copy_if (in_edges.first,
                  in_edges.second,
                  std::back_inserter (edges_with_conditions),
                  [&] (IRCFGEdge e) {
                    return edgecond_map[e];
                  });

    //std::cout << "There are " << edges_with_conditions.size() << " edges with conditions" << std::endl;

    auto num_edges_with_conditions = edges_with_conditions.size ();
    auto num_edges = boost::in_degree (v, g);

    if ((num_edges_with_conditions == 1 && num_edges == 1) ||
        (num_edges_with_conditions == 0)) {
      // v is ok if there is one conditional edge and no others, or
      // solely unconditional edges.
    } else {
      // For each edge with a condition, we need to create a new
      // vertex and redirect the edge to that vertex.  Then we add
      // a unconditional edge from that new vertex to v.
      for (auto e : edges_with_conditions) {
        // Here is our new vertex.
        IRCFGVertex nv = boost::add_vertex (g);
        ir_map[nv] = boost::make_shared<Stmts> ();
        // This is the dest of e
        IRCFGVertex dv = v;
        // This is the src of e
        IRCFGVertex sv = boost::source (e, g);
        // Create an edge from sv to nv
        IRCFGEdge ne;
        bool succ;
        std::tie (ne, succ) = boost::add_edge (sv, nv, g);
        assert (succ);
        // Set the condition on ne
        edgecond_map[ne] = edgecond_map[e];
        // Delete the original edge
        boost::remove_edge (e, g);
        // Create an unconditional edge from nv to dv
        std::tie (ne, succ) = boost::add_edge (nv, dv, g);
        assert (succ);
      }
    }

  }

  return IR(ir, g);
}

IR prune_unreachable (const IR& ir) {

  auto cfg = ir.get_cfg ();
  std::vector<int> d;
  std::map<IRCFGVertex, int> m;

  boost::dijkstra_shortest_paths (cfg,
                                  ir.get_entry (),
                                  boost::distance_map (boost::make_assoc_property_map (m)).
                                  weight_map (boost::make_static_property_map<IRCFGEdge,int> (1)));

  std::vector <boost::graph_traits<IRCFG>::vertex_descriptor> remove_these;

  BGL_FORALL_VERTICES (v, cfg, IRCFG) {
    if (m[v] == std::numeric_limits<int>::max () && v != ir.get_error ()) {
      // unreachable
      remove_these.push_back (v);
    }
  }

  // This is an annoying hack. Remove vertices in descending order
  // so we can use VL=vecS.
  std::sort (remove_these.begin (), remove_these.end ());

  for (auto v : boost::make_iterator_range (remove_these.rbegin (),
                                            remove_these.rend ())) {
    // std::cout << "Clearing unreachable vertex " << v << std::endl;
    boost::clear_vertex (v, cfg);
    boost::remove_vertex (v, cfg);
  }

  return IR(ir, cfg);
}

IR change_entry (const IR& ir_, rose_addr_t new_entry) {
  IR ir = ir_;
  IRCFG g = ir.get_cfg ();
  auto edgecond_map = boost::get (boost::edge_name_t (), g);
  auto ir_map = boost::get (boost::vertex_ir_t (), g);
  auto name_map = boost::get (boost::vertex_name_t (), g);

  // First we find the new entry BB
  IRCFGVertex before_entry_v = ir.find_addr (new_entry);
  assert (before_entry_v != boost::graph_traits<IRCFG>::null_vertex ());
  auto before_stmts = ir_map[before_entry_v];

  // Now we split the entry BB into "before" and "after" BBs.  The
  // entry for the IR will go to the "after" BB.  But we still
  // need the "before" BB because in the presence of loops, we
  // could circle around back to the "before" BB.  (If we didn't
  // have loops, we wouldn't need to do this because there is no
  // way a terminating execution could execute the "before"
  // portion.)

  // Since the existing new_entry_v is already properly
  // incorporated into the CFG as the "before" BB, we'll create a
  // new BB for the "after" BB.  This will moving the edges from
  // the original BB to the "after" BB, and adding an
  // unconditional end from the "before" BB to the "after" BB.
  // The entry for the function will then become the "after" BB.

  // Find the first statement corresponding to the "after" statements
  auto it = boost::find_if (*before_stmts,
                            [new_entry] (Stmt s) {
                              auto addr = addrFromStmt (s);
                              return addr && *addr == new_entry;
                            });
  assert (it != before_stmts->end ());

  IRCFGVertex after_entry_v;

  if (it == before_stmts->begin ()) {
    // Hey, it's the first statement in the BB.  Great! We don't have to split anything.
    after_entry_v = before_entry_v;
  } else {

    after_entry_v = boost::add_vertex (g);
    name_map[after_entry_v] = ir.get_ds ()->get_insn (new_entry);

    // Make a copy of the after statements
    StmtsPtr after_stmts (new Stmts (it,
                                     before_stmts->end ()));
    ir_map[after_entry_v] = after_stmts;

    // And delete the after statements from before
    before_stmts->erase (it, before_stmts->end ());

    // Copy all of the outgoing edges from before_v to after_v
    auto out_edges = boost::out_edges (before_entry_v, g);
    boost::for_each (out_edges,
                     [&] (const IRCFGEdge &edge) {
                       auto target = boost::target (edge, g);
                       auto cond = edgecond_map [edge];
                       bool succ;
                       IRCFGEdge new_edge;
                       std::tie (new_edge, succ) = boost::add_edge (after_entry_v, target, g);
                       assert (succ);
                       edgecond_map [new_edge] = cond;
                     });

    // Remove the old edges. We need to copy them to a set first
    // because the edge iterators become invalidated as soon as we
    // delete an edge.
    std::vector<IRCFGEdge> edges_to_remove;
    boost::copy (out_edges,
                 std::back_inserter (edges_to_remove));
    boost::for_each (edges_to_remove,
                     [&] (const IRCFGEdge &edge) {
                       boost::remove_edge (edge, g);
                     });

    // Add an unconditional edge from before to after
    bool succ;
    IRCFGEdge new_edge;
    std::tie (new_edge, succ) = boost::add_edge (before_entry_v, after_entry_v, g);
    assert (succ);
    edgecond_map[new_edge] = EdgeCond();
  }

  // Set after_entry_v as the new entry node of the IR
  ir = IR(ir, g, after_entry_v);

  // Finally, prune any unreachable nodes
  ir = prune_unreachable (ir);

  return ir;
}


// This is a helper function because it's also used in get_cg
CGVertex findfd_cgg(const FunctionDescriptor* fd, const CGG& cgg) {
  auto fd_map = boost::get (boost::vertex_name_t (), cgg);
  boost::graph_traits<CGG>::vertex_iterator vi, viend;
  std::tie(vi, viend) = boost::vertices (cgg);
  auto o = std::find_if (vi, viend, [&] (CGVertex v) { return fd_map[v]->get_address () == fd->get_address (); });
  return o == viend ? boost::graph_traits<CGG>::null_vertex () : *o;
}

CGVertex CG::findfd(const FunctionDescriptor* fd) const {
  return findfd_cgg (fd, graph);
}

CG CG::get_cg(const DescriptorSet& ds) {
  CGG cgg;
  auto fd_map = boost::get (boost::vertex_name_t (), cgg);
  auto edge_map = boost::get (boost::edge_name_t (), cgg);
  auto index_map = boost::get (boost::vertex_index_t (), cgg);

  // Add function vertices to CGG
  size_t i = 0;
  const FunctionDescriptorMap& fdmap = ds.get_func_map();
  for (const FunctionDescriptor& fd : boost::adaptors::values(fdmap)) {
    CGVertex v = boost::add_vertex (&fd, cgg);
    fd_map[v] = &fd;
    index_map[v] = i++;
  }

  for (auto& pair : ds.get_call_map()) {
    const CallDescriptor & cd = pair.second;

    const FunctionDescriptor *fromfd = ds.get_func_containing_address(pair.first);

    // Filter out things without functions (?) and functions at address 0 (thunks?)
    if (fromfd && fromfd->get_address() != 0) {
      // std::cout << "call from addr " << from << " in function "
      //        << fromfd->get_name() << " to" << std::endl;
      CGVertex fromv = findfd_cgg (fromfd, cgg);
      if (fromv != boost::graph_traits<CGG>::null_vertex()) {
        // OK, we found the fromt function.
        // std::cout << "found from vertex!" << std::endl;

        for (auto& target : cd.get_targets()) {
          // std::cout << fromfd->get_address() << " target " << target << std::endl;

          const FunctionDescriptor *tofd = ds.get_func_containing_address(target);
          if (tofd) {
            CGVertex tov = findfd_cgg (tofd, cgg);
            if (tov != boost::graph_traits<CGG>::null_vertex()) {
              // std::cout << "creating an edge!" << std::endl;

              CGEdge e;
              bool succ;
              std::tie (e, succ) = boost::add_edge (fromv, tov, cgg);
              // std::cout << fromfd->get_address() << " uh " << tofd->get_address() << std::endl;
              // std::cout << fromv << " uh " << tov << std::endl;
              // std::cout << *fromfd << " " << *tofd << std::endl;
              assert (succ);

              edge_map[e] = &cd;
            }
          }
        }
      }
    }
  }

  return CG(cgg, &ds);
}

// This class is used to extract an instruction statement's address
struct InsnVisitor : public boost::static_visitor<boost::optional<rose_addr_t>> {
  boost::optional<rose_addr_t> operator()(const InsnStmt &is) const {
    return is.first;
  }
  template <typename T>
  boost::optional<rose_addr_t> operator()(T const &) const {
    return boost::none;
  }
};

boost::optional<rose_addr_t> addrFromStmt(const Stmt &stmt) {
  return boost::apply_visitor (InsnVisitor (), stmt);
}

struct CallVisitor : public boost::static_visitor<boost::optional<rose_addr_t>> {
  boost::optional<rose_addr_t> operator()(const CallStmt &cs) const {
    if (boost::get <ImportCall> (&(std::get<1> (cs)))) {
      // Imports don't count here because we don't want to remove them
      return boost::none;
    }
    SymbolicLeafPtr leaf = std::get<0> (cs)->isLeafNode ();
    if (leaf && leaf->isIntegerConstant ())
      return *leaf->toUnsigned ();
    else
      return boost::none;
  }
  template <typename T>
  boost::optional<rose_addr_t> operator()(T const &) const {
    return boost::none;
  }
};

boost::optional<rose_addr_t> targetOfCallStmt (const Stmt &stmt) {
  return boost::apply_visitor (CallVisitor (), stmt);
}

// cut1_cg
// src -> dst
// Include any functions that are reachable from src
void cut1_cg(CG &cg, CGVertex srcv, UNUSED CGVertex dstv) {
  CGG &cgg = cg.get_graph ();
  std::set<CGVertex> reachable_vertices;
  std::set<CGVertex> remove_vertices;

  boost::breadth_first_search(cgg,
                              srcv,
                              boost::visitor(boost::make_bfs_visitor(boost::write_property(boost::typed_identity_property_map<CGVertex> (),
                                                                                           std::inserter(reachable_vertices, reachable_vertices.begin ()),
                                                                                           boost::on_discover_vertex()))));


  BGL_FORALL_VERTICES(v, cgg, CGG) {
    if (reachable_vertices.count (v) == 0) {
      // v is not reachable so remove it
      //std::cout << "Removing " << v << std::endl;
      // We use a set of FDs here because removing a vertex actually invalidates any existing
      // vertex descriptor.... whoops.
      remove_vertices.insert (v);
    } else {
      //std::cout << "Keeping " << fd_map [v] << std::endl;
    }
  }

  for (auto v : remove_vertices) {
    // std::cout << "Clearing " << v << std::endl;
    boost::clear_vertex (v, cgg);
    boost::remove_vertex (v, cgg);
  }


  //std::cout << "Before returning there are " << boost::num_vertices (cg) << " vertices in cg." << std::endl;

  cg.rebuild_indices ();
}

using SeenFuncs = ConstFunctionDescriptorSet;

IR inline_cg (const CG& cg, const FunctionDescriptor* entryfd, SeenFuncs seen = {});
IR inline_cg (const CG& cg, const CGVertex entryv, const IR& ir, SeenFuncs seen = {});


// This function inlines all calls from the specific function
// according to the provided call graph.
IR inline_cg (const CG& cg, const CGVertex entryv, const IR& ir, SeenFuncs  seen) {
  const CGG& cgg = cg.get_graph ();
  CGVertex targetv;

  // Start from the entry node
  IRCFG cfg = ir.get_cfg ();

  auto ir_map = boost::get (boost::vertex_ir_t (), cfg);
  auto edgecond_map = boost::get (boost::edge_name_t (), cfg);
  auto cd_map = boost::get (boost::edge_name_t (), cgg);

  // Iterate through each BB of IR and keep track of the most
  // recent call instruction.  If we reach a CallStmt, check to
  // see if there is a corresponding edge in the callgraph.  If
  // there is, recurse on that function and then splice it in.

  BGL_FORALL_VERTICES (v, cfg, IRCFG) {
    auto stmts = *ir_map [v];

    boost::optional<rose_addr_t> last_addr;
    for (Stmt stmt : stmts) {
      auto new_addr = addrFromStmt(stmt);
      if (new_addr) {
        last_addr = new_addr;
        //std::cout << "I am an instruction statement: " << stmt << " " << new_addr << std::endl;
      }

      auto call_target = targetOfCallStmt (stmt);
      if (call_target) {
        assert (last_addr);
        //std::cout << "I am a call statement: " << stmt << " " << call_target << std::endl;
        // Are there any outgoing edges from entry to call_target's function from last_addr?
        const FunctionDescriptor *targetfd = ir.get_ds ()->get_func_containing_address (*call_target);

        if (!targetfd) {
          GWARN << "Found an unresolved direct call" << LEND;
          continue;
        }

        targetv = cg.findfd (targetfd);

        if (targetv == boost::graph_traits<CGG>::null_vertex ()) {
          GWARN << "Found an unresolved direct call" << LEND;
          continue;
        }

        // Remove the Call Statement
        // Hopefully this is enough to not screw up iterating over stmts
        Stmts new_stmts = stmts;
        new_stmts.pop_back ();
        ir_map [v] = boost::make_shared<Stmts> (new_stmts);

        boost::graph_traits<CGG>::out_edge_iterator cgobegin, cgoend;
        std::tie (cgobegin, cgoend) = boost::edge_range (entryv,
                                                         targetv,
                                                         cgg);
        auto the_edge = std::find_if (cgobegin, cgoend,
                                      [&](CGEdge ed) {
                                        auto cd = cd_map[ed];

                                        // GCC reports that *last_addr may be used uninitialized, but in
                                        // fact this is not true because of fairly complex logic involving
                                        // how last_addr is set at the beginning of this loop.
#if (defined(__GNUC__) && !defined(__clang__))
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
                                        if (cd->get_address () == *last_addr)
                                          return true;
                                        else return false;
#if (defined(__GNUC__) && !defined(__clang__))
#pragma GCC diagnostic pop
#endif
                                      });

        // If we didn't find the edge, or if inlining the edge would create a cycle in the
        // callgraph, don't do the inlining.
        if (the_edge == cgoend || seen.count (targetfd)) {
          std::string t;
          if (the_edge == cgoend) {
            t = "Didn't find the corresponding edge in the callgraph.";
          } else if (seen.count (targetfd)) {
            t = "Ignoring a backedge in the callgraph since it would create a cycle.";
          } else {
            assert (false);
            abort ();
          }

          GWARN << t << " Doing something like writing assert false." << LEND;

          boost::graph_traits<IRCFG>::out_edge_iterator cfgobegin, cfgoend;
          std::tie (cfgobegin, cfgoend) = boost::out_edges (v, cfg);

          // Set each out-going edge in the CFG to false
          std::for_each (cfgobegin, cfgoend,
                         [&] (CFGEdge e) {
                           edgecond_map [e] = EdgeCond (
                             SymbolicExpr::makeBooleanConstant (false));
                         });
        } else {
          //std::cout << "Found the edge! Inlining time!" << std::endl;

          // For a call, there should be a single edge from v to
          // the successor bb. We want to add a copy of the target
          // function's CFG to the original cfg, and change the
          // edge so that the function copy is in between.

          if (boost::out_degree (v, cfg) != 1) {
            GFATAL << "Inlining assumes that calls have exactly one outgoing edge in the CFG but " << *targetfd << " has " << boost::out_degree (v, cfg) << "." << LEND;
            exit (EXIT_FAILURE);
          }
          auto old_call_edge = *boost::out_edges (v, cfg).first;


          // Inline the callee
          const IR inlinee = inline_cg (cg, targetfd, seen);
          const IRCFG inlinee_cfg = inlinee.get_cfg ();

          boost::graph_traits<IRCFG>::vertex_iterator vi, viend;
          std::tie (vi, viend) = boost::vertices (inlinee_cfg);

          auto ventry = inlinee.get_entry ();

          // Find the exits of inlinee_cfg
          std::vector<IRCFGVertex> vexits;
          boost::copy (inlinee.get_exits (),
                       std::back_inserter (vexits));


          if (vexits.size () == 0) {
            GFATAL << "Did not find any exits for " << *targetfd << ". This may not be a bug but for now this is unsupported." << LEND;
            exit (EXIT_FAILURE);
          }

          // Actually copy inlinee_cfg to cfg
          // XXX: Handle error node
          using IRCFGVertexMap = std::map <IRCFGVertex, IRCFGVertex>;
          IRCFGVertexMap vmap;
          boost::associative_property_map<IRCFGVertexMap> IRCFGVertexMapper (vmap);

          boost::copy_graph (inlinee_cfg, cfg,
                             boost::orig_to_copy (IRCFGVertexMapper));

          // This is the entry point of the inlined function in the inlined cfg
          auto inlinedventry = vmap [ventry];

          // Remove the old call edge and construct a new one to inlinedventry
          IRCFGEdge new_call_edge;
          bool succ;
          std::tie (new_call_edge, succ) = boost::add_edge (v, inlinedventry, cfg);
          assert (succ);
          edgecond_map[new_call_edge] = edgecond_map[old_call_edge];
          boost::remove_edge (old_call_edge, cfg);

          // Finally add unconditional return edge(s)
          std::for_each (vexits.begin (), vexits.end (),
                         [&] (IRCFGVertex oldexit) {
                           auto newexit = vmap [oldexit];
                           std::tie (std::ignore, succ) = boost::add_edge (newexit,
                                                                           boost::target (old_call_edge, cfg),
                                                                           cfg);
                           assert (succ);
                         });

        }
      }
    }
  }

  return IR (ir, cfg);
}

// This is just a convenience wrapper for the main definition of inline_cg.
IR inline_cg (const CG& cg, const FunctionDescriptor* entryfd, SeenFuncs seen) {
  seen.insert (entryfd);
  CGVertex entryv = cg.findfd (entryfd);
  IR ir = IR::get_ir (entryfd);
  return inline_cg (cg, entryv, ir, seen);
}

IR get_inlined_cfg (const CG& cg_,
                    rose_addr_t from,
                    rose_addr_t to,
                    std::function<void(CG& cg, CGVertex from, CGVertex to)> cutf) {
  CG cg(cg_);
  const FunctionDescriptor *fromfd = cg.get_ds ()->get_func_containing_address (from);
  const FunctionDescriptor *tofd = cg.get_ds ()->get_func_containing_address (to);
  assert (fromfd && tofd);

  CGVertex fromcgv = cg.findfd (fromfd);
  CGVertex tocgv = cg.findfd (tofd);
  assert (fromcgv != boost::graph_traits<CGG>::null_vertex ());
  assert (tocgv != boost::graph_traits<CGG>::null_vertex ());

  IR fromir = IR::get_ir (fromfd);
  fromir = change_entry (fromir, from);

  cutf (cg, fromcgv, tocgv);

  return inline_cg (cg, fromcgv, fromir);
}

void CG::rebuild_indices (void) {
  size_t i = 0;
  auto index_map = boost::get (boost::vertex_index_t (), graph);

  BGL_FORALL_VERTICES(v, graph, CGG) {
    index_map[v] = i++;
  }
}


}
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
