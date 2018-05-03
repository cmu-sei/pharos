#include "ir.hpp"
#include "util.hpp"
#include "masm.hpp"
#include "descriptors.hpp"

#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/copy.hpp>

using namespace pharos;
using namespace pharos::ir;

namespace {
  namespace IRSemantics2 = Rose::BinaryAnalysis::InstructionSemantics2;

  typedef IRSemantics2::SymbolicSemantics::SValue SymValue;
  typedef IRSemantics2::SymbolicSemantics::SValuePtr SymValuePtr;

  typedef SymbolicExpr::InteriorPtr InteriorPtr;
  typedef SymbolicExpr::Operator Operator;
  typedef SymbolicExpr::Nodes Nodes;

  // A list of variable to memory expression mappings that are still valid because memory hasn't
  // been overwritten yet.
  struct Mem {};
  typedef boost::variant<RegisterDescriptor, Mem> GenDescriptor;
  typedef std::pair<IRExprPtr, GenDescriptor> Subst;
  typedef std::map<IRExprPtr, Subst> Substs;

  typedef std::map<SgAsmInstruction*, Stmts> IRMap;
  typedef std::map<SgAsmBlock*, IRExprPtr> EdgeCondMap;

  typedef IRSemantics2::BaseSemantics::RegisterStateGeneric RegisterStateGeneric;
  typedef IRSemantics2::BaseSemantics::RegisterStateGenericPtr RegisterStateGenericPtr;
  
  typedef IRSemantics2::SymbolicSemantics::SValue SymValue;
  typedef IRSemantics2::SymbolicSemantics::SValuePtr SymValuePtr;
  typedef IRSemantics2::SymbolicSemantics::MemoryMapState SymMemoryMapState;
  typedef IRSemantics2::SymbolicSemantics::MemoryMapStatePtr SymMemoryMapStatePtr;
  typedef IRSemantics2::SymbolicSemantics::State SymState;
  typedef IRSemantics2::SymbolicSemantics::StatePtr SymStatePtr;
  typedef IRSemantics2::SymbolicSemantics::RiscOperators SymRiscOperators;
  typedef IRSemantics2::SymbolicSemantics::RiscOperatorsPtr SymRiscOperatorsPtr;
  typedef IRSemantics2::DispatcherX86 RoseDispatcherX86;
  typedef IRSemantics2::DispatcherX86Ptr RoseDispatcherX86Ptr;

  typedef boost::shared_ptr<class IRRegisterState> IRRegisterStatePtr;
  typedef boost::shared_ptr<class IRRiscOperators> IRRiscOperatorsPtr;

  typedef Rose::BinaryAnalysis::InstructionSemantics2::BaseSemantics::Exception SemanticsException;

  // Stub implementation
  bool isRegister(Register r) {
    return r->comment() != "";
  }

  // Remove temporary variables that aren't used anymore
  Stmts removeUnusedStatements(Stmts &stmts_) {
    Stmts livestmts = stmts_;
    Stmts stmts;
  
    do {
      stmts = livestmts;
      livestmts.clear();
      std::set<Register> usedvars;

      std::for_each(stmts.begin(), stmts.end(),
		    [&usedvars](Stmt &stmt) {
		      std::set<IRExprPtr> exps = expsFromStmt(stmt);
		      std::for_each(exps.begin(),
				    exps.end(),
				    [&usedvars](const IRExprPtr &exp) {
				      //std::cout << "stmt " << stmt << " exp " << **exp << std::endl;
				      std::set<SymbolicLeafPtr> newusedvars = exp->getVariables();
				      // Convert variables to their names
				      std::copy (newusedvars.begin(), newusedvars.end(),
						 std::inserter(usedvars, usedvars.end()));

				    });
		    });
    
      //std::cout << "recorded " << usedvars.size() << " variables" << std::endl;
    
      struct StmtVisitor : public boost::static_visitor<bool> {
      
	std::set<Register> usedvars;
      
	StmtVisitor(std::set<Register> &usedvars_) : usedvars(usedvars_) {}
      
	// Only keep RegWriteStmt if the variable is used XXX or a reg
	bool operator()(RegWriteStmt &rs) const {
	  return isRegister(rs.first) || usedvars.count(rs.first);
	}
	bool operator()(UNUSED MemWriteStmt &ms) const {
	  return true;
	}
	bool operator()(UNUSED SpecialStmt &ss) const {
	  return true;
	}
	bool operator()(UNUSED CallStmt &cs) const {
	  return true;
	}
	bool operator()(UNUSED InsnStmt &is) const {
	  return true;
	}
      };
    
      StmtVisitor sv(usedvars);
      std::copy_if(stmts.begin(),
		   stmts.end(),
		   std::back_inserter(livestmts),
		   boost::apply_visitor(sv));
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
    void interrupt(int majr, int minr) ROSE_OVERRIDE {
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
      : SymRiscOperators(state) {};
  };

  // Define how we want to represent a register state.
  class IRRegisterState: public RegisterStateGeneric
  {
    // Create the register state and initialize the register values.
    explicit IRRegisterState(const BaseSValuePtr& valueProtoval, const ::RegisterDictionary *rd):
      RegisterStateGeneric(valueProtoval, rd) {

      // Create an X86 instruction dispatcher and initialize the "usual" registers with values.
      // Normally these would be the values in the state, here they're just "names" for the
      // registers.  We're never going to overwrite the registers so this is a completely static
      // dictionary of registers.
      Semantics2::DispatcherX86Ptr dispatcher = RoseDispatcherX86::instance(global_descriptor_set->get_arch_bits());
      dispatcher->set_register_dictionary(rd);
      initialize_nonoverlapping(dispatcher->get_usual_registers(), false);
      Reg_IP = rd->findLargestRegister(x86_regclass_ip,  0, global_descriptor_set->get_arch_bits());
    }

    IRRegisterState(const IRRegisterState &rs)
      : RegisterStateGeneric(rs) {
      Reg_IP = rs.Reg_IP;
    }

  public:

    RegisterDescriptor Reg_IP;

    // Construct an instance of an IR register state.
    static IRRegisterStatePtr instance(const SymValuePtr &proto,
				       const ::RegisterDictionary *rd) {
      return IRRegisterStatePtr(new IRRegisterState(proto, rd));
    }

    // Called every time a register is read.
    BaseSValuePtr readRegister(RegisterDescriptor reg, const BaseSValuePtr &dflt,
			       BaseRiscOperators *ops) ROSE_OVERRIDE {
      // Clone ourselves so that we can read from a
      // register.  This is needed so that when we read from AL, we
      // don't remove the EAX register.  Whoops.

      IRRegisterState aclone(*this);

      BaseSValuePtr value = aclone.RegisterStateGeneric::readRegister(reg, dflt, ops);
      SymValuePtr svalue = SymValue::promote(value);
      SymValuePtr sdflt = SymValue::promote(dflt);

      //std::string regname = unparseX86Register(reg, NULL);
      //std::cout << *svalue << " = RegRead(" << regname << ")" << std::endl;

      SymbolicLeafPtr leaf = sdflt->get_expression()->isLeafNode();
      assert (leaf);

      Stmt stmt = RegWriteStmt(leaf, svalue->get_expression());

      IRRiscOperators *irops = IRRiscOperators::promote (ops);
      irops->irmap[irops->currentInstruction()].push_back(stmt);
      irops->substs[leaf] = std::make_pair (svalue->get_expression(), reg);;

      return dflt;
    }

    // Called every time a register is written.
    void writeRegister(RegisterDescriptor reg, const BaseSValuePtr &value,
		       BaseRiscOperators *ops) ROSE_OVERRIDE {
      SymValuePtr svalue = SymValue::promote(value);
      std::string regname = unparseX86Register(reg, NULL);

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
	//std::cout << "hmm " << unparseX86Register(reg, NULL) << svalue->get_width() << *regvar << std::endl;

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
	  IRExprPtr high = SymbolicExpr::makeExtract(SymbolicExpr::makeInteger(int_width, reg.get_nbits() + reg.get_offset()),
						     SymbolicExpr::makeInteger(int_width, fullreg.get_nbits()),
						     regleaf);
	  exp = SymbolicExpr::makeConcat(high, exp);
	}
	// Add low portion if necessary
	if (reg.get_offset() > fullreg.get_offset()) {
	  // std::cout << "i'm low " << fullreg << " " << reg.get_offset() << " " << reg.get_nbits() << std::endl;
	  IRExprPtr low = SymbolicExpr::makeExtract(SymbolicExpr::makeInteger(int_width, 0),
						    SymbolicExpr::makeInteger(int_width, reg.get_offset()),
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
			    [&reg](Substs::value_type &p) {
			      if (p.second.second.which() == 0) {
				RegisterDescriptor &rd = boost::get<RegisterDescriptor> (p.second.second);
				return rd == reg;
			      } else return false; // Mem
			    });
	irops->substs = validsubsts;
      }
    }
  };

  typedef boost::shared_ptr<class IRMemoryState> IRMemoryStatePtr;

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
      mem = SymbolicExpr::makeMemory(addrProto->get_width(),
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
			     BaseRiscOperators *valOps) ROSE_OVERRIDE {

      if (!memset) {
      	// This is the first time that readMemory was called, so let's
      	// create a memory with the proper sizes
      	mem = SymbolicExpr::makeMemory(addr->get_width(),
      				       dflt->get_width())->isLeafNode();
      	assert (mem);
      	mem->comment("M");
      	memset = true;
      }

      size_t nbits = dflt->get_width();
      SymValuePtr saddr = SymValue::promote(addr);

      SymValuePtr smemread = SymValue::instance_undefined(nbits);
      smemread->set_expression(SymbolicExpr::makeRead(mem, saddr->get_expression()));

      SymValuePtr newvar = SymValue::instance_undefined(nbits);
      SymbolicLeafPtr leaf = newvar->get_expression()->isLeafNode();

      Stmt stmt = RegWriteStmt(leaf, smemread->get_expression());

      IRRiscOperators *irops = IRRiscOperators::promote (valOps);
      irops->irmap[irops->currentInstruction()].push_back(stmt);
      irops->substs[leaf] = std::make_pair (smemread->get_expression(), Mem());

      return newvar;
    }

    // Called every time memory is written.
    void writeMemory(const BaseSValuePtr &addr, const BaseSValuePtr &value,
		     UNUSED BaseRiscOperators *addrOps,
		     BaseRiscOperators *valOps) ROSE_OVERRIDE {

      if (!memset) {
	// This is the first time that writeMemory was called, so let's
	// create a memory with the proper sizes
	mem = SymbolicExpr::makeMemory(addr->get_width(),
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

};

namespace pharos {
  namespace ir {
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
    std::ostream& operator<<(std::ostream &out, const CallType &ct) {
      switch (ct) {
      case CallType::direct:
	out << "direct";
	break;
      case CallType::indirect:
	out << "indirect";
	break;
      default:
	assert(false);
      }
      return out;
    }
    std::ostream& operator<<(std::ostream &out, const CallStmt &stmt) {
      out << "CallStmt(" << stmt.first << ", " << *stmt.second << ")";
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

    std::set<IRExprPtr> expsFromStmt(Stmt &stmt) {
      struct StmtVisitor : public boost::static_visitor<std::set<IRExprPtr>> {
	std::set<IRExprPtr> operator()(RegWriteStmt &rs) const { return {rs.second}; }
	std::set<IRExprPtr> operator()(MemWriteStmt &ms) const { return {ms.first, ms.second}; }
	std::set<IRExprPtr> operator()(UNUSED InsnStmt &is) const { return {}; }
	std::set<IRExprPtr> operator()(UNUSED SpecialStmt &ss) const { return {}; }
	std::set<IRExprPtr> operator()(CallStmt &cs) const { return {cs.second}; }
      };
      return boost::apply_visitor( StmtVisitor(), stmt );
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
	if (l->isNumber() && l->toInt() == dest) return c;
	else if (r->isNumber() && r->toInt() == dest) return SymbolicExpr::makeInvert(c);
	else return boost::none;
      } else return boost::none;
    }

    IR get_ir(FunctionDescriptor& fd) {
      CFG& cfg = fd.get_rose_cfg();

      size_t arch_bits = global_descriptor_set->get_arch_bits();

      //std::cout << "---- Creating analysis domain" << std::endl;
      // Build an instance of our IR analysis domain.  We only need to build it once, because we
      // never actually write to it in any way.
      SymValuePtr protoval = SymValue::instance();
      pharos::RegisterDictionary regdict = global_descriptor_set->get_regdict();
      IRRegisterStatePtr rstate = IRRegisterState::instance(protoval, regdict);
      IRMemoryStatePtr mstate = IRMemoryState::instance(protoval, protoval);
      SymStatePtr state = SymState::instance(rstate, mstate);
      IRRiscOperatorsPtr rops = IRRiscOperators::instance(state);
      RoseDispatcherX86Ptr dispatcher = RoseDispatcherX86::instance(rops, arch_bits, NULL);

      EdgeCondMap edgecondmap;

      const CallDescriptorMap &calls = global_descriptor_set->get_call_map ();

      for (const CFGVertex& vertex : cfg_vertices(cfg)) {
	SgAsmBlock* block = get(boost::vertex_name, cfg, vertex);

	const SgAsmStatementPtrList & insns = block->get_statementList();

	for (size_t i=0; i<insns.size(); ++i) {
	  SgAsmX86Instruction *insn = isSgAsmX86Instruction(insns[i]);
	  // To print boundaries between native instructions.
	  //std::cout << "---- Insn: " << debug_instruction(insn) << std::endl;
	  // Process the instruction.
	  rops->irmap[insn].push_back(InsnStmt(insn->get_address(), debug_instruction(insn)));
	  try {
	    dispatcher->processInstruction(insn);
	  } catch (SemanticsException &e) {
	    // XXX: HACK
	    rops->irmap[insn].push_back(SpecialStmt(e.what()));
	  }

	  // Is this a call?
	  if (calls.count (insn->get_address ())) {
	    const CallDescriptor &cd = calls.at (insn->get_address ());
	    CallType ircalltype = CallType::indirect;

	    if (cd.get_target_location () == CallInternal)
	      ircalltype = CallType::direct;

	    // auto targets = cd.get_targets ();

	    // Start with a general expression
	    BaseSValuePtr cond = rstate->RegisterStateGeneric::readRegister(rstate->Reg_IP,
									    SymValue::instance_undefined (arch_bits),							
									    boost::static_pointer_cast<BaseRiscOperators> (rops).get());
	    IRExprPtr targetexp = SymValue::promote (cond)->get_expression ();

	    rops->irmap[insn].push_back(CallStmt(ircalltype,
						 targetexp));

	  } // end call
	  
	  // Remove unused temporary variables
	  rops->irmap[insn] = removeUnusedStatements(rops->irmap[insn]);

	} // Each instruction

	BaseSValuePtr cond = rstate->RegisterStateGeneric::readRegister(rstate->Reg_IP,
									SymValue::instance_undefined (arch_bits),							
									boost::static_pointer_cast<BaseRiscOperators> (rops).get());
	SymValuePtr scond = SymValue::promote(cond);
	edgecondmap[block] = scond->get_expression();
	// std::cout << "rip at end of block " << block->get_id() << " is "
	// 	  << edgecondmap[block] << std::endl;
      } // Each block

      // XXX: Can we convert both of these to lambdas?
      struct vertex_copier {
      private:
	CFG& from;
	IRCFG& to;
	IRMap& irmap;
      public:
	vertex_copier(CFG &from_, IRCFG& to_, IRMap &irmap_) : from(from_), to(to_), irmap(irmap_) {
	  // We could define maps here
	}
	void operator()(boost::graph_traits<CFG>::vertex_descriptor input,
			boost::graph_traits<IRCFG>::vertex_descriptor output) const {
	  auto oldnamemap = boost::get(boost::vertex_name_t(), from);
	  auto newnamemap = boost::get(boost::vertex_name_t(), to);
	  auto newirmap = boost::get(boost::vertex_ir_t(), to);

	  const SgAsmBlock* block = oldnamemap[output];
	  //std::cout << "Copying properties of " << block->get_id() << std::endl;
	  newnamemap[output] = oldnamemap[input]; // Copy SgAsmBlock to new CFG

	  StmtsPtr stmts(new Stmts());
	  const SgAsmStatementPtrList &insns = block->get_statementList();
	  for (size_t i=0; i<insns.size(); ++i) {
	    SgAsmX86Instruction *insn = isSgAsmX86Instruction(insns[i]);
	    std::copy(irmap[insn].begin(),
		      irmap[insn].end(),
		      std::back_inserter(*stmts));
	  }
	  newirmap[output] = stmts;
	}
      };

      struct edge_copier {
      private:
	CFG& from;
	IRCFG& to;
	EdgeCondMap& edgecondmap;
      public:
	edge_copier(CFG &from_, IRCFG &to_, EdgeCondMap &edgecondmap_) : from(from_), to(to_), edgecondmap(edgecondmap_) {}
	void operator()(UNUSED boost::graph_traits<CFG>::edge_descriptor input,
			boost::graph_traits<IRCFG>::edge_descriptor output) const {
	  EdgeCond cond;

	  auto enamemap = boost::get(boost::edge_name_t(), to);
	  auto vnamemap = boost::get(boost::vertex_name_t(), to);

	  auto oldsrcv = boost::source(input, from);
	  auto srcv = boost::source(output, to);
	  auto dstv = boost::target(output, to);

	  switch (boost::out_degree (oldsrcv, from)) {
	  case 0:
	    assert(false); break;
	  case 1:
	    cond = EdgeCond(); break;
	  case 2:
	    // JE style?
	    {
	      auto ipexp = edgecondmap[vnamemap[srcv]];
	      if (auto econd = get_edge_cond(ipexp, vnamemap[dstv]->get_id())) {
		//std::cout << "inferred condition is " << *econd.get() << std::endl;
		cond = EdgeCond(econd);
	      } else {
		GWARN << "Unable to determine condition for vertex with out degree = 2.  This could be a bug, or an indirect jump with two known destinations." << LEND;
	      }
	      // if (auto targets = get_cjmp_targets(ipexp)) {
	      // 	IRExprPtr c;
	      // 	SymbolicLeafPtr l, r;
	      // 	std::tie(c, l, r) = targets.get();
	      // 	std::cout << *c << *l << *r << std::endl;
	      // }
	      // std::cout << "testing " << *ipexp << std::endl;
	    }
	    break;
	  default:
	    GWARN << "Vertex with out degree > 2 found, and currently unable to label edge condition correctly." << LEND;
	  }

	  // Do the assignment
	  enamemap[output] = cond;
	}
      };

      IRCFG newcfg;
      boost::copy_graph (cfg, newcfg,
			 boost::vertex_copy(vertex_copier{cfg, newcfg, rops->irmap}).
			 // Yes, that's a period, not a comma.  And
			 // yes, you can't put boost:: on edge_copy
			 // for some reason. You know, 'cause boost.
			 edge_copy(edge_copier{cfg, newcfg, edgecondmap}));

      return IR({newcfg, rstate, mstate->getMemoryVar()});
    }

  };
};

namespace pharos {
  namespace ir {

    Register IR::get_reg(RegisterDescriptor rd) const {
      auto regs = rstate->get_stored_registers();
      auto reg_it = std::find_if(regs.begin(),
				     regs.end(),
				     [&] (RegPair pair) {
				       return pair.desc == rd;
				     });
      if (reg_it == regs.end()) {
	GFATAL << "Unable to find register " << rd << LEND;
	exit(EXIT_FAILURE);
      }
      Register exp = Rose::BinaryAnalysis::InstructionSemantics2::SymbolicSemantics::SValue::promote(reg_it->value)->get_expression()->isLeafNode();
      assert (exp);

      return exp;
    }

    IR filter_backedges(IR ir) {

      IRCFG g = ir.get_cfg();

      struct BackEdgeVisitor : public boost::default_dfs_visitor {
	std::vector<IRCFGEdge> &v;
	BackEdgeVisitor(std::vector<IRCFGEdge> &v_) : v(v_) {}
	
	void back_edge(IRCFGEdge e, UNUSED const IRCFG &g) {
	  v.push_back(e);
	}

      };

      std::vector<IRCFGEdge> back_edges;
      BackEdgeVisitor bev (back_edges);
      depth_first_search (g,
			  boost::visitor(bev));

      for (const IRCFGEdge &e : back_edges) {
	boost::remove_edge (e, g);
      }

      return IR(ir, g);
    }

    IR split_edges(IR ir) {
      IRCFG g = ir.get_cfg ();
      auto edgecond_map = boost::get (boost::edge_name_t (), g);
      auto ir_map = boost::get (boost::vertex_ir_t (), g);
      auto name_map = boost::get (boost::vertex_name_t (), g);

      for (auto v : boost::make_iterator_range (boost::vertices (g))) {
	auto out_edges = boost::in_edges (v, g);
	std::vector <IRCFGEdge> edges_with_conditions;

	std::copy_if (out_edges.first,
		      out_edges.second,
		      std::back_inserter (edges_with_conditions),
		      [&] (IRCFGEdge e) {
			return edgecond_map[e];
		      });

	//std::cout << "There are " << edges_with_conditions.size() << " edges with conditions" << std::endl;

	if (edges_with_conditions.size () > 1) {
	  // There is more than one edge with a condition on it
	  // pointing to v.  For each of these edges, we need to
	  // create a new vertex and redirect the edge to that vertex.
	  // Then we add a unconditional edge from that new vertex to
	  // v.
	  for (auto e : edges_with_conditions) {
	    // Here is our new vertex.
	    IRCFGVertex nv = boost::add_vertex (g);
	    ir_map[nv] = boost::make_shared<Stmts>(Stmts());
	    name_map[nv] = NULL;
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
  };
};
