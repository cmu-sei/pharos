// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/property_map/property_map.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/visitors.hpp>
#include <boost/graph/named_function_params.hpp>
#include <boost/range/adaptors.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include "rose.hpp"
#include <AstTraversal.h>

#include "misc.hpp"
#include "descriptors.hpp"
#include "pdg.hpp"
#include "apidb.hpp"
#include "partitioner.hpp"
#include "vftable.hpp"
#include "imports.hpp"
#include "masm.hpp"
#include "threads.hpp"

#include <mutex>

namespace bf = boost::filesystem;

namespace pharos {

size_t global_arch_bytes = 4;

void set_global_arch_bytes(size_t arch_bytes)
{
  static bool initialized = false;
  static std_mutex mutex;

  write_guard<decltype(mutex)> lock(mutex);

  if (initialized) {
    if (arch_bytes != global_arch_bytes) {
      GFATAL << "Cannot analyze a binary with a pointer-size of " << arch_bytes
             << " when already analyzing binaries with a pointer size of "
             << global_arch_bytes << ".\n"
             << "This is a limitation with the current code that will may"
             << " go away in a future version." << LEND;
      throw std::runtime_error("Architecture size mismatch");
    }
  } else {
    global_arch_bytes = arch_bytes;
    initialized = true;
  }

  if (arch_bytes != 4 and arch_bytes != 8) {
    GFATAL << "Architecture has unrecognized word size of " << arch_bytes << " bytes." << LEND;
    // We should probably throw or exit, here since it's very unlikely that continuing will end
    // well.  On the other hand, nothing terrible has happened yet, so we can continue.
  }
}

ImportDescriptor *DescriptorSet::add_import(
  rose_addr_t addr, std::string dll, std::string name, size_t ord)
{
  ImportDescriptor * nid = &map_emplace_or_replace(
    import_descriptors, addr, *this, addr, dll, name, ord);

  // Get the expresison for the variable that was filled in by the loader.
  TreeNodePtr tn = nid->get_loader_variable()->get_expression();
  assert(tn != NULL);
  // The expression should always be a LeafNode, or our code is inconsistent.
  LeafNodePtr ln = tn->isLeafNode();
  assert(ln != NULL);
  // Key the import variable map by just the unique number of the variable.
  uint64_t vnum = ln->nameId();
  // The import variables map is just a pointer to the object in the other map.
  import_variables[vnum] = nid;
  return nid;
}

template <typename... Args>
FunctionDescriptor *DescriptorSet::add_function_descriptor(rose_addr_t addr, Args &&... args)
{
  FunctionDescriptor & fd = map_emplace_or_replace(
    function_descriptors, addr, *this, std::forward<Args>(args)...);
  if (apidb) {
    // If the address of this function has an API DB entry, incorporate it here.
    auto apidef = apidb->get_api_definition(addr);
    if (!apidef.empty()) {
      fd.set_api(*apidef.front());
    }
  }
  return &fd;
}

namespace {
// The following include has the following definitions:
//
// unsigned char tags_yaml[];   // YAML tag definitions
// unsigned int  tags_yaml_len; // length of tags_yaml
#include "tags.yaml.ii"
}

std::shared_ptr<TagManager> DescriptorSet::create_tag_manager(ProgOptVarMap const & vm)
{
  // Currently we don't have a reason to have multiple tag managers, so we just maintain a
  // global one here.
  static std::shared_ptr<TagManager> global_manager;
  if (!global_manager) {
    // Create the global tag manager, initialize its built-in defaults, and load any user
    // modifications on top of that.
    global_manager = std::make_shared<TagManager>();
    global_manager->merge(reinterpret_cast<char const *>(tags_yaml), tags_yaml_len);
    auto const & config = vm.config().path_get("pharos.function_tags");
    if (config.IsMap()) {
      global_manager->merge(config);
    }
  }
  return global_manager;
}

RegisterVector DescriptorSet::get_usual_registers()
{
  RegisterDictionary const & rd = get_regdict();
  if (arch_name == "i386" || arch_name == "amd64") {
    SymbolicValuePtr protoval = SymbolicValue::instance();
    SymbolicRegisterStatePtr rstate = SymbolicRegisterState::instance(protoval, &rd);
    SymbolicMemoryMapStatePtr mstate = SymbolicMemoryMapState::instance();
    SymbolicStatePtr state = SymbolicState::instance(rstate, mstate);
    SymbolicRiscOperatorsPtr lrops = SymbolicRiscOperators::instance(*this, state);
    DispatcherPtr dispatcher = RoseDispatcherX86::instance(lrops, get_arch_bits(), NULL);
    return dispatcher->get_usual_registers();
  }
  else {
    return get_regdict().get_largest_registers();
  }
}

// This is called by all the DescriptorSet::DescriptorSet() constructors (including the "usual"
// one and the version in tracesem where we pass in an already built engine) but NOT by the
// super ancient constructor where we "build" a function manually.
void DescriptorSet::init()
{
  apidb = APIDictionary::create_standard(vm);

  tag_manager = create_tag_manager(vm);

  interp = engine->interpretation();
  if (interp == NULL) {
    throw std::runtime_error("Unable to analyze file (no executable content found).");
  }

  // Populate the file and memmap object so that we can read the program image.
  SgAsmGenericHeader *hdr = interp->get_headers()->get_headers()[0];
  auto file = SageInterface::getEnclosingNode < SgAsmGenericFile > (hdr);
  memory.set_memmap(interp->get_map());
  assert(memory);

  // The recommended way to determine the architecture size is ask the disassembler.
  RoseDisassembler *disassembler = engine->obtainDisassembler();
  arch_bytes = disassembler->wordSizeBytes();
  set_global_arch_bytes(arch_bytes);

  // OINFO << "Input file is a " << get_arch_bits() << "-bit Windows PE executable!" << LEND;
  // Set the architecture name.
  arch_name = disassembler->name();

  // This needs to be set before we do any emulation, and after we know our architecture size.
  // Perhaps it's time to move this _into_ the global descriptor set (or eliminate it completely).
  global_rops = NULL;
  if (get_arch_name() != "i386" && get_arch_name() != "amd64") {
    GWARN << "Analyzing executable with unsupported architecture '" << get_arch_name()
          << "', results may be incorrect." << LEND;
  }
  else {
    global_rops = SymbolicRiscOperators::instance(*this);
  }

  // Find all SgAsmPEImportDirectory objects in the project.  Walk these, extracting the DLL
  // name, and the names of the imported functions.  Create an import descriptor for each.
  // BUG? I'd prefer that this method not use querySubTree to obtain this list.
  std::vector<SgNode*> impdirs = NodeQuery::querySubTree(file, V_SgAsmPEImportDirectory);
  for (std::vector<SgNode*>::iterator it = impdirs.begin(); it != impdirs.end(); it++) {
    SgAsmPEImportDirectory* impdir = isSgAsmPEImportDirectory(*it);
    std::string dll = impdir->get_dll_name()->get_string();

    SgAsmPEImportItemPtrList& impitems = impdir->get_imports()->get_vector();
    for (SgAsmPEImportItemPtrList::iterator iit = impitems.begin(); iit != impitems.end(); iit++) {
      SgAsmPEImportItem* item = isSgAsmPEImportItem(*iit);
      rose_addr_t iat_va = item->get_iat_entry_va();
      if (iat_va != 0) {
        add_import(iat_va, dll, item->get_name()->get_string(), item->get_ordinal());
      }
    }
  }

  // Experimental new code to create "imports" based on ELF RelocEntry objects.
  SgAsmElfFileHeader* elfHeader = isSgAsmElfFileHeader(hdr);
  if (elfHeader) {
    for (SgAsmGenericSection *section : elfHeader->get_sections()->get_sections()) {
      if (SgAsmElfRelocSection *relocSection = isSgAsmElfRelocSection(section)) {
        SgAsmElfSymbolSection *symbolSection = isSgAsmElfSymbolSection(relocSection->get_linked_section());
        if (SgAsmElfSymbolList *symbols = symbolSection ? symbolSection->get_symbols() : NULL) {
          for (SgAsmElfRelocEntry *rel : relocSection->get_entries()->get_entries()) {
            if (rel->get_type() == SgAsmElfRelocEntry::R_X86_64_JUMP_SLOT ||
                rel->get_type() == SgAsmElfRelocEntry::R_386_JMP_SLOT) {
              rose_addr_t raddr = rel->get_r_offset();
              // ELF files don't say explicltly which files contain which symbols.  They're
              std::string dll("ELF");
              // Start with a NULL name.  The import descriptor constructor will change it to
              // '*INVALID*' if we're unable to find the symbol.
              std::string name;
              // But if there's a name in the ELF (and there should be) use it.
              unsigned long symbolIdx = rel->get_sym();
              if (symbolIdx < symbols->get_symbols().size()) {
                SgAsmElfSymbol *symbol = symbols->get_symbols()[symbolIdx];
                name = symbol->get_name()->get_string();
              }
              add_import(raddr, dll, name);
              //OINFO << "Added ELF 'import':" << addr_str(raddr) << " " << name << LEND;
            }
          }
        }
      }
    }
  }

  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

  time_point start_ts = clock::now();
  GDEBUG << "Creating the whole-program function call graph..." << LEND;
  function_call_graph = partitioner.functionCallGraph(P2::AllowParallelEdges::NO);
  duration secs = clock::now() - start_ts;
  GDEBUG << "Creation of the whole-program function call graph took "
         << secs.count() << " seconds." << LEND;

  // Create function descriptors, call descriptors, and global memory descriptors...
  create();

  // Since we need the call descriptors to create the new PDG graph, this seems like the right
  // place to do that for now.  In the future, this might be better someplace else.
  pdg_graph.populate(*this, partitioner);

  // Now make any connections that couldn't be made easily until we had complete data.
  update_connections();
  //dump(std::cout);
}

// When passed a NULL interpretation, we'll analyze the file specified in the program options.
// This is the standard way of constructing the descriptor set, despite the implementation
// being the other way around.  This is because there are some special constraints in tracesem
// that should really just be eliminated.
DescriptorSet::DescriptorSet(const ProgOptVarMap& povm) :
  DescriptorSet(povm,
                povm.count("file")
                ? std::vector<std::string>({povm["file"].as<bf::path>().native()})
                : std::vector<std::string>())
{}

void partition(const ProgOptVarMap & vm)
{
  using namespace std::string_literals;
  if (!vm.count("file")) {
    OFATAL << "No file to partition" << LEND;
    exit(EXIT_FAILURE);
  }
  auto pfile = vm["file"].as<bf::path>();
  auto file = pfile.native();
  if (!vm.count("serialize")) {
    auto filename = pfile.filename().native();
    auto sername = bf::path{filename + ".serialized"};
    auto vmcopy = vm;
    vmcopy.emplace("serialize"s,
                   boost::program_options::variable_value{boost::any{sername}, false});
    DescriptorSet ds{vmcopy, {file}, true};
  } else {
    DescriptorSet ds{vm, {file}, true};
  }
}

DescriptorSet::DescriptorSet(
  const ProgOptVarMap& povm,
  std::vector<std::string> const & specimens,
  bool partition_only)
  : vm(povm), specimen_names(specimens)
{
  // Instantiate a partitioning engine as requested by the options/configuration.
  boost::optional<std::string> pname = vm.get<std::string>("partitioner", "pharos.partitioner");
  if (!pname) {
    *pname = "pharos";
  }

  // The --stockpart option is deprecated, please use "--partitioner=rose" instead.
  bool sp = vm.count("stockpart");
  if (sp) {
    *pname = "rose";
    OWARN << "The option --stockpart has been deprecated.  Use --partitioner=rose instead." << LEND;
  }
  if (boost::iequals(*pname, "rose")) {
    engine = new P2::Engine();
    GINFO << "Using the standard ROSE function partitioner." << LEND;
  }
  else if (boost::iequals(*pname, "superset")) {
    engine = new SupersetEngine();
    GINFO << "Using the Pharos superset disassembly algorithm." << LEND;
  }
  else if (boost::iequals(*pname, "pharos")) {
    engine = new CERTEngine();
    GINFO << "Using the default Pharos function partitioner." << LEND;
  }
  else {
    engine = new CERTEngine();
    OERROR << "The partitioner '" << *pname << "' is not recognized, "
           << "using the Pharos function partitioner." << LEND;
  }

  // And then partition...
  partitioner = create_partitioner(vm, engine, specimen_names);

  if (!partition_only) {
    // Call communal init
    init();
  }
}


// This version of the constructor is only used by tracesem, which wants to pass in its own
// engine.  Pharos programs should always call the first constructor.  I'm currently passing
// both the engine and the partitioner in tracesem, but perhaps we don't really need both.
DescriptorSet::DescriptorSet(const ProgOptVarMap& povm, P2::Engine& eng,
                             P2::Partitioner&& par) : vm(povm), partitioner(std::move(par))
{
  engine = &eng;
  init();
}

std::string DescriptorSet::get_filename() const {
  return vm["file"].as<bf::path>().filename().native();
}

// Wes needed to be able to create a DescriptorSet from a single function because Wes loaded the
// function from an assembly source file, and made the SgAsgInstruction objects himself.
DescriptorSet::DescriptorSet(const ProgOptVarMap& povm, SgAsmFunction *func) : vm(povm) {
  // Because the function based approach is so wildly hacked, just hard-code 32-bits and
  // construct our global_rops now.
  arch_bytes = 4;
  global_rops = SymbolicRiscOperators::instance(*this);

  // We want to load API data for an imports in the created code.  WARNING! We have no imports
  // in this view of the world, so attempts to resolve imports will always fail.
  apidb = APIDictionary::create_standard(vm);

  // The fact that these three values are NULL is very likely to be problematic.  In
  // particular, the lack of a memory map will cause us to be very confused about what
  // addresses are defined in memory if we ever try to use that functionality.
  interp = nullptr;

  // Create a function descriptor for theone function.
  add_function_descriptor(func);

  // Add call descriptors, for each call instruction, even though the call targets don't
  // actually exist.
  SgAsmStatementPtrList &blocks = func->get_statementList();
  for (size_t x = 0; x < blocks.size(); x++) {
    SgAsmBlock *bb = isSgAsmBlock(blocks[x]);
    if (!bb) continue;

    SgAsmStatementPtrList &ilist = bb->get_statementList();
    for (size_t y = 0; y < ilist.size(); y++) {
      SgAsmX86Instruction *insn = isSgAsmX86Instruction(ilist[y]);

      if (insn_is_call(insn)) {
        call_descriptors.add(insn->get_address(), *this, insn);
      }
    }
  }
}

DescriptorSet::~DescriptorSet() {
  if (engine != NULL) delete engine;
}

RegisterDictionary const & DescriptorSet::get_regdict() const {
  return *partitioner.instructionProvider().registerDictionary();
}

void DescriptorSet::create() {
  // Create function descriptors first, because we need them to determine whether some jump
  // instructions are really tail-optimized calls or not.
  const P2::AstConstructionSettings &settings = P2::AstConstructionSettings::strict();
  for (const P2::Function::Ptr &function : partitioner.functions()) {
    SgAsmFunction* func = P2::Modules::buildFunctionAst(partitioner, function, settings);
    if (func) {
      add_function_descriptor(func);
    }
  }

  // Now create the other descriptors (by looking at individual instructions).
  for (P2::BasicBlock::Ptr b : partitioner.basicBlocks()) {
    for (SgAsmInstruction* insn : b->instructions()) {
      GTRACE << "INSN: " << debug_instruction(insn, 5, NULL) << LEND;

      SgAsmX86Instruction *xinsn = isSgAsmX86Instruction(insn);
      if (isSgAsmX86Instruction(insn) == NULL) continue;

      // Look for references to absolute addresses, in order to create global memory
      // descriptors.  This code is very similar to what we do to detect calls as well, but
      // it's not clear that we can do much better than to just duplicate it here.
      SgAsmOperandList *oplist = xinsn->get_operandList();
      SgAsmExpressionPtrList& elist = oplist->get_operands();
      for (SgAsmExpression * expr : elist) {
        // The value of the constant expression.
        uint64_t v = 0;
        //bool known_memory = false;
        if (isSgAsmValueExpression (expr)) {
          // Don't create global memory descriptors for calls and jumps to immediate addresses.
          // We know that these are code references, not data references.
          if (!insn_is_control_flow(xinsn)) {
            v = SageInterface::getAsmConstant(isSgAsmValueExpression(expr));
          }
        }
        else if (isSgAsmMemoryReferenceExpression(expr)) {
          //known_memory = true;
          SgAsmMemoryReferenceExpression* mr = isSgAsmMemoryReferenceExpression(expr);
          SgAsmExpression *addr_expr = mr->get_address();
          // This case handles expressions like [403123]
          if (isSgAsmValueExpression(addr_expr)) {
            v = SageInterface::getAsmConstant(isSgAsmValueExpression(addr_expr));
          }
          // This is the case for expressions like [eax+403123] and [ecx*4+403123]
          else if (isSgAsmBinaryExpression(addr_expr)) {
            // Is the constant always the right hand side?
            SgAsmExpression *const_expr = isSgAsmBinaryExpression(addr_expr)->get_rhs();
            if (isSgAsmValueExpression(const_expr)) {
              v = SageInterface::getAsmConstant(isSgAsmValueExpression(const_expr));
            }
            else {
              // In all of the cases that I looked at, these expressions were of the form [ecx+edx*2]
              GTRACE << "Right hand side of add expression is not constant!"
                     << " insn=" << debug_instruction(xinsn, 0)
                     << " expr=" << unparseExpression(const_expr, NULL, NULL) << LEND;}
          }
          // The remaning cases appear to be register dereferences e.g. "[eax]".  It appears
          // that V_SgAsmBinarySubtract is not actually used (at least on X86).
        }

        // The determination of which addresses to include is a total hack, and it probably
        // needs to be replaced with something more intelligent.  On the other hand, it would
        // be nice if something this general caused no significant downstream problems, because
        // it would be nice for this criteria to be sufficiently broad to catch all possible
        // memory refs.
        rose_addr_t addr = (rose_addr_t) v;
        if (possible_global_address(addr)) {
          // But don't create global memory descriptors for the imports.  We should probably be
          // checking that no-one writes to the import table as well, perhaps the rigth place to
          // do that is during emulation?
          ImportDescriptor *id = import_descriptors.get_import(v);
          if (id == NULL) {
            // Do we already have a global memory descriptor for this address?
            GlobalMemoryDescriptor* gmd = get_rw_global(addr); // add_ref()
            // If not, then create one.
            if (gmd == NULL) {
              map_emplace_or_replace(global_descriptors, addr, addr, get_arch_bits());
              gmd = get_rw_global(addr); // add_ref(), just created
            }
            // Either way, this instruction references the address...
            gmd->add_ref(xinsn);
            // We don't actually know if the reference was a read or a write, so this is WRONG!
            // But it'll do for my current testing needs.
            // if (known_memory) gmd->add_read(xinsn);
          }
        }
      }

      // We're only interested in call and jmp instructions for creating call descriptors.
      if (!insn_is_call_or_jmp(xinsn)) continue;
      // If the instruction was a jump, it also needs to be a jump to a function entry.
      if (insn_is_jmp(xinsn)) {
        boost::optional<rose_addr_t> taddr = insn_get_branch_target(insn);
        if (!taddr) continue;
        if (!get_func(*taddr)) continue;
      }
      // Create a call descriptor for the call, or the tail-call optimized jump instruction.
      map_emplace_or_replace(call_descriptors, insn->get_address(), *this, xinsn);
    }
  }
}

void DescriptorSet::update_connections() {
  for (CallDescriptorMap::value_type & pair : call_descriptors) {
    CallDescriptor& cd = pair.second;
    cd.update_connections();
  }

  for (FunctionDescriptorMap::value_type & pair : function_descriptors) {
    FunctionDescriptor& fd = pair.second;
    fd.update_connections(function_descriptors);
  }

  // Cory doesn't like the way this worked out, but propagating thunk info has to follow the
  // pass in the main update_connections() method.  This really needs to be some kind of a pass
  // based architecture.
  for (FunctionDescriptorMap::value_type & pair : function_descriptors) {
    FunctionDescriptor& fd = pair.second;
    fd.propagate_thunk_info();
  }
}

void DescriptorSet::validate(std::ostream &o) {
  for (CallDescriptorMap::value_type & pair : call_descriptors) {
    CallDescriptor& cd = pair.second;
    cd.validate(o, function_descriptors);
  }
  for (FunctionDescriptorMap::value_type & pair : function_descriptors) {
    FunctionDescriptor& fd = pair.second;
    fd.validate(o);
  }
  for (ImportDescriptorMap::value_type & pair : import_descriptors) {
    ImportDescriptor& id = pair.second;
    id.validate(o);
  }
  // I should probably be doing something here for globals...
}

void DescriptorSet::dump(std::ostream &o) const {
  for (const CallDescriptorMap::value_type & pair : call_descriptors) {
    o << pair.second << LEND;
  }
  for (const FunctionDescriptorMap::value_type & pair : function_descriptors) {
    o << pair.second << LEND;
  }
  for (const ImportDescriptorMap::value_type & pair : import_descriptors) {
    o << pair.second << LEND;
  }
  for (const GlobalMemoryDescriptorMap::value_type & pair : global_descriptors) {
    o << pair.second << LEND;
  }
}

void DescriptorSet::resolve_imports() {
  // For each import in our file...
  for (auto & pair : import_descriptors) {
    ImportDescriptor &id = pair.second;
    if (!id.is_dll_valid()) {
      continue;
    }
    auto root = id.get_dll_root();
    GDEBUG << "Resolving imports for: " << id << " in DLL root: " << root << LEND;
    // If the user specified a delta in the user config file, we don't need to load a delta
    // from the DLL config files.  This also serves to eliminate the warnings when the entry is
    // not found in the DLL config files.
    StackDelta isd = id.get_stack_delta();
    if (isd.confidence == ConfidenceUser)
      continue;

    APIDefinitionList fdesc;
    if (id.is_name_valid()) {
      fdesc = apidb->get_api_definition(root, id.get_name());
    }
    if (fdesc.empty() && id.get_ordinal() != 0) {
      fdesc = apidb->get_api_definition(root, id.get_ordinal());
    }
    if (!fdesc.empty()) {
      id.merge_api_definition(*fdesc.front());
    } else {
      GWARN << "No stack delta information for: " << id.get_best_name() << LEND;
    }

    // This is where we can first report the full prototypes of the imported functions that
    // actually occur in the program being analyzed...
    if (GTRACE) {
      const ParameterList& params = id.get_function_descriptor()->get_parameters();
      GTRACE << "Import " << id.get_long_name() << " has parameters: ";
      params.debug();
    }
  }

  // Now update the connections...  I'm not sure if this is really needed or not.
  update_connections();
}

// Find an import descriptor given the symbolic value that the loader filled in for that
// import.   This is primarily used when resolving
ImportDescriptor* DescriptorSet::get_import_by_variable(SymbolicValuePtr v) {
  // Get the expression provided by the caller.
  TreeNodePtr tn = v->get_expression();
  if (tn == NULL) return NULL;
  // The expression should always be a LeafNode, or it's not really an import.
  LeafNodePtr ln = tn->isLeafNode();
  if (ln == NULL) return NULL;
  // Get the unique variable number.
  uint64_t vnum = ln->nameId();
  // Attempt to lookup the import by that variable number in the map.
  ImportVariableMap::iterator finder = import_variables.find(vnum);
  // If it wasn't found, we're not an import.
  if (finder == import_variables.end()) return NULL;
  // If it was, return it.
  return finder->second;
}

void DescriptorSet::update_import_target(SymbolicValuePtr& v, SgAsmX86Instruction* insn) {
  SDEBUG << "Call target is to loader defined value: " << *v << LEND;
  ImportDescriptor* id = get_import_by_variable(v);
  // Yes, it's a call to an import.  Update the call target list with a new target.
  if (id != NULL) {
    SDEBUG << "The call " << debug_instruction(insn)
           << " was to import " << id->get_long_name() << LEND;
    CallDescriptor* cd = get_rw_call(insn->get_address()); // add_import_target()
    cd->add_import_target(id);
  }
  else {
    SDEBUG << "The constant call target was not resolved." << LEND;
  }
}

const FunctionDescriptor*
DescriptorSet::get_func_containing_address(rose_addr_t addr) const {
  std::vector<const FunctionDescriptor*> fds = get_funcs_containing_address(addr);
  if (fds.size() == 0) {
    return NULL;
  }
  // This is not intended to be a permanent warning because there's nothing the end user can
  // act on!  while it might be appropriate to keep this function as a "helper", it would
  // probably be better to eliminate it entirely in favor of newer get_funcs_containg_address()
  // API.
  else if (fds.size() > 1) {
    OWARN << "Address " << addr_str(addr) << " was used by more than one function!" << LEND;
  }

  return fds[0];
}

std::vector<const FunctionDescriptor*>
DescriptorSet::get_funcs_containing_address(rose_addr_t addr) const {
  std::vector<const FunctionDescriptor*> funcs;
  const AddressInterval ai(addr);
  for (const P2::Function::Ptr & func : partitioner.functionsOverlapping(ai)) {
    const FunctionDescriptor* fd = get_func(func->address());
    if (fd) {
      funcs.push_back(fd);
    }
    // If there was a P2::Function::Ptr, but not a FunctionDescriptor that's an assertion
    // worthy level programming error, but let's not exit needlessly.
    else {
      GERROR << "No function found at address " << addr_str(addr) << LEND;
    }
  }
  // This list might be empty, and that's not an unexpected condition.
  return funcs;
}

std::vector<FunctionDescriptor*>
DescriptorSet::get_rw_funcs_containing_address(rose_addr_t addr) {
  std::vector<FunctionDescriptor*> funcs;
  const AddressInterval ai(addr);
  for (const P2::Function::Ptr & func : partitioner.functionsOverlapping(ai)) {
    FunctionDescriptor* fd = get_rw_func(func->address());
    if (fd) {
      funcs.push_back(fd);
    }
    // If there was a P2::Function::Ptr, but not a FunctionDescriptor that's an assertion
    // worthy level programming error, but let's not exit needlessly.
    else {
      GERROR << "No function found at address " << addr_str(addr) << LEND;
    }
  }
  // This list might be empty, and that's not an unexpected condition.
  return funcs;
}

// Find a general purpose register in an semi-architecture independent way.
// Now implemented in terms of a method in misc.cpp that does the heavy lifting.
RegisterDescriptor
DescriptorSet::get_arch_reg(const std::string & name) const
{
  return pharos::get_arch_reg(get_regdict(), name, arch_bytes);
}

unsigned int DescriptorSet::get_concurrency_level(ProgOptVarMap const & vm)
{
  auto level_opt = vm.get<int>("threads", "concurrency_level");
  if (!level_opt) {
    return 1;
  }
#ifdef PHAROS_BROKEN_THREADS
  GWARN << "Multi-threading has been disabled in this binary." << LEND;
  return 1;
#else
  auto level = *level_opt;
  if (level > 0) {
    return unsigned(level);
  }
  auto hwc = std::thread::hardware_concurrency();
  if (level == 0) {
    return hwc;
  }
  auto inverted_level = unsigned(-level);
  if (hwc <= inverted_level) {
    return 1;
  }
  return hwc - inverted_level;
#endif
}


} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
