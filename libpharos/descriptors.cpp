// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/foreach.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/property_map/property_map.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/visitors.hpp>
#include <boost/graph/named_function_params.hpp>

#include <rose.h>
#include <boost/property_tree/json_parser.hpp>
#include <AstTraversal.h>

#include "misc.hpp"
#include "descriptors.hpp"
#include "pdg.hpp"

DescriptorSet* global_descriptor_set = NULL;

DescriptorSet::DescriptorSet(SgAsmInterpretation *interpretation, ProgOptVarMap *povm) {
  // Set this immediately, because if we don't we can't use it from within
  // specific descriptor types.  Hackish and ugly. :-(
  global_descriptor_set = this;

  // save the arguments
  vm = povm;

  // Set the library path if it was provided, or use the default if it was not.
  if (vm != NULL) {
    auto v = vm->get<std::string>("library", "pharos.library");
    lib_path = v ? *v : DEFAULT_LIB;
  } else {
    lib_path = DEFAULT_LIB;
  }

  // Instead of passing in a project, not we pass in an interpretation.
  interp = interpretation;


  // Populate the file and memmap object so that we can read the program image.
  SgAsmGenericHeader *hdr = interp->get_headers()->get_headers()[0];
  file = SageInterface::getEnclosingNode < SgAsmGenericFile > (hdr);
  memmap = (interp->get_map());
  assert(memmap != NULL);

  // Robb Matzke did this instead.  Perhaps we shouldn't be ignoring the values other than [0]
  // in the get_headers call above?
#if 0
  std::set<SgAsmGenericFile*> emittedFiles;
  BOOST_FOREACH (SgAsmGenericHeader *fileHeader, interp->get_headers()->get_headers()) {
    SgAsmGenericFile *container = SageInterface::getEnclosingNode<SgAsmGenericFile>(fileHeader);
    if (emittedFiles.insert(container).second) {
      container->dump(stdout);
      int i=0;
      BOOST_FOREACH (SgAsmGenericSection *section, container->get_sections()) {
        printf("Section [%d]:\n", i++);
        section->dump(stdout, "  ", -1);
      }
    }
  }
#endif

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
        add_import(ImportDescriptor(dll, item));
      }
    }
  }

  // Get the Win32Interpretation.  We only want to traverse this portion of the executable for
  // finding functions and calls, so we don't mix the DOS stub into the analysis.
  // BUG? Doesn't handle multiple files, assumes Win32 executables, etc. etc.
  // interp = GetWin32Interpretation(project);

  GDEBUG << "building FCG" << LEND;
  rose::BinaryAnalysis::FunctionCall().build_cg_from_ast(interp, function_call_graph);

  // Traverse the AST looking for calls and functions.
  traverse(interp);

  // create an spTracker to do stack analysis. This is required for update_connections
  // or virtual function call tracking will not work.
  sp_tracker = new spTracker(this);

  // Now make any connections that couldn't be made easily until we had complete data.
  update_connections();
}

void DescriptorSet::add_import(ImportDescriptor id) {
  // The map makes a copy of the Import Descriptor object that was passed...
  import_descriptors[id.get_address()] = id;

  // Get a pointer to the newly allocated copy in the map.
  ImportDescriptor* nid = import_descriptors.get_import(id.get_address());
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
}

// Wes needed to be able to create a DescriptorSet from a single function because he loaded the
// function from an assembly source file, and made the SgAsgInstruction objects himself.
DescriptorSet::DescriptorSet(SgAsmFunction *func, ProgOptVarMap *povm) {
  // This is still our "global" descriptor set even though it only has a single function in it.
  // The need for a limied-scope descriptor set shows that we've been naughty in allowing the
  // existing constructor to set the global value.  Cory figures we'll need to correct that.
  global_descriptor_set = this;

  // save the arguments
  vm = povm;

  // Set the library path if it was provided, or use the default if it was not.
  if (vm != NULL && vm->count("library") != 0) {
    lib_path = (*vm)["library"].as<std::string>();
  }
  else {
    lib_path = DEFAULT_LIB;
  }

  // The fact that these three values are NULL is very likely to be problematic.  In
  // particular, the lack of a memory map will cause us to be very confused about what
  // addresses are defined in memory if we ever try to use that functionality.
  interp = NULL;
  memmap = NULL;
  file = NULL;

  sp_tracker = new spTracker(this);

  // Create a function descriptor for theone function.
  function_descriptors[func->get_address()] = FunctionDescriptor(func);

  // WARNING! We have no imports in this view of the world, so attempts to resolve imports will
  // always fail.

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
        call_descriptors[insn->get_address()] = CallDescriptor(insn);
      }
    }
  }
}

DescriptorSet::~DescriptorSet() {
  delete sp_tracker;
}

spTracker * DescriptorSet::get_spTracker() const { return sp_tracker; }

// This method should really be a method on MemoryMap.
bool DescriptorSet::memory_initialized(rose_addr_t addr) {
  // The zero is a mask meaning we don't care what the protection bits are?
  if (memmap->at(addr).exists(0)) {
    // Cory has temporarily disabled this code, but he needs to harass Robb about it.

    //const Sawyer::Container::AddressSegment<> seg = memmap->at(addr);
    //const MemoryMap::Segments::Node& sinode = memmap->at(addr);
    //const MemoryMap::Segment& seg = sinode.value();
    //std::string bufname = seg.get_buffer()->get_name();
    //if (bufname.compare(0, 5, "anon ") == 0)
    //  return false;
    //return true;
    return false;
  }
  return false;
}

bool DescriptorSet::memory_in_image(rose_addr_t addr) {
  // The zero is a mask meaning we don't care what the protection bits are?
  return memmap->at(addr).exists(0);
}

rose_addr_t DescriptorSet::read32(rose_addr_t addr) {
  int32_t buff;
  rose_addr_t naddr = 0;
  size_t nread = file->read_content(memmap, addr, &buff, sizeof(buff), false);
  if (nread == sizeof(buff)) {
    // naddr is concrete value of function pointer
    naddr = buff;
    return naddr;
  }

  return 0;
}

SgAsmInstruction* DescriptorSet::get_insn(rose_addr_t addr) const {
  AddrInsnMap::const_iterator finder = insn_map.find(addr);
  if (finder == insn_map.end()) return NULL;
  return (*finder).second;
}

void DescriptorSet::add_insn(rose_addr_t addr, SgAsmInstruction* insn) {
  insn_map[addr] = insn;
}

// This is the traversal part of the class.
void DescriptorSet::preOrderVisit(SgNode* n) {
  SgAsmInstruction* ainsn = isSgAsmInstruction(n);
  if (ainsn != NULL) add_insn(ainsn->get_address(), ainsn);

  if (isSgAsmX86Instruction(n) != NULL) {
    SgAsmX86Instruction *insn = isSgAsmX86Instruction(n);
    GTRACE << "INSN: " << debug_instruction(insn, 5, NULL) << LEND;

    // Look for references to absolute addresses, in order to create global memory descriptors.
    // This code is very similar to what we do to detect calls as well, but it's not clear that
    // we can do much better than to just duplicate it here.
    SgAsmOperandList *oplist = insn->get_operandList();
    SgAsmExpressionPtrList& elist = oplist->get_operands();
    BOOST_FOREACH(SgAsmExpression * expr, elist) {
      // The value of the constant expression.
      uint64_t v = 0;
      //bool known_memory = false;
      if (isSgAsmValueExpression (expr)) {
        // Don't create global memory descriptors for calls and jumps to immediate addresses.
        // We know that these are code references, not data references.
        if (!insn_is_control_flow(insn)) {
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
          SgAsmExpression *const_expr =
            isSgAsmBinaryExpression(addr_expr)->get_rhs();
          if (isSgAsmValueExpression(const_expr)) {
            v = SageInterface::getAsmConstant(isSgAsmValueExpression(const_expr));
          }
          else {
            // In all of the cases that I looked at, these expressions were of the form [ecx+edx*2]
            GTRACE << "Right hand side of add expression is not constant!"
                   << " insn=" << debug_instruction(insn, 0)
                   << " expr=" << unparseExpression(const_expr, NULL, NULL) << LEND;}
        }
        // The remaning cases appear to be register dereferences e.g. "[eax]".  It appears
        // that V_SgAsmBinarySubtract is not actually used (at least on X86).
      }

      // The determination of which addresses to include is a total hack, and it probably needs
      // to be replaced with something more intelligent.  On the other hand, it would be nice
      // if something this general caused no significant downstream problems, because it would
      // be nice for this criteria to be sufficiently broad to catch all possible memory refs.
      rose_addr_t addr = (rose_addr_t) v;
      if (possible_global_address(addr)) {
        // But don't create global memory descriptors for the imports.  We should probably be
        // checking that no-one writes to the import table as well, perhaps the rigth place to
        // do that is during emulation?
        ImportDescriptor *id = import_descriptors.get_import(v);
        if (id == NULL) {
          // Do we already have a global memory descriptor for this address?
          GlobalMemoryDescriptor* gmd = get_global(addr);
          // If not, then create one.
          if (gmd == NULL) {
            global_descriptors[addr] = GlobalMemoryDescriptor(addr);
            gmd = get_global(addr);
          }
          // Either way, this instruction references the address...
          gmd->add_ref(insn);
          // We don't actually know if the reference was a read or a write, so this is WRONG!
          // But it'll do for my current testing needs.
          // if (known_memory) gmd->add_read(insn);
        }
      }
    }

    if (insn->get_kind() != x86_call && insn->get_kind() != x86_farcall) return;
    //OINFO << "Creating call descriptor for insn:" << debug_instruction(insn) << LEND;
    call_descriptors[insn->get_address()] = CallDescriptor(insn);
  } else if (isSgAsmFunction(n) != NULL) {
    SgAsmFunction *func = isSgAsmFunction(n);
    function_descriptors[func->get_address()] = FunctionDescriptor(func);
  }
}

void DescriptorSet::do_update_vf_call_descriptors(CallType t) {
  CallDescMapPredicate p(t);
  CallDescriptorMap::filtered_iterator it = calls_filter_begin(p);
  CallDescriptorMap::filtered_iterator end = calls_filter_end(p);

  while (it != end) {
    rose_addr_t call_addr = it->first;
    CallDescriptor &cd = it->second;

    SgAsmFunction *func = insn_get_func(cd.get_insn());
    assert(func);
    FunctionDescriptor &fd = function_descriptors[func->get_address()];
    PDG * pdg = fd.get_pdg();
    if (pdg != NULL && cd.check_virtual(pdg)) {
      // this may be a virtual function call
      call_descriptors[call_addr].update_call_type(CallVirtualFunction, ConfidenceGuess);
    }
    ++it;
  }
}

// Refining the descriptor set currently means searching for virtual functions
void DescriptorSet::update_vf_call_descriptors() {
  do_update_vf_call_descriptors(CallRegister);
  do_update_vf_call_descriptors(CallUnknown);
}

void DescriptorSet::update_connections() {
  BOOST_FOREACH(CallDescriptorMap::value_type & pair, call_descriptors) {
    CallDescriptor& cd = pair.second;
    cd.update_connections();
  }

  BOOST_FOREACH(FunctionDescriptorMap::value_type & pair, function_descriptors) {
    FunctionDescriptor& fd = pair.second;
    fd.update_connections(function_descriptors);
  }

  // Cory doesn't like the way this worked out, but propagating thunk info has to follow the
  // pass in the main update_connections() method.  This really needs to be some kind of a pass
  // based architecture.
  BOOST_FOREACH(FunctionDescriptorMap::value_type & pair, function_descriptors) {
    FunctionDescriptor& fd = pair.second;
    fd.propagate_thunk_info();
  }
}

void DescriptorSet::validate(std::ostream &o) {
  BOOST_FOREACH(CallDescriptorMap::value_type & pair, call_descriptors) {
    CallDescriptor& cd = pair.second;
    cd.validate(o, function_descriptors);
  }
  BOOST_FOREACH(FunctionDescriptorMap::value_type & pair, function_descriptors) {
    FunctionDescriptor& fd = pair.second;
    fd.validate(o);
  }
  BOOST_FOREACH(ImportDescriptorMap::value_type & pair, import_descriptors) {
    ImportDescriptor& id = pair.second;
    id.validate(o);
  }
  // I should probably be doing something here for globals...
}

void DescriptorSet::dump(std::ostream &o) {
  BOOST_FOREACH(CallDescriptorMap::value_type & pair, call_descriptors) {
    o << pair.second << LEND;
  }
  BOOST_FOREACH(FunctionDescriptorMap::value_type & pair, function_descriptors) {
    o << pair.second << LEND;
  }
  BOOST_FOREACH(ImportDescriptorMap::value_type & pair, import_descriptors) {
    o << pair.second << LEND;
  }
  BOOST_FOREACH(GlobalMemoryDescriptorMap::value_type & pair, global_descriptors) {
    o << pair.second << LEND;
  }
}

void DescriptorSet::resolve_imports() {
  // Have we attempted to load a given DLL config?
  std::set < std::string > loaded;
  // The import descriptors that we've loaded from the DLL config files keyed by name.
  ImportNameMap import_names;
  // The import descriptors that we've loaded from the DLL config files keyed by ordinal.
  ImportNameMap import_ordinals;

  // For each import in our file...
  BOOST_FOREACH(ImportDescriptorMap::value_type & pair, import_descriptors) {
    ImportDescriptor* id = &(pair.second);
    std::string root = id->get_dll_root();
    GDEBUG << "Resolving imports for: " << *id << " in DLL root: " << root << LEND;

    // If we haven't already loaded the DLL config file, do so now.
    if (loaded.find(root) == loaded.end()) {
      std::string dll_config_filename = lib_path + "/configs/" + to_lower(root) + ".json";
      using boost::property_tree::ptree;
      ptree dll_tree;
      // We should be checking for missing files and so forth here.

      try {
        read_json(dll_config_filename, dll_tree);

        BOOST_FOREACH(const ptree::value_type & v, dll_tree.get_child("config.exports")) {
          std::string name = to_lower(v.first.data());

          // CRAZY INEXPLICABLE CODE REQUIRED!  The need for this code is a complete mystery to
          // Cory, but without it, we end up "off by one" when reading the JSON DLL config
          // files, and thus assign the incorrect ordinal to import.

#if 1 // Enable fixes in general.

#if 1 // Enable the brief fix instead of the complex fix.
          v.second.get_optional<size_t>("foo");
#else
          // This more complex fix helps hone in on where the problem really occurs, which is
          // in the call to get_value_optional(), which shouldn't be called at all because node
          // should be false since there's no JSON element named "foo".
          const ptree& crazy = v.second;
          boost::optional<const ptree &> node = crazy.get_child_optional("foo");
          if (node) {
            const boost::property_tree::ptree& cnode = *node;
            // This line actually causes the fix.
            cnode.get_value_optional<size_t>();
          }
#endif
#endif

          ImportDescriptor* dll_id = new ImportDescriptor;
          // The the function in imports.cpp for an explanation of what this sillyness is.
          dll_id->set_names_hack(name);
          // Now read fields from the JSON config.
          dll_id->read_config(v.second);

          // Add the entry to the map, keyed by the normalized name.
          std::string norm_name = dll_id->get_normalized_name();
          import_names[norm_name] = dll_id;
          // Ordinal zero is not real?  Cory has confirmed that the PE specification sets
          // ordinal base to one by default, but not that the loader refuses to import ordinals
          // with the value zero.  Hopefully this isn't a problem.
          if (dll_id->get_ordinal() != 0) {
            std::string ord_name = dll_id->get_ordinal_name();
            GTRACE << "Import descriptor ordinal name is: " << ord_name
                   << " which is really " << dll_id->get_best_name() << LEND;
            import_ordinals[ord_name] = dll_id;
          }
        }
        GINFO << "Read DLL config file: '" << dll_config_filename << "'..." << LEND;
      }
      catch (...) {
        // At least report that we've had a problem parsing the JSON file.  Catching everything
        // is probably a bug here, and we should narrow the catch to the exceptions thrown by
        // boost property tree.
        GERROR << "Unexpected error parsing JSON file: " << dll_config_filename << LEND;
      }

      loaded.insert(root);
    }

    // If the user specified a delta in the user config file, we don't need to load a delta
    // from the DLL config files.  This also serves to eliminate the warnings when the entry is
    // not found in the DLL config files.
    StackDelta isd = id->get_stack_delta();
    if (isd.confidence == ConfidenceUser)
      continue;

    // Now that we know we've loaded the DLL config file, look for this import in the import
    // name map.
    std::string normal = id->get_normalized_name();
    ImportNameMap::iterator ifinder = import_names.find(normal);
    bool found = false;
    if (ifinder != import_names.end()) {
      found = true;
      id->merge_export_descriptor(ifinder->second);
    } else {
      // If we couldn't find the import by name, try looking it up by ordinal.
      if (id->get_ordinal() != 0) {
        std::string ord_name = id->get_ordinal_name();
        ifinder = import_ordinals.find(ord_name);
        if (ifinder != import_ordinals.end()) {
          found = true;
          id->merge_export_descriptor(ifinder->second);
          GDEBUG << "Found import by ordinal: " << ord_name
                 << " is really " << id->get_long_name() << LEND;
        }
      }
    }

    if (!found) {
      GWARN << "No stack delta information for: " << id->get_best_name() << LEND;
    }

    // This is where we can first report the full prototypes of the imported functions that
    // actually occur in the program being analyzed...
    if (GDEBUG) {
      const ParameterList& params = id->get_function_descriptor()->get_parameters();
      GDEBUG << "Import " << id->get_long_name() << " has parameters: ";
      params.debug();
    }
  }

  // Now update the connections...  I'm not sure if this is really needed or not.
  //update_connections();

  // Free memory for temporarily allocated import descriptors.
  BOOST_FOREACH(ImportNameMap::value_type & pair, import_names) {
    delete pair.second;
  }
}

void DescriptorSet::read_config() {
  if (!vm) {
    return;
  }
  auto import = vm->get<std::string>("imports", "pharos.json_config");
  if (import) {
    read_config(*import);
  }
}

void DescriptorSet::read_config(std::string filename) {
  // Build a map of normalized import names to import descriptor objects so that names in the
  // config file get associated with the correct descriptor.  This is the only place I know of
  // so far where we'll want to lookup imports by name and not by address.  If it ends up being
  // used more widely, I'll move the code elsewhere.
  ImportNameMap import_names;
  BOOST_FOREACH(ImportDescriptorMap::value_type & pair, import_descriptors) {
    import_names[pair.second.get_normalized_name()] = &(pair.second);
  }
  using boost::property_tree::ptree;
  ptree config_tree;
  read_json(filename, config_tree);

  // For each descriptor type, parse the config tree to get the key and find the appropriate
  // descriptor.  If the descriptor is not found, whine mildly, and then create a new
  // descriptor.  We do this because we assume the use knows something about the future that we
  // do not (yet).

  // Functions.
  BOOST_FOREACH(ptree::value_type & v, config_tree.get_child("config.funcs")) {
    // The value_type v is a pair.  First is the key and second is the data.

    rose_addr_t addr = parse_number(v.first.data());
    FunctionDescriptor* fd = function_descriptors.get_func(addr);
    if (fd == NULL) {
      GWARN << "No function found at address " << std::hex << addr << std::dec
            << ", creating a new function descriptor." << LEND;
      fd = new FunctionDescriptor;
      function_descriptors[addr] = *fd;
    }
    fd->read_config(v.second);
  }

  // Imports.
  BOOST_FOREACH(ptree::value_type & v, config_tree.get_child("config.imports")) {
    std::string name = to_lower(v.first.data());
    GTRACE << "IMPORT:" << name << LEND;
    ImportNameMap::iterator ifinder = import_names.find(name);
    ImportDescriptor* id;
    if (ifinder != import_names.end()) {
      id = ifinder->second;
      id->read_config(v.second);
    } else {
      GWARN << "No import named '" << name << "', creating a new import descriptor." << LEND;
      id = new ImportDescriptor;
      import_names[name] = id;
      id->read_config(v.second);
      // This is a little less wrong than it was before... but it's still not correct.  That's
      // probably because I'm having trouble undersanding exactly when you'd want to add an
      // import that wasn't in the import table.  It has something to do with obfuscated
      // imports.  But would we always have an address to uniquely key the import in that case
      // like we do currently for an import table?  If not, what would we uniquely key the
      // imports by?
      add_import(*id);
    }
  }

  // Calls.
  BOOST_FOREACH(ptree::value_type & v, config_tree.get_child("config.calls")) {
    rose_addr_t addr = parse_number(v.first.data());
    GTRACE << "CALL:" << addr_str(addr) << LEND;
    CallDescriptor* cd = call_descriptors.get_call(addr);
    if (cd == NULL) {
      GWARN << "No CALL instructon at address " << addr_str(addr)
            << ", creating a new call descriptor." << LEND;
      cd = new CallDescriptor;
      call_descriptors[addr] = *cd;
    }
    cd->read_config(v.second, &import_names);
  }

  // Resolve imports.  Should the user be able to turn this off?
  resolve_imports();

  // Now update the connections...
  update_connections();
}

void DescriptorSet::write_config(std::string filename) {
  // The whole tree
  boost::property_tree::ptree config_tree;

  BOOST_FOREACH(FunctionDescriptorMap::value_type & pair, function_descriptors) {
    FunctionDescriptor* fd = &(pair.second);
    boost::property_tree::ptree descriptor;
    fd->write_config(&descriptor);
    config_tree.put_child("config.funcs." + fd->address_string(), descriptor);
  }
  BOOST_FOREACH(CallDescriptorMap::value_type & pair, call_descriptors) {
    CallDescriptor* cd = &(pair.second);
    boost::property_tree::ptree descriptor;
    cd->write_config(&descriptor);
    config_tree.put_child("config.calls." + cd->address_string(), descriptor);
  }
  BOOST_FOREACH(ImportDescriptorMap::value_type & pair, import_descriptors) {
    ImportDescriptor* id = &(pair.second);
    boost::property_tree::ptree descriptor;
    id->write_config(&descriptor);
    typedef boost::property_tree::ptree::path_type PathType;
    // We have to use an alternate character for the path separator, because there are usually
    // dots in the DLL names.  Here we use slash, which should not occur in the DLL names or
    // the import function names.
    std::string key = "config/imports/" + id->get_long_name();
    config_tree.put_child(PathType(key, '/'), descriptor);
  }

  write_json(filename, config_tree);
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

//
// Support for topo sorting the function list.
//

typedef boost::graph_traits<FCG>::vertex_descriptor FCGVertex;

template<typename OutputIterator>
struct ptopo_sort_visitor: public boost::dfs_visitor<> {
  ptopo_sort_visitor(OutputIterator _iter):
    m_iter(_iter) {
  }

  template<typename Edge, typename Graph>
  void back_edge(const Edge& e, Graph& g) {
    /* BOOST_THROW_EXCEPTION(not_a_dag()); */

    FCGVertex src = source(e, g);
    FCGVertex dst = target(e, g);
    SgAsmFunction *sf = get(boost::vertex_name, g, src);
    SgAsmFunction *df = get(boost::vertex_name, g, dst);

    GWARN << "Function call graph has a cycle: src=" << addr_str(sf->get_address())
          << " dst=" << addr_str(df->get_address()) << " stack analysis may be incorrect." << LEND;
  }

  template <typename Vertex, typename Graph>
  void finish_vertex(const Vertex& u, Graph&) {
    *m_iter++ = u;
  }

  OutputIterator m_iter;
};

template<typename VertexListGraph, typename OutputIterator, typename P,
         typename T, typename R>
void ptopological_sort(VertexListGraph& g, OutputIterator result,
                       const boost::bgl_named_params<P, T, R>& params) {
  typedef ptopo_sort_visitor<OutputIterator> PtopoVisitor;
  depth_first_search(g, params.visitor(PtopoVisitor(result)));
}

template<typename VertexListGraph, typename OutputIterator>
void ptopological_sort(VertexListGraph& g, OutputIterator result) {
  ptopological_sort(g, result,
                    boost::bgl_named_params<int, boost::buffer_param_t>(0)); // bogus
}

FuncDescVector DescriptorSet::funcs_in_bottom_up_order() {
  // We should probably be caching the program fcg and and possibly even the sorted list.

  GDEBUG << "pseudo topo sort" << LEND;
  std::list<FCGVertex> funcvs;
  ptopological_sort(function_call_graph, std::back_inserter(funcvs));

  FuncDescVector funcs;
  GTRACE << "new order:" << LEND;

  // there has got to be a better way to do this...
  BOOST_FOREACH(FCGVertex fv, funcvs) {
    SgNode *node = get(boost::vertex_name, function_call_graph, fv);
    SgAsmFunction* func = isSgAsmFunction(node);
    if (func == NULL) {
      GERROR << "Unexpected non-function node in topo sort" << LEND;
      continue;
    }
    FunctionDescriptor* fd = get_func(func->get_address());
    funcs.push_back(fd);
    GTRACE << " " << fd->address_string() << LEND;
  }

  return funcs;
}

FunctionDescriptor* DescriptorSet::get_fd_from_insn(const SgAsmInstruction *insn) {
  SgAsmFunction* func = insn_get_func(insn);
  if (func == NULL) return NULL;
  return get_func(func->get_address());
}
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
