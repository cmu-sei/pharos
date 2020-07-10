// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include <rose.h>

#include "oojson_exporter.hpp"

#include "misc.hpp"
#include "descriptors.hpp"
#include "usage.hpp"
#include "vcall.hpp"

#include "ooelement.hpp"
#include "ooclass.hpp"
#include "oovftable.hpp"
#include "oomember.hpp"
#include "oomethod.hpp"
#include "demangle.hpp"

using namespace pharos::json;

namespace pharos {

using VirtualFunctionCallInformationPtr = boost::shared_ptr<VirtualFunctionCallInformation>;

std::string type_of_method (OOMethodPtr m) {
  return m->is_constructor () ? "ctor" :
    m->is_deleting_destructor () ? "deldtor" :
    m->is_destructor () ? "dtor" : "meth";
}

// this is a simple utility function to convert a rose address to a hex string
std::string addr2str (rose_addr_t addr) {
  std::stringstream stream;
  stream << "0x" << std::hex << addr;
  return stream.str();
}

// convert/append an integer to a string
std::string intcat (int i, int base) {
  std::stringstream stream;
  if (base == 16) {
    stream << "0x" << std::hex << i;
  }
  else if (base == 10)  {
    stream << std::dec << i;
  }
  return stream.str();
}

// create a new JSON exporter without a JSON output filename.
OOJsonExporter::OOJsonExporter () {
  json = simple_builder ()->object ();
  num_structs = 0;
  vcalls_resolved = 0;
  usages_found = 0;
  json_filename = "";
}
// create a new JSON exporter with the JSON output filename.
OOJsonExporter::OOJsonExporter(ProgOptVarMap& vm) {
  json = simple_builder ()->object ();
  num_structs = 0;
  vcalls_resolved = 0;
  usages_found = 0;

  if (vm.count("json")) {
    json_filename = vm["json"].as<std::string>();
  }
  else {
    std::string ext(".json");
    std::string input_path = vm["file"].as<std::string>();
    json_filename = (std::string(boost::filesystem::basename(input_path.c_str())) + ext);
  }

  std::string exe_filepath = vm["file"].as<std::string>();
  exe_filename = boost::filesystem::path(exe_filepath).filename().string();
  file_md5 = get_file_md5(exe_filepath);

  GINFO << "Exporting classes to JSON file: " << json_filename << LEND;
}

// std::string
// OOJsonExporter::demangle_class_name(std::string mangled_name) {

//   try {
//     auto dtype = demangle::visual_studio_demangle(mangled_name);
//     if (dtype) {
//       return dtype->get_class_name();
//     }
//   }
//   catch (const demangle::Error &) {
//     // It doesn't matter what the error was.  We might not have even
//     // been a mangled name.
//   }
//    return "";
// }

std::string
OOJsonExporter::demangle_method_name(std::string mangled_name) {

  // attempt to demangle the import to better set the method name
  try {
    auto dtype = demangle::visual_studio_demangle(mangled_name);

    if (dtype) {

      // Evaluate imported __thiscall method
      if (dtype->symbol_type == demangle::SymbolType::ClassMethod) {
        return dtype->get_method_name();
      }
    }
  }
  catch (const demangle::Error &) {
    // I guess this isn't a mangled OO Method
  }
  return "";
}

// this function exports the JSON to a file.
void OOJsonExporter::export_json(void) {

  // write the JSON file out.
  std::ofstream f (json_filename);
  f << pharos::json::pretty () << *json;
  f.close ();

  // Cory says this message should be emitted for --report output also.
  GDEBUG << "Found " << num_structs << " classes, "
         << methods_associated.size() << " methods, "
         << vcalls_resolved << " virtual calls, and "
         << usages_found << " usage instructions." << LEND;

  OINFO << "Successfully exported to JSON file '" << json_filename << "'." << LEND;
}

// JSG isn't sure what to do with the object instances in OOAnalyzer? It remains commented out
// for now
// void OOJsonExporter::generate_object_instances() {
//   // For every object use in every function
//   for (const ObjectUseMap::value_type& oupair : object_uses) {
//     const ObjectUse& obj_use = oupair.second;
//     // Not all functions have object uses.   Just skip those.
//     if (obj_use.references.size() == 0) continue;

//     // Each ThisPtrUsage in references is a new object instance.
//     for (const ThisPtrUsageMap::value_type& rpair : obj_use.references) {
//       const ThisPtrUsage& tpu = rpair.second;
//       JsonObject use_tree;

//       // Report the function that the object instance is in.
//       use_tree.put("function", obj_use.fd->address_string());
//       // Now record all the methods invoked on that object.
//       JsonObject methods_tree;
//       // Cory notes that this code used call tpu.get_methods() instead.
//       for (const ThisCallMethod* tcm : tpu.get_method_evidence()) {
//         // Making the method address the key is a little stupid, but the property_tree API
//         // appears to limit our ability to make lists of values, which is what I really wanted.
//         methods_tree.put(tcm->address_string(), "");
//       }
//       use_tree.push_back(std::make_pair("methods", methods_tree));
//       // The object instances are keyed by the hash of the this-pointer, which should be a
//       // globally unique identifier for the object instance.
//       SVHash hash = tpu.this_ptr->get_expression()->hash();
//       std::string hash_str = boost::str(boost::format("%016x") % hash);
//       object_instances.push_back(std::make_pair(hash_str, use_tree));
//     }
//   }
// }

// Generate the appropriate JSON data structure from the set of objects and
// function calls.
void OOJsonExporter::generate_json(const std::vector<OOClassDescriptorPtr> &classes) {
  JsonObject
    json_vcalls = simple_builder ()->object (),
    json_structs = simple_builder ()->object ();

  // Reset state in case we generate more than once?
  usages_found = 0;
  methods_associated.clear();

  std::vector<OOClassDescriptorPtr> sorted_classes(classes);
  std::sort(sorted_classes.begin(), sorted_classes.end(),
            [](OOClassDescriptorPtr & a, OOClassDescriptorPtr & b) {
              return a->get_id() < b->get_id();
            });

  for (OOClassDescriptorPtr cls : sorted_classes) {

    // property trees for the current class
    JsonObject
      json_cls = simple_builder ()->object (),
      json_members = simple_builder ()->object (),
      json_methods = simple_builder ()->object (),
      json_vftables = simple_builder ()->object (),
      json_parents = simple_builder ()->object ();

    // the current class naming scheme is ClsN where N is an integer starting at 0
    std::string cls_name = cls->get_name();

    GDEBUG << "Using OOAnalyzer JSON Exporter to produce JSON for class: " << cls_name << LEND;

    json_cls->add("name", cls_name);
    json_cls->add("demangled_name", cls->get_demangled_name());

    // adding the class size to the JSON output
    json_cls->add("size", cls->get_size());

    for (auto& mpair : cls->get_members()) {

      JsonObject json_mbr = simple_builder ()->object ();
      bool add_json_mbr = true;
      OOElementPtr elm_member = mpair.second;


      bool member_on_base = !elm_member->get_exactly ();

      json_mbr->add ("size", elm_member->get_size());
      json_mbr->add ("base", member_on_base);
      auto mbr_offset = mpair.first;

      auto mbr_usages = simple_builder ()->array ();
      for (auto usage_insn : elm_member->get_evidence()) {
        auto ea = addr2str(usage_insn->get_address());
        mbr_usages->add (ea);
        usages_found++;
      }
      json_mbr->add ("usages", std::move (mbr_usages));

      // Do not add the vftptr for a base class.  Vftptr members do not have the get_exactly
      // property set right, so instead we see if the vftptr is for a base class by checking to
      // see if there is a parent at the same offset.  For some unknown reason, there are also
      // non-vftptr members for base classes too.
      auto parents = cls->get_parents ();
      if (parents.find (mbr_offset) != parents.end ()) {
        add_json_mbr = false;
        if (elm_member->get_type() != OOElementType::VFPTR) {
          // Ed still doesn't have an explanation for why this happens
          GDEBUG << "Offset " << mbr_offset << " co-exists with parent and has type " << (int) elm_member->get_type() << " base=" << member_on_base << "..." << LEND;
        }
      }

      // start with virtual tables/pointers
      if (elm_member->get_type() == OOElementType::VFPTR) {

        std::shared_ptr<OOVfptr> vftptr = std::dynamic_pointer_cast<OOVfptr> (elm_member);
        OOVirtualFunctionTablePtr vtab = vftptr->get_vftable();

        GDEBUG << "Adding Vftable ... " << vtab->get_address () << LEND;

        if (vtab->get_address() != INVALID) {
          JsonObject
            json_vft = simple_builder ()->object (),
            json_vft_entries = simple_builder ()->object ();

          // add the vftptr member
          std::stringstream vftptr_ss;
          vftptr_ss << "vftptr_0x" << std::hex << mbr_offset << std::dec;

          json_mbr->add ("name", vftptr_ss.str ());
          json_mbr->add ("type", "vftptr");


          GDEBUG << "Adding Vftable ... "<< LEND;

          json_vft->add("ea", addr2str(vtab->get_address()));
          json_vft->add("vftptr", intcat(mbr_offset, 16));

          GDEBUG << "Vftable size: " << vtab->get_size() << LEND;

          size_t voff = 0;
          for (auto vfpair : vtab->get_virtual_functions()) {
            size_t vf_offset = vfpair.first;
            OOMethodPtr vfunc = vfpair.second;

            GDEBUG << "Adding VF: " << addr_str(vfunc->get_address()) << LEND;

            JsonObject json_vf = simple_builder ()->object ();

            // add the virtual function
            json_vf->add ("ea", addr2str(vfunc->get_address()));
            json_vf->add ("offset", vf_offset);
            json_vf->add ("name", vfunc->get_name());
            json_vf->add ("demangled_name", demangle_method_name(vfunc->get_name()));
            json_vf->add ("import", vfunc->is_import ());

            json_vf->add ("type", type_of_method (vfunc));

            // Book keeping
            methods_associated.insert(vfunc->get_address());

            voff++;
            json_vft_entries->add (intcat(vf_offset, 10), std::move (json_vf)); // add the new vf
          }

          json_vft->add ("entries", std::move (json_vft_entries));
          json_vftables->add (addr2str (vtab->get_address ()), std::move (json_vft));

          GDEBUG << "Vftable added" << LEND;
        }
      }
      // add embedded objects
      else if (elm_member->get_type() == OOElementType::STRUC) {

        OOClassDescriptorPtr mbr_cls = std::dynamic_pointer_cast<OOClassDescriptor>(elm_member);

        std::stringstream struc_ss;
        struc_ss << mbr_cls->get_name() << "_0x" << std::hex << mbr_offset;
        json_mbr->add ("name", struc_ss.str());
        json_mbr->add ("type", "struc");
        json_mbr->add ("struc", mbr_cls->get_name());
        json_mbr->add ("parent", false);
      }

      // otherwise this is a standard class member
      else {

        std::stringstream mbr_ss;
        mbr_ss <<  elm_member->get_name() << "_0x" << std::hex << mbr_offset;
        json_mbr->add ("name", mbr_ss.str ());

        // type of standard members is blank
        json_mbr->add ("type", "");
      }

      // All members have an offset and a count of 1 (not array support)
      auto offset_str = intcat (mbr_offset, 16);
      json_mbr->add ("offset", offset_str);
      json_mbr->add ("struc", "");
      json_mbr->add ("parent", false);

      if (add_json_mbr)
        json_members->add (offset_str, std::move (json_mbr));
    }

    // Add the parents as additional members
    for (auto& ppair : cls->get_parents()) {

      JsonObject parent_mbr = simple_builder ()->object ();
      size_t parent_offset = ppair.first;
      OOClassDescriptorPtr parent = ppair.second;

      std::stringstream ss;
      ss << parent->get_name() << "_0x" << std::hex << parent_offset;
      auto offset_str = intcat (parent_offset, 16);
      parent_mbr->add ("name", ss.str());
      parent_mbr->add ("size", parent->get_size());
      parent_mbr->add ("type", "struc");
      parent_mbr->add ("struc", parent->get_name());
      parent_mbr->add ("parent", true);
      parent_mbr->add ("base", false); // not defined in the base; is a base

      auto members = cls->get_members();
      auto member_finder = members.find (parent_offset);
      if (member_finder != members.end ()) {
        OOElementPtr elm_member = (*member_finder).second;
        auto mbr_usages = simple_builder ()->array ();
        for (auto usage_insn : elm_member->get_evidence()) {
          auto ea = addr2str(usage_insn->get_address());
          mbr_usages->add (ea);
          usages_found++;
        }
        parent_mbr->add ("usages", std::move (mbr_usages));
      }
      else {
        parent_mbr->add ("usages", simple_builder ()->array ());
      }

      parent_mbr->add ("offset", intcat(parent_offset, 16));

      json_members->add (offset_str, std::move (parent_mbr));
    }

    GDEBUG << "All members added" << LEND;

    GDEBUG << "Adding Methods ... "<< LEND;

    unsigned int mtd_index = 0;
    for (OOMethodPtr method : cls->get_methods()) {

      JsonObject json_mtd = simple_builder ()->object ();

      auto ea = addr2str(method->get_address());
      GDEBUG << "Adding method " << ea << " to class " << addr_str(cls->get_id()) << LEND;
      json_mtd->add ("ea", ea);
      json_mtd->add ("name", method->get_name());
      json_mtd->add ("demangled_name", demangle_method_name(method->get_name()));

      json_mtd->add ("import", method->is_import ());

      methods_associated.insert(method->get_address());

      json_mtd->add ("type", type_of_method (method));

      mtd_index++;
      json_methods->add (ea, std::move (json_mtd));
    }

    GDEBUG << "Methods added" << LEND;

    json_cls->add ("members", std::move (json_members));
    json_cls->add ("methods", std::move (json_methods));
    json_cls->add ("vftables", std::move (json_vftables));

    num_structs ++;
    json_structs->add (cls_name, std::move (json_cls));

    GDEBUG << "Class complete" << LEND;

    // get the virtual function calls for this class
    for (auto vftable : cls->get_vftables ()) {

      for (auto& pair : vftable->get_virtual_call_targets ()) {
        // The object and vftable offsets were stored in VirtualFunctionCallInformation
        // structure in the OOAnalyzer.  We could change the Prolog output interface to
        // include these properties in the finalResolvedVirtualCall result, or we could merge
        // with the structure in OOAnalyzer, but we can't get it off the call descriptor
        // anymore because we're not storing "possible" virtual calls there any more.

        // GDEBUG << "Virtual function call " << addr_str(vcall->get_address())
        //        << " has object offset: " << vc_info->vtable_offset
        //        << " and virtual function table offset: " << vc_info->vfunc_offset
        //        << LEND;

        // We can however report the call target as we did previously.
        JsonObject vc_tree = simple_builder ()->object ();
        const CallDescriptor* vcall = pair.first;
        const AddrSet& targets = pair.second;

        if (targets.size() > 0) {
          auto calladdr = addr2str (vcall->get_address ());

          auto
            call_targets = simple_builder ()->array ();
          for (rose_addr_t t : targets) {
            vcalls_resolved++;
            call_targets->add (addr2str (t));

            GTRACE << "Virtual function target " << addr_str(t) << LEND;
          }
          vc_tree->add ("targets", std::move (call_targets));
          json_vcalls->add (calladdr, std::move (vc_tree));
        }
      }
    }
  }

  json->add("version", "2.1.0");
  json->add("filemd5", file_md5);
  json->add("filename", exe_filename);
  json->add("structures", std::move (json_structs));
  json->add("vcalls", std::move (json_vcalls));

  // JSG isn't really sure what to make of this instance stuff ... it isn't used by the IDA
  // plugin right now. That is not to say that is isn't meaningful
  // generate_object_instances();
}

} // namespace pharos
