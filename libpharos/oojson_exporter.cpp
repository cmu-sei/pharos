// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

// boost/property_tree/json_parser includes sys/stat.h which rose doesn't like. :-(
#include <rose.h>

#include <boost/property_tree/json_parser.hpp>

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


namespace pharos {

// this is a simple utility function to convert a rose address to a hex string
std::string addr2str(rose_addr_t addr) {
   std::stringstream stream;
   stream << std::hex << addr;
   return stream.str();
}

// convert/append an integer to a string
std::string intcat(std::string const& s, int i, int base) {
   std::stringstream stream;
   if (base == 16) {
     stream << s << std::hex << std::noshowbase << i;
   }
   else if (base == 10)  {
      stream << s << std::dec << i;
   }
   return stream.str();
}

// create a new JSON exporter without a JSON output filename.
OOJsonExporter::OOJsonExporter() {
   vcalls_resolved = 0;
   usages_found = 0;
   json_filename = "";
}
// create a new JSON exporter with the JSON output filename.
OOJsonExporter::OOJsonExporter(ProgOptVarMap& vm) {
   vcalls_resolved = 0;
   usages_found = 0;

   if (vm.count("json")) {
      json_filename = vm["json"].as<std::string>();
   }
   else {
      std::string ext(".json");
      std::string input_path = vm["file"].as<std::string>();
      json_filename =  (std::string(boost::filesystem::basename(input_path.c_str())) + ext);
   }

   GINFO << "Exporting classes to JSON file: " << json_filename << LEND;
}

boost::property_tree::ptree OOJsonExporter::get_json() {
   boost::property_tree::ptree pt;
   boost::property_tree::ptree usages;

   if (cls_usages.size() > 0 ) {
      usages.push_back(std::make_pair("",cls_usages));
   }
   // add the structures
   if (structs.size() > 0) {
      pt.put_child("Structures", structs);
   }

   if (usages.size() > 0) {
      pt.put_child("Usages", usages);
   }

   if (object_instances.size() > 0) {
      pt.put_child("instances", object_instances);
   }

   return pt;
}

std::string
OOJsonExporter::demangle_class_name(std::string mangled_name) {

  try {
    auto dtype = demangle::visual_studio_demangle(mangled_name);
    if (dtype) {
      return dtype->get_class_name();
    }
  }
  catch (const demangle::Error &) {
    // It doesn't matter what the error was.  We might not have even
    // been a mangled name.
  }
   return "";
}

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

   // JSG updated this to fetch the JSON
   boost::property_tree::ptree pt = get_json();
   // write the JSON file out.
   write_json(json_filename, pt);

   // Cory says this message should be emitted for --report output also.
   GDEBUG << "Found " << structs.size() << " classes, "
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
//       boost::property_tree::ptree use_tree;

//       // Report the function that the object instance is in.
//       use_tree.put("function", obj_use.fd->address_string());
//       // Now record all the methods invoked on that object.
//       boost::property_tree::ptree methods_tree;
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
   boost::property_tree::ptree json_member_usages, json_vcalls;

   // Reset state in case we generate more than once?
   usages_found = 0;
   methods_associated.clear();

   for (OOClassDescriptorPtr cls : classes) {
      // property trees for the current class
     boost::property_tree::ptree json_cls, json_members, json_methods, json_vftables, json_parents;

      // the current class naming scheme is ClsN where N is an integer starting at 0
      std::string cls_name = cls->get_name();

      GDEBUG << "Using OOAnalyzer JSON Exporter to produce JSON for class: " << cls_name << LEND;

      json_cls.put("Name", cls_name);

      json_cls.put("DemangledName", demangle_class_name(cls_name));

      // adding the class size to the JSON output
      json_cls.put("Size", intcat("",cls->get_size(),10));

      for (auto& mpair : cls->get_members()) {

        boost::property_tree::ptree json_mbr;
        OOElementPtr elm_member = mpair.second;

        // start with virtual tables/pointers
        if (elm_member->get_type() == OOElementType::VFPTR) {

          GDEBUG << "Adding Vftable ... "<< LEND;

          std::shared_ptr<OOVfptr> vfptr = std::dynamic_pointer_cast<OOVfptr> (elm_member);
          OOVirtualFunctionTablePtr vtab = vfptr->get_vftable();

          if (vtab->get_address() != INVALID) {
            boost::property_tree::ptree json_vft, json_vft_entries;

            // add the vfptr member
            json_mbr.push_back(make_ptree("name", vfptr->get_name()));
            json_mbr.push_back(make_ptree("type", "vfptr"));

            GDEBUG << "Adding Vftable ... "<< LEND;

            json_vft.put("ea", addr2str(vtab->get_address()));
            json_vft.put("vfptr", intcat("", vfptr->get_offset(), 10));

            GDEBUG << "Vftable size: " << vtab->get_size() << LEND;

            size_t voff = 0;
            for (auto vfpair : vtab->get_virtual_functions()) {
              size_t vf_offset = vfpair.first;
              OOMethodPtr vfunc = vfpair.second;

              GDEBUG << "Adding VF: " << addr_str(vfunc->get_address()) << LEND;

              boost::property_tree::ptree json_vf;

              // add the virtual function
              json_vf.put("ea", addr2str(vfunc->get_address()));
              json_vf.put("offset", intcat("",vf_offset,10));
              json_vf.push_back(make_ptree("name", vfunc->get_name()));
              json_vf.put("demangled_name", demangle_method_name(vfunc->get_name()));

              if (vfunc->is_import()) {
                json_vf.push_back(make_ptree("import", "yes"));
              }
              else {
                json_vf.push_back(make_ptree("import", "no"));
              }

              // is this a deleting destructor, which is what you get with a virtual destructor
              if (vfunc->is_deleting_destructor() || vfunc->is_destructor()) {
                json_vf.put("type","dtor");
              }
              else {
                json_vf.put("type","meth");
              }
              methods_associated.insert(vfunc->get_address());
              json_vft_entries.push_back(std::make_pair("",json_vf)); // add the new vf
              voff++;
            }

            json_vft.put_child("entries",json_vft_entries);
            json_vftables.push_back(std::make_pair("", json_vft));

            GDEBUG << "Vftable added" << LEND;
          }
        }
        // add embedded objects
        else if (elm_member->get_type() == OOElementType::STRUC) {
          OOClassDescriptorPtr mbr_cls = std::dynamic_pointer_cast<OOClassDescriptor>(elm_member);

           std::stringstream ss;
           ss << mbr_cls->get_name() << "_" << std::hex << mbr_cls->get_offset();
           json_mbr.push_back(make_ptree("name", ss.str()));
           json_mbr.push_back(make_ptree("type", "struc"));
           json_mbr.push_back(make_ptree("struc", mbr_cls->get_name()));
           json_mbr.push_back(make_ptree("parent", "no"));
        }

        // otherwise this is a standard class member
        else {
          json_mbr.push_back(make_ptree("name", elm_member->get_name())); //intcat("Mem_", elm_member->get_offset(), 16)));

          if (elm_member->get_type() == OOElementType::BYTE) {
            json_mbr.push_back(make_ptree("type", "byte"));
          }
          else if (elm_member->get_type() == OOElementType::DWORD) {
            json_mbr.push_back(make_ptree("type", "dword"));
          }
          else if (elm_member->get_type() == OOElementType::WORD) {
            json_mbr.push_back(make_ptree("type", "word"));
          }
          else {
            // this is the default for now
            GDEBUG << "Cannot determine size of member " << cls->get_name() << "::"
                  << "Mem_" << elm_member->get_offset() << LEND;

            json_mbr.push_back(make_ptree("type", "byte"));
          }
        }
        // All members have an offset and a count of 1 (not array support)
        json_mbr.push_back(make_ptree("offset", intcat("", elm_member->get_offset(),16)));
        json_mbr.push_back(make_ptree("count", "1"));

        json_members.push_back(std::make_pair("", json_mbr));

        for (auto usage_insn : elm_member->get_evidence()) {
            boost::property_tree::ptree mu;

            mu.put("class", cls_name);
            mu.put("ea",addr2str(usage_insn->get_address()));
            json_member_usages.push_back(std::make_pair("",mu));
            usages_found++;
         }
      }

      // Add the parents as additional members
      for (auto& ppair : cls->get_parents()) {

        boost::property_tree::ptree parent_mbr;
        size_t parent_offset = ppair.first;
        OOClassDescriptorPtr parent = ppair.second;

        std::stringstream ss;
        ss << parent->get_name() << "_" << std::hex << std::noshowbase << parent_offset;
        parent_mbr.push_back(make_ptree("name", ss.str()));
        parent_mbr.push_back(make_ptree("type", "struc"));
        parent_mbr.push_back(make_ptree("struc", parent->get_name()));
        parent_mbr.push_back(make_ptree("parent","yes"));
        parent_mbr.push_back(make_ptree("offset", intcat("",parent_offset, 16)));
        parent_mbr.push_back(make_ptree("count", "1"));

        json_members.push_back(std::make_pair("", parent_mbr));
      }

      GDEBUG << "All members added" << LEND;

      GDEBUG << "Adding Methods ... "<< LEND;

      unsigned int mtd_index = 0;
      for (OOMethodPtr method : cls->get_methods()) {

         boost::property_tree::ptree json_mtd;

         if (!method->is_virtual()) {

            // this is not a virtual function
            json_mtd.push_back(make_ptree("ea", addr2str(method->get_address())));
            json_mtd.push_back(make_ptree("name", method->get_name()));
            json_mtd.push_back(make_ptree("demangled_name", demangle_method_name(method->get_name())));

            if (method->is_import()) {
              json_mtd.push_back(make_ptree("import", "yes"));
            }
            else {
              json_mtd.push_back(make_ptree("import", "no"));
            }

            methods_associated.insert(method->get_address());

            if (method->is_constructor()) {
              json_mtd.push_back(make_ptree("type", "ctor"));

              GDEBUG << "Adding constructor ... "<< LEND;
            }
            else if (method->is_destructor()) {
              json_mtd.push_back(make_ptree("type", "dtor"));
              // json_mtd.push_back(make_ptree("name", "Dtor"));
              GDEBUG << "Adding destructor ... "<< LEND;
            }
            else {
               // not a constructor
               json_mtd.push_back(make_ptree("type", "meth"));
               GDEBUG << "Adding method " << mtd_index <<  "... "<< LEND;
            }
            // the name of each method follows the familiar MethN where N ::= 0 ... UINT_MAX

            mtd_index++;
            json_methods.push_back(std::make_pair("", json_mtd));
         }
      }

      GDEBUG << "Methods added" << LEND;

      if (json_members.size() > 0) {
         json_cls.put_child("Members", json_members);
      }
      if (json_methods.size() > 0) {
         json_cls.put_child("Methods", json_methods);
      }
      if (json_vftables.size() > 0) {
         json_cls.put_child("Vftables", json_vftables);
      }

      structs.push_back(std::make_pair("", json_cls));

      GDEBUG << "Class complete" << LEND;

      // get the virtual function calls for this class
      for (auto vftable : cls->get_vftables()) {
        for (CallDescriptor* vcall : vftable->get_virtual_calls()) {

          boost::property_tree::ptree vc_tree;

          CallInformationPtr ci = vcall->get_call_info();
          if (ci) {
            VirtualFunctionCallInformationPtr vc_info = boost::dynamic_pointer_cast<VirtualFunctionCallInformation>(ci);

            GDEBUG << "Virtual function call " << addr_str(vcall->get_address())
                  << " has object offset: " << vc_info->vtable_offset
                  << " and virtual function table offset: " << vc_info->vfunc_offset
                  << LEND;

            CallTargetSet targets = vcall->get_targets();
            if (targets.size() > 0) {
              vc_tree.put("call", addr2str(vcall->get_address()));

              boost::property_tree::ptree call_targets, tgt;
              for (rose_addr_t t : targets) {
                tgt.put("ea",addr2str(t));
                vcalls_resolved++;
                call_targets.push_back(std::make_pair("",tgt));

                GTRACE << "Virtual function target " << addr_str(t) << LEND;
              }
              vc_tree.put_child("targets",call_targets);
              json_vcalls.push_back(std::make_pair("",vc_tree));
            }
          }
        }
      }
   }


   if (json_vcalls.size() > 0) {
      // add the vcalls to the list of usages for this class
      cls_usages.put_child("Vcalls",json_vcalls);
   }

   if (json_member_usages.size() > 0) {
      // add the member usages to the
      cls_usages.put_child("Members",json_member_usages);
   }

   // JSG isn't really sure what to make of this instance stuff ... it isn't used by the IDA
   // plugin right now. That is not to say that is isn't meaningful
   // generate_object_instances();

   // write the JSON data structure to a file
   //export_json();
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
