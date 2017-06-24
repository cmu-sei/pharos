// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

// boost/property_tree/json_parser includes sys/stat.h which rose doesn't like. :-(
#include <rose.h>

#include <boost/property_tree/json_parser.hpp>

#include "jsonoo.hpp"

#include "misc.hpp"
#include "descriptors.hpp"
#include "oo.hpp"
#include "method.hpp"
#include "usage.hpp"
#include "class.hpp"
#include "vcall.hpp"

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
      stream << s << std::hex << i;
   }
   else if (base == 10)  {
      stream << s << std::dec << i;
   }
   return stream.str();
}

// create a new JSON exporter without a JSON output filename.
ObjdiggerJsonExporter::ObjdiggerJsonExporter() {
   vcalls_resolved = 0;
   usages_found = 0;
   json_filename = "";
}
// create a new JSON exporter with the JSON output filename.
ObjdiggerJsonExporter::ObjdiggerJsonExporter(ProgOptVarMap& vm) {
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

boost::property_tree::ptree ObjdiggerJsonExporter::get_json() {
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

// this function exports the JSON to a file.
void ObjdiggerJsonExporter::export_json(void) {

   // JSG updated this to fetch the JSON
   boost::property_tree::ptree pt = get_json();
   // write the JSON file out.
   write_json(json_filename, pt);

   // Cory says this message should be emitted for --report output also.
   OINFO << "Found " << structs.size() << " classes, "
   << methods_associated.size() << " methods, "
   << vcalls_resolved << " virtual calls, and "
   << usages_found << " usage instructions." << LEND;

   OINFO << "Successfully exported to JSON file '" << json_filename << "'." << LEND;
}

void ObjdiggerJsonExporter::generate_object_instances() {
  // For every object use in every function
  for (const ObjectUseMap::value_type& oupair : object_uses) {
    const ObjectUse& obj_use = oupair.second;
    // Not all functions have object uses.   Just skip those.
    if (obj_use.references.size() == 0) continue;

    // Each ThisPtrUsage in references is a new object instance.
    for (const ThisPtrUsageMap::value_type& rpair : obj_use.references) {
      const ThisPtrUsage& tpu = rpair.second;
      boost::property_tree::ptree use_tree;

      // Report the function that the object instance is in.
      use_tree.put("function", obj_use.fd->address_string());
      // Now record all the methods invoked on that object.
      boost::property_tree::ptree methods_tree;
      for (const ThisCallMethod* tcm : tpu.get_methods()) {
        // Making the method address the key is a little stupid, but the property_tree API
        // appears to limit our ability to make lists of values, which is what I really wanted.
        methods_tree.put(tcm->address_string(), "");
      }
      use_tree.push_back(std::make_pair("methods", methods_tree));
      // The object instances are keyed by the hash of the this-pointer, which should be a
      // globally unique identifier for the object instance.
      SVHash hash = tpu.this_ptr->get_expression()->hash();
      std::string hash_str = boost::str(boost::format("%016x") % hash);
      object_instances.push_back(std::make_pair(hash_str, use_tree));
    }
  }
}

// Generate the appropriate JSON data structure from the set of objects and
// function calls.
void ObjdiggerJsonExporter::generate_json(const ClassDescriptorMap &objects) {
   boost::property_tree::ptree member_usages, vcalls;

   // Reset state in case we generate more than once?
   usages_found = 0;
   methods_associated.clear();

   for (const ClassDescriptorMap::value_type& ucpair : objects) {
      ClassDescriptor obj = ucpair.second;

      // property trees for the current class
      boost::property_tree::ptree cls, members, methods, vftables, parents;

      // the current class naming scheme is ClsN where N is an integer starting at 0
      std::string cls_name = obj.get_name();

      ThisCallMethod *deldtor = obj.get_deleting_dtor();

      GTRACE << "Using JSON Exporter to produce JSON for class: " << cls_name << LEND;
      cls.put("Name", cls_name);

      // adding the class size to the JSON output
      cls.put("Size", intcat("",obj.get_size(),10));

      AddrSet vcall_set;
      for (const MemberMap::value_type &mpair : obj.data_members) {

         const Member& member = mpair.second;
         if (!(member.is_virtual())) continue;

         unsigned int vfptr = member.offset;

         VirtualFunctionTable *vtab = member.get_vftable();

         if (vtab->addr > 0 && vtab->best_size > 0) {
            boost::property_tree::ptree vft, vft_entries;

            GTRACE << "Adding Vftable ... "<< LEND;

            vft.put("ea",addr2str(vtab->addr));
            vft.put("vfptr",intcat("",vfptr,10));

            GTRACE << "Vftable size: " << vtab->best_size << LEND;

            for (unsigned int i=0; i < vtab->best_size; i++) {

               rose_addr_t vf_addr = vtab->read_entry(i);
               GTRACE << "Adding VF: " << addr_str(vf_addr) << LEND;

               boost::property_tree::ptree vf;

               // add the virtual function
               vf.put("ea",addr2str(vf_addr));
               vf.put("offset",intcat("",i,10));
               vf.put("name",intcat("Virt",(int)i,10));

               // is this a deleting destructor
               bool set_dtor = false;
               if (deldtor != NULL) {
                  if (deldtor->get_address() == vf_addr) {
                     vf.put("type","dtor");
                     set_dtor = true;
                  }
               }
               if (!set_dtor) {
                  vf.put("type","meth");
               }

               // remember that the virtual function was called
               vcall_set.insert(vf_addr);
               methods_associated.insert(vf_addr);

               vft_entries.push_back(std::make_pair("",vf)); // add the new vf
            }
            vft.put_child("entries",vft_entries);
            vftables.push_back(std::make_pair("",vft));
         }
      }

      GTRACE << "Vftable added" << LEND;

      GTRACE << "Adding Members ... "<< LEND;
      for (const MemberMap::value_type &m : obj.data_members) {

         boost::property_tree::ptree mbr;

         Member member = m.second;

         // Check for embedded object
         if (member.object != NULL) {
            ClassDescriptor *mobj = member.object;

            std::string parent_name = mobj->get_name();

            std::stringstream ss;
            ss << parent_name << "_" << std::hex << member.offset;
            mbr.push_back(make_ptree("name", ss.str()));

            mbr.push_back(make_ptree("type", "struc"));
            mbr.push_back(make_ptree("struc", parent_name));

            if (member.is_parent()) {
               mbr.push_back(make_ptree("parent","yes"));
            }
            else {
               mbr.push_back(make_ptree("parent","no"));
            }
         }
         else if (member.is_virtual()) {
            mbr.push_back(make_ptree("name", intcat("vfptr_",member.offset,16)));
            mbr.push_back(make_ptree("type", "dword"));
         }
         // otherwise this is a standard class member
         else {
            mbr.push_back(make_ptree("name", intcat("Mem_",member.offset,16)));
            size_t size = member.size;

            // simple determination of type based on size
            if (size == 1) {
               mbr.push_back(make_ptree("type", "byte"));
            }
            else if (size == 4) {
               mbr.push_back(make_ptree("type", "dword"));
            }
            else if (size == 2) {
               mbr.push_back(make_ptree("type", "word"));
            }
            else {
               // this is the default for now
               OINFO << "Cannot determine size of member " << cls_name << "::"
               << "Mem_" << m.first << LEND;

               mbr.push_back(make_ptree("type", "byte"));
            }
         }

         // All members have an offset
         mbr.push_back(make_ptree("offset", intcat("",member.offset,16)));

         // Array members are not yet supported
         mbr.push_back(make_ptree("count", "1"));

         members.push_back(std::make_pair("", mbr));

         for (const SgAsmx86Instruction* usage_insn : member.using_instructions) {
            boost::property_tree::ptree mu;

            mu.put("class",cls_name);
            mu.put("ea",addr2str(usage_insn->get_address()));
            member_usages.push_back(std::make_pair("",mu));
            usages_found++;
         }
      }

      GTRACE << "Members added" << LEND;

      GTRACE << "Adding Methods ... "<< LEND;

      unsigned int mtd_index = 0;
      for (const ThisCallMethod* tcm : obj.methods) {

         boost::property_tree::ptree mtd;

         if (vcall_set.find(tcm->get_address()) == vcall_set.end()) {

            // this is not a virtual function
            mtd.push_back(make_ptree("ea", addr2str(tcm->get_address())));
            methods_associated.insert(tcm->get_address());

            if (tcm->is_constructor()) {
               mtd.push_back(make_ptree("type", "ctor"));
               mtd.push_back(make_ptree("name", "Ctor"));
               GTRACE << "Adding constructor ... "<< LEND;
            }
            else if (tcm->is_destructor()) {
               mtd.push_back(make_ptree("type", "dtor"));
               mtd.push_back(make_ptree("name", "Dtor"));
               GTRACE << "Adding destructor ... "<< LEND;
            }
            else {
               // not a constructor
               mtd.push_back(make_ptree("type", "meth"));
               mtd.push_back(make_ptree("name", intcat("Meth",mtd_index,10)));
               GTRACE << "Adding method " << mtd_index <<  "... "<< LEND;


            }
            // the name of each method follows the familiar MethN where N ::= 0 ... UINT_MAX

            mtd_index++;
            methods.push_back(std::make_pair("", mtd));
         }
      }

      GTRACE << "Methods added" << LEND;

      // After a discussion with Cory, I don't think that inherited methods need to be in the
      // JSON output anymore. I could be wrong - jsg

      //      GTRACE << "Adding Inherited Methods ... "<< LEND;
      //
      //      unsigned int inmtd_index = 0;
      //      for (const InheritedMethodMap::value_type &m : obj.inherited_methods) {
      //
      //        boost::property_tree::ptree imtd;
      //        imtd.push_back(make_ptree("ea", addr2str(m.first->get_address())));
      //        imtd.push_back(make_ptree("type", "meth"));
      //        imtd.push_back(make_ptree("name", intcat("InheritedMeth",inmtd_index,10)));
      //        inmtd_index++;
      //
      //        methods.push_back(std::make_pair("", imtd));
      //      }
      //      GTRACE << "Inherited Methods added" << LEND;

      if (members.size() > 0) {
         cls.put_child("Members", members);
      }
      if (methods.size() > 0) {
         cls.put_child("Methods", methods);
      }
      if (vftables.size() > 0) {
         cls.put_child("Vftables", vftables);
      }

      // parents not yet supported.

      GTRACE << "Class complete" << LEND;

      structs.push_back(std::make_pair("",cls));
   }

   // the following code generates JSON for all found virtual function calls by filtering
   // call descriptors for virtual function calls only.

   CallDescMapPredicate p(CallVirtualFunction);

   // JSG changed this to use the globa_descriptor_set instead of a local ds to simplify
   // the interface to this function
   CallDescriptorMap::filtered_iterator it = global_descriptor_set->calls_filter_begin(p);
   CallDescriptorMap::filtered_iterator end = global_descriptor_set->calls_filter_end(p);

   while (it != end) {


      boost::property_tree::ptree vc_tree;

      CallDescriptor &vfcd = it->second;
      CallInformationPtr ci = vfcd.get_call_info();
      if (ci) {
         VirtualFunctionCallInformationPtr vc = boost::dynamic_pointer_cast<VirtualFunctionCallInformation>(ci);

         //call_ea = vfcd.get_address();

         GTRACE << "Virtual function call " << addr_str(vfcd.get_address())
         << " has object offset: " << vc->vtable_offset
         << " and virtual function table offset: " << vc->vfunc_offset
         << " the SV is " << *(vc->obj_ptr) << LEND;

         CallTargetSet targets = vfcd.get_targets();

         if (targets.size() > 0) {
            vc_tree.put("call",addr2str(vfcd.get_address()));

            boost::property_tree::ptree call_targets, tgt;
            for (rose_addr_t t : targets) {
               tgt.put("ea",addr2str(t));
               vcalls_resolved++;
               call_targets.push_back(std::make_pair("",tgt));

               GTRACE << "Virtual function target " << addr_str(t) << LEND;
            }
            vc_tree.put_child("targets",call_targets);
            vcalls.push_back(std::make_pair("",vc_tree));
         }
      }
      it++;
   }
   if (vcalls.size() > 0) {
      // add the vcalls to the list of usages for this class
      cls_usages.put_child("Vcalls",vcalls);
   }

   if (member_usages.size() > 0) {
      // add the member usages to the
      cls_usages.put_child("Members",member_usages);
   }

   // Generate the object instances.
   generate_object_instances();

   // JSG thinks this should be a separate call

   // write the JSON data structure to a file
   //export_json();




}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
