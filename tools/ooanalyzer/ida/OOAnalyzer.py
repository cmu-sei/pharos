'''Created on Jan 8, 2014

@version: 2.0
@organization: CERT Malicious Code Team
@author: jsg

This is the IDA plugin to apply OOAnalyzer output into IDA
Pro. Version 2.0 is the first version that works with OOAnalyzer.

'''
from idc import GetStrucIdByName
from idaapi import *
from abc import ABCMeta, abstractmethod
import sys
import pickle

VERSION = 2.0

import json
import copy
import re
import traceback

try:
   import idaapi
   import idc
   import idaapi
   import idautils
   from idaapi import PluginForm
except ImportError:
   print "Could not import IDA Python modules"
   sys.exit(-1)

# IDA 6.9 uses Python a bit differently than <6.9.

ida_version = float(idc.Eval("\" \" + __IDA_VERSION__").strip())

if ida_version < 6.9:
   from PySide.QtCore import *
   from PySide.QtGui import *
else:
   from PyQt5.QtCore import *
   from PyQt5.QtGui import *
   from PyQt5.QtWidgets import *

def ida_hexify(value):
   '''
   convert hex string (0xNNNN...) to IDA-like hex value (NNNh)
   '''
   val = value

   # convert integers to strings and make them "IDA-like"
   if not isinstance(value, str):
      val = hex(value)

   if val.find("0x") != -1:
      ret_val = val[val.find("0x") + 2:]
      if ret_val.find('L') != -1:  # in newer versions of IDA an 'L' is appended to immediates
         ret_val = ret_val[:-1]
      return ret_val
   else:
      return val

def sanitize_name(name):
   if name != None:
      # strip off non-alphanumeric characters because IDA kind of sucks
      return re.sub('[^0-9a-zA-Z]+', '_', name)
   return None

def generate_vftable_name(classes, vft, cls, off):
   '''
   Generate vftable names of the form X_Y_... where Y is the parent of X. This captures the
   lineage of overwritten vfptrs
   '''

   lineage = [cls]
   c = cls
   more_parents = False

   while True:

      # add the current parent
      if off in c.parents:
         lineage.append(c.parents[off])

         # go to the next parent at this offset. This will capture over-written vfptrs
         for i in classes:
            if c.parents[off].name == i.name:
               c = i
               more_parents = True
               break

      if more_parents == False:
         break
      else:
         # there are more parents
         more_parents = False

   vft_parts = []
   for x in lineage:
      if x.ida_name != "":
         vft_parts.append(x.ida_name)
      else:
         vft_parts.append(x.name)

   vft_name = "_".join(str(y) for y in vft_parts)

   print "Vritual function table name %s_vftable" % vft_name
   return  "%s_vftable" % vft_name

class PyOOAnalyzer(object):
   '''
   Responsible for parsing and applying JSON class specification to an IDB.
   '''

   def __init__(self):
      '''
      Constructor for the PyOOAnalyzer Plugin
      '''
      self.__json_filename = None
      self.__json_data = None
      self.__classes = []
      self.__vfcalls = []

      self.__member_usages_found = False
      self.__vcall_usages_found = False
      self.__classes_found = False


      self.__is_parsed = False;

      # this is the results of parsing
      self.__parse_results = {}

      self.__applied_classes = {}

      return

   def set_classes(self,other_classes):
      self.__classes = copy.deepcopy(other_classes)

   def __str__(self):
      '''
      Convert a class to a string
      '''
      s = ""
      for c in self.__classes:
         s += "%s\n" % c
      return s

   def set_json_file(self,jsn_file):
      '''
      Set the JSON file
      '''

      self.__json_filename = jsn_file
      result = True
      if jsn_file != None:

         try:
            self.__json_data = open(jsn_file).read()
         except:
            result = False

      # the file was opened, it is eligible for parsing
      if result == True:
         self.__is_parsed = False

      return result

   def is_parsed(self):
      '''
      Return flag indicate if the JSON file is parsed
      '''
      return self.__is_parsed

   def get_classes(self):
      return self.__classes

   def get_json_filename(self):
      return self.__json_filename

   def get_json_data(self):
      return self.__json_data

   def set_json_data(self, data):
      self.__json_data = data

   def get_parse_results(self):
      '''
      Return results of parsing
      '''
      if len(self.__parse_results) == 0:
         return None

      return self.__parse_results

   def parse(self):
      '''
      Parse the JSON object into a Python dictionary. Parse methods are responsible for properly
      setting the type of data. addresses are always base 16 and offsets are always in base 10
      '''
      if self.__json_data == None:
         return [False,"File not specified"]

      data = None
      try:
         data = json.loads(self.__json_data, object_hook=self.decode_json_hook)
      except Exception, e:
         print "JSON parsing error: %s" % e
         return [False,"JSON parsing error: %s" % e]

      if "Structures" in data:

         print "Parsing JSON structures ..."
         self.__parse_structs(data["Structures"])
         print "Completed Parsing JSON structures file: %s classes found" % len(self.__classes)

      if "Usages" in data:
         self.__parse_usages(data["Usages"])
         print "Completed Parsing JSON class usages"

      self.__is_parsed = True
      return [True,"OK"]

   def apply(self):
      '''
      Apply classes, then usages
      '''

      print "Applying class structures"

      self.__apply_structs()

      print "Applying class virtual function calls"

      self.__apply_vfcalls()

      return True


   def apply_struct(self, cls_to_apply):
      '''
      Apply classes, then usages
      '''
      result = False
      for c in self.__classes:
         if c.ida_name == cls_to_apply.ida_name:
            if not c.applied:

               print "Applying class %s" % c.ida_name

               c.id = self.__apply_class(c)

               c.applied = True
               result = True
               break
            else:
               print "Class %s already applied" % c.name
               result = False
               break

      return result

   def __parse_structs(self, structs):
      '''
      Parse the structures defined in the JSON file. The order here matters:

         * vftables must be parsed before methods because vftables contain additional methods
      '''
      self.__parse_results["NumClasses"] = len(structs)

      for s in structs:
          # use the ID of the current struct, if it exists
         c = PyClassStructure(s)

         #  The class must be created for members to work
         self.__classes.append(c)

         print "Found class %s" % c.ida_name

      for s in structs:
         # Now fill out the structures
         for c in self.__classes:
            if c.name == s['Name']:

               cid = idc.GetStrucIdByName(c.ida_name)
               if cid != idc.BADADDR: c.id = cid

               if 'Vftables' in s: self.__parse_vftables(c, s['Vftables'])
               if 'Members' in s: self.__parse_members(c, s['Members'])
               if 'Methods' in s: self.__parse_methods(c, s['Methods'])

      # this point each class structure is loaded
      self.__classes_found = True

      return

   def __parse_members(self, cls, members):
      '''
      Add each member specified
      '''

      print "Parsing %d members for class %s ..." % (len(members), cls.ida_name)

      for m in members:

         offset = int(m['offset'], 16)
         if offset > 0x7FFFFFFF: offset -= 0x100000000

         if offset < 0:
            print "WARNING: Negative member offset (%d) found - discarding" % offset
            continue

         # valid member - create it
         mem = PyClassMember()
         mem.cls = cls
         mem.member_type = m['type']
         mem.count = int(m['count'])

         if mem.member_type == FF_STRU:

            class_member_name = m['struc'] # This could be mangled
            cls_mem = None
            for c in self.__classes:
               if class_member_name == c.name:
                  cls_mem = c
                  break

            if cls_mem != None:

               mem.class_member = cls_mem

               if m['parent'] == 'yes':
                  # this is a parent
                  mem.is_parent = True
                  cls.add_parent(cls_mem, offset)
                  print "   - Found class parent, name: '%s', type: %s" % (mem.member_name, mem.class_member.ida_name)
               else:
                  print "   - Found class member, name: '%s', type: %s" % (mem.member_name, mem.class_member.ida_name)
                  mem.member_name = "mbr_%x" %  offset

         else:
            mem.class_member = None
            if mem.is_vfptr:
               mem.member_name = "vfptr_%x" % offset
            else:
               mem.member_name = "mbr_%x" % offset
            print "   - Found member '%s' @ offset 0x%x" % (mem.member_name, offset)


         # offset of this member
         mem.offset = offset

         # add the new member
         cls.add_member(mem, offset)

         if cls.id != idc.BADADDR:
             mid = idc.GetMemberId(cls.id, offset)
             if mid != -1:
                mem.id = mid

      print "Members parsed"

      return

   def __parse_methods(self, cls, methods):
      '''
      Parse the methods defined in the JSON file
      '''

      print "Parsing %d methods for class %s ..." % (len(methods), cls.ida_name)

      for m in methods:

         meth = PyClassMethod()

         meth.cls = cls
         meth.is_virtual = False  # no traditional methods are virtual

         meth.is_ctor = False
         meth.is_dtor = False
         if m['type'] == "ctor": meth.is_ctor = True
         elif m['type'] == "dtor": meth.is_dtor = True

         #  this method is imported
         meth.is_import = False
         if m['import'] == "yes":  meth.is_import = True

         meth.start_ea = int(m['ea'], 16)

         meth.method_name = m['name']

         meth.userdef_name = False

         has_name = idc.hasUserName(idc.GetFlags(meth.start_ea))
         if has_name and not meth.is_import:
            meth.method_name = idc.GetFunctionName(meth.start_ea)
            meth.userdef_name = True

         print "   - Method %s parsed" % meth.method_name

         cls.add_method(meth)

      print "All methods parsed"

      return

   def __parse_vftables(self, cls, vftables):
      '''
      Parse the vftables defined in the JSON file
      '''

      print "Parsing %s vftables for class %s ..." % (len(vftables), cls.ida_name)

      for v in vftables:

         vfptr_off = int(v['vfptr'])
         if vfptr_off < 0:
            print "   WARNING: Negative virtual function pointer offset found (%d) - discarding" % vfptr_off
            continue

         vft = PyClassVftable()
         vft.cls = cls
         vft.start_ea = int(v['ea'], 16)

         for entry in v['entries']:
            meth = PyClassMethod()

            meth.cls = cls
            meth.start_ea = int(entry['ea'], 16)
            # meth.method_name = "%s_%x" % (entry['name'], meth.start_ea)
            meth.method_name = entry['name']

            meth.is_virtual = True

            meth.is_ctor = False
            meth.is_dtor = False
            if entry['type'] == "ctor":
               meth.is_ctor = True
            elif entry['type'] == "dtor":
               meth.is_dtor = True

            meth.userdef_name = False
            has_name = idc.hasUserName(idc.GetFlags(meth.start_ea))
            ida_method_name = idc.GetFunctionName(meth.start_ea)
            if has_name:
               meth.method_name = ida_method_name
               meth.userdef_name = True

            vft.add_virtual_function(meth, int(entry['offset']))
            # enqueue the vf for later processing when methods are applied
            cls.add_method(meth)


         print "   - Adding vtable %x at offset %d" % (vft.start_ea,vfptr_off)
         print ""

         vft_name = generate_vftable_name(self.__classes, vft, cls, vfptr_off)
         vftid = idc.GetStrucIdByName(vft_name)
         if vftid != idc.BADADDR:
            vft.id = vftid
         cls.add_vftable(vft, vfptr_off)

      print "Vftables parsed"

      return

   def __parse_usages(self, usages):
      '''
      Parse different class usages.
      '''
      for u in usages:
         if 'Vcalls' in u:
            self.__parse_vf_calls(u['Vcalls'])

         if 'Members' in u:
            self.__parse_member_usages(u['Members'])


      return

   def __parse_member_usages(self,mem_usages):
      '''
      Parse member usages and enqueue them for processing.
      '''
      self.__parse_results["NumUsages"] = len(mem_usages)
      for m in mem_usages:
         mu = PyMemberUsage()
         for c in self.__classes:
            if c.name == m['class']:
               mu.ida_name = c.ida_name
               mu.ea = int(m['ea'], 16)
               mu.cid = BADADDR
               c.add_usage(mu)
      return


   def __parse_vf_calls(self, vcalls):
      '''
      Parse virtual function calls
      '''
      print "Parsing %s virtual function calls ..." % (len(vcalls))
      self.__parse_results["NumVcalls"] = len(vcalls)

      for v in vcalls:
         vc = PyVirtualFunctionCallUsage()
         vc.call_ea = int(v['call'], 16)

         for t in v['targets']:
            vc.add_target_ea(int(t['ea'], 16))

         print "Parsed virtual function call: %s" % vc

         self.__vfcalls.append(vc)

      return

   # The following methods concern applying the parsed JSON file to an IDB

   def __apply_class(self, cls):
      '''
      Apply the class
      '''

      print "================================================"
      print "Applying class '%s'" % cls.ida_name

      if cls.ida_name in self.__applied_classes:
         print "class '%s' is already applied" % cls.ida_name
         return cls.id


      cls.id = idc.AddStrucEx(0, cls.ida_name, 0)
      self.__applied_classes[cls.ida_name] = cls # Save the ID of this struct

      if cls.demangled_name != "":
         idc.SetStrucComment(cls.id, "Original mangled name: %s" % cls.name, 1)

      if len(cls.members) > 0:
         print "Applying %d members ..." % len(cls.members)
         for moff, mem in cls.members.iteritems():
            self.__apply_member(cls.id, mem, moff)
         print "Members applied"
      else:
         print "Class with no members not allowed by IDA Pro, creating dummy member"

         idc.AddStrucMember(cls.id, "EMPTY", 0, FF_BYTE | FF_DATA, 0xFFFFFFFF, 1)
         cls.members[0] = PyClassMember(cls=cls, mem_type=FF_BYTE|FF_DATA, mem_name="EMPTY")

      if len(cls.parents) > 0:
         print "Applying %d parents ..." % len(cls.parents)
         for poff, par in cls.parents.iteritems():
            self.__apply_parent(cls.id, par, poff)
         print "Parents applied"

      if len(cls.vftables) > 0:
         print "Applying %d vftables ..." % len(cls.vftables)
         for voff, vft in cls.vftables.iteritems():
            self.__apply_vftable(cls.id, cls, vft, voff)
         print "Vftables applied"

      if len(cls.methods) > 0:
         print "Applying %d methods ..." % len(cls.methods)
         for n in cls.methods:
            self.__apply_method(n)
         print "Methods applied"

      if len(cls.usages) > 0:
         print "Applying %d usages ..." % len(cls.usages)
         for u in cls.usages:
            u.cid = cls.id
            u.apply()
         print "Methods applied"


      print "Applied class '%s'" % cls.ida_name
      print "================================================\n"

      return cls.id

   def __apply_member(self, cid, mem, off):
      '''
      Apply members of this class to the IDB
      '''

      if mem.is_parent:
         return

      nbytes = BADADDR
      if mem.member_type == FF_STRU:
         if mem.cls.ida_name not in self.__applied_classes:
            mem.cls.id = self.__apply_class(mem.cls)
            print "Applying class member: %s" % str(mem.cls.ida_name)

         nbytes = idc.GetStrucSize(mem.cls.id) * mem.count
         mem_type = FF_STRU | FF_DATA

         idc.AddStrucMember(cid, mem.member_name, off, mem_type, mem.cls.id, nbytes)
      else:
         # non-struct member
         nbytes = mem.size * mem.count
         idc.AddStrucMember(cid, mem.member_name, off, mem.member_type, 0xFFFFFFFF, nbytes)

      # save the member ID
      mem.id = idc.GetMemberId(cid, off)

      return

   def __apply_method(self, method):
      '''
      Apply methods of this class to the IDB
      '''

      # Does this function already have a user-defined name? If so, preserve it

      cmt = cmt = "%s::%s" % (method.cls.ida_name, method.method_name)

      if method.is_virtual == True:
         cmt = "virtual %s" % cmt

      if method.is_ctor == True:
         cmt += " (constructor)"

      if method.is_dtor == True:
         cmt += " (destructor)"

      print "Applying class method %s @ %x" % (method.method_name, method.start_ea)

      if not method.userdef_name and not method.is_import:
         idc.MakeName(method.start_ea, method.method_name)

      idc.SetFunctionCmt(method.start_ea, cmt, 1)

      return

   def __apply_vftable(self, cid, cls, vft, off):
      '''
      Apply the parsed vftable(s) for this class
      '''

      vft_name = generate_vftable_name(self.__classes, vft, cls, off)

      print "Applying vftable: %s" % (vft_name)

      idc.MakeName(vft.start_ea, "%s_%x" % (vft_name, vft.start_ea))

      vftid = idc.AddStrucEx(0, vft_name, 0)
      vft.id = vftid

      # this will likely occur if the structure name is already present in the IDB.
      if vftid == BADADDR:
         print "Vtable already exists!"
         n = 1  # simply create an indexed struct
         while vftid == BADADDR:
            vft_name = "%s_%d" % (vft_name, n)

            vftid = idc.AddStrucEx(0, vft_name, 0)
            n += 1

      idc.SetStrucComment(vftid, vft.cls.ida_name + " virtual function table", 1)

      i = 0
      for vf_off, vf in vft.virtual_functions.iteritems():

         # attempt to preserve vftable inheritance
         print "Found virtual function: %s" % vf

         idc.MakeDword(vft.start_ea + vf_off)

         # check to see if the name is repeated in the vftable - this happens in the case of
         # pure virtual functions

         res = idc.AddStrucMember(vftid, str(vf.method_name), (4 * vf_off), FF_DWRD, 0xffffffff, 4)
         if res == idc.STRUC_ERROR_MEMBER_NAME:
            idc.AddStrucMember(vftid, "%s_%d" % (str(vf.method_name),i), (4 * vf_off), FF_DWRD, 0xffffffff, 4)

         ea = idc.Dword(vft.start_ea + (4 * vf_off))
         idc.SetMemberComment(vftid, (4 * vf_off), ida_hexify(ea), 1)

         i += 1  # next vftable entry


      # add the vfptr :or rename existing member to vfptr
      vptr_name = "vfptr_%s" % ida_hexify(off)

      if idc.GetMemberName(cid,off) == None:
         # there is no member at this offset
         idc.AddStrucMember(cid, vptr_name, off, FF_DWRD, 0xffffffff, 4)
         idc.SetMemberComment(cid, off, vft_name, 1)
      else:
         # There is a member at this offset

         if (idc.GetMemberFlag(cid,off) & DT_TYPE) != FF_STRU:
            # there is already a member defined at this offset, change it to a vfptr
            idc.SetMemberName(cid, off, vptr_name)
            idc.SetMemberType(cid, off, FF_DWRD, 0xFFFFFFFF, 4)

      # set the vtable name on the global class list
      for c in self.__classes:
         if c.ida_name == cls.ida_name:
            c.vftables[off].vtable_name = vft_name
            break

      return

   def __apply_parent(self, cid, parent, off):
      '''
      Apply the parent classes to the IDB. This may (should) overwrite a virtual function pointer
      '''
      print "Applying parent: %s" % parent.ida_name

      if parent.id == BADADDR:
         parent.id = self.__apply_class(parent)

         # add the variable for the parent
      nbytes = idc.GetStrucSize(parent.id)
      name = "parent_%s" % ida_hexify(off)

      # apply the parent, deleting any empty members :or vfptrs
      result = idc.AddStrucMember(cid, name, off, FF_STRU | FF_DATA, parent.id, nbytes)
      if result == STRUC_ERROR_MEMBER_OFFSET:
         idc.DelStrucMember(cid, off)
         idc.AddStrucMember(cid, name, off, FF_STRU | FF_DATA, parent.id, nbytes)

      return


   def decode_json_hook(self, data):
      '''
      This function decodes a loaded JSON object in a way that can be used by
      IDA Python. This means no unicode.
      '''
      rv = {}
      for key, value in data.iteritems():
         if isinstance(key, unicode):
            key = key.encode('ascii')
         if isinstance(value, unicode):
            value = value.encode('ascii')
         rv[key] = value
      return rv


   def get_applied_classes(self):
      '''
      Return a list of classes that have been applied
      '''
      return [cls for name, cls in self.__applied_classes.iteritems()]

   def apply_all_structs(self):
      '''
      Apply the parsed classes. The basic algorithm is to iteratively apply
      structs for classes without parents. Eventually all structs will have
      their parents applied
      '''

      print "OOAnalyzer has %d classes to apply:" % len(self.__classes)

      for c in self.__classes:
         if c.demangled_name != "":
            print "   * %s (Demangled name: %s)" % (c.name, c.demangled_name)
         else:
            print "   * %s" % (c.name)

      worklist_count = len(self.__classes)
      # while all classes are not complete

      while worklist_count > 0:

         # idaapi.show_wait_box("Applying class %s ..." % c.demangled_name)

         for c in self.__classes:

            # Has this class been applied
            if c.applied == True: continue

            do_apply = True
            missing_member = ""

            # if this class has members, check for sub classes
            if c.members:
               for o, m in c.members.iteritems():

                  if m == None: continue
                  if m.member_type == FF_STRU:

                     if m.class_member == None: continue

                     if m.class_member.ida_name not in self.__applied_classes:
                        # don't apply members with structs that are not yet applied
                        do_apply = False
                        missing_member = m.class_member.ida_name
                        break

            if do_apply:
               print "Applying class '%s'" % c.ida_name
               c.id = self.__apply_class(c)
               c.applied = True
               worklist_count -= 1

            else:
               print "Not applying class '%s' because cannot find member class '%s'" % (c.ida_name, missing_member)

         # idaapi.hide_wait_box()

      return

   def apply_vfcalls(self):
      '''
      Apply the different usages for each class
      '''

      for u in self.__vfcalls:
         # apply the virtual function call
         u.apply()

      return

# =============================================================================
# End class

class PyClassUsage(object):

   OP_REG            = o_reg     # 1
   OP_MEM_REF        = o_mem     # 2
   OP_REG_INDEX      = o_phrase  # 3
   OP_REG_INDEX_DISP = o_displ   # 4
   OP_IMMEDIATE      = o_imm     # 5

   '''
   This interface represents the usages for classes.
   '''
   def apply(self, usage):
      raise NotImplementedError("Must extend")

# =============================================================================
# End class


class PyVirtualFunctionCallUsage(PyClassUsage):
   '''
   This class represents a virtual function call
   '''

   def __init__(self):
      '''
      Constructor
      '''
      self.__call_ea = None
      self.__targets = []

      return

   def __str__(self):

      tstr = ""
      for t in self.targets:
         tstr += ("%x " % t)

      return "Call %x -> Target(s): %s" % (self.__call_ea, tstr)

   def get_call_ea(self):
      return self.__call_ea

   def get_target_ea(self):
      return self.__targets

   def set_call_ea(self, value):
      self.__call_ea = value

   def add_target_ea(self, t):
      self.__targets.append(t)

   def apply(self):
      '''
      Apply virtual function call by making an xref to the right place in the IDB
      '''
      print "================================================"
      for t in self.__targets:
         print "Applying virtual function call %x -> %x" % (self.__call_ea, t)

         idc.AddCodeXref(self.__call_ea, t, XREF_USER | fl_F)

         cmt = idc.GetCommentEx(self.__call_ea, 0)
         if cmt != None:
            cmt = cmt + ", %s" % ida_hexify(t)
            print "Multiple virtual function calls detected at %x (%s)" % (self.__call_ea, cmt)

         else:
            cmt = "%s" % ida_hexify(t)

         idc.MakeComm(self.__call_ea, cmt)

      print "================================================"

      return True

   # properties of virtual function calls

   call_ea = property(get_call_ea, set_call_ea, None, None)
   targets = property(get_target_ea, None, None, None)


# =============================================================================
# End class

class PyMemberUsage(PyClassUsage):

   def __init__(self, name=None):
      self.__ea = None
      self.__ida_name = name
      self.__cid = BADADDR

      return

   def apply(self):
      '''
      Apply a usage
      '''

      if self.__ida_name is None:
         return False

      if self.__cid == BADADDR:
         print "*** Cannot apply because bad ID"
         return False

      print "================================================"
      print "Applying class %s to %x" % (self.__ida_name, self.__ea)
      print "================================================"

      # there must be two and only two operands, assume 1 and check for 2
      n = 0
      if idc.GetOpType(self.__ea, 1) in [self.OP_REG_INDEX,self.OP_REG_INDEX_DISP]:
         n = 1

      idc.OpStroffEx(self.__ea, n, self.__cid, 0)

      return True

   def get_cid(self):
      return self.__cid

   def get_ida_name(self):
      return self.__ida_name

   def get_ea(self):
      return self.__ea

   def set_cid(self, value):
      self.__cid = value

   def set_ea(self, value):
      self.__ea = value

   def set_ida_name(self, value):
      self.__ida_name = value

   ida_name = property(get_ida_name, set_ida_name, None, None)
   cid = property(get_cid, set_cid, None, None)
   ea = property(get_ea, set_ea, None, None)

# =============================================================================
# End class

class PyVtableUsage(PyClassUsage):

   def __init__(self, cls):
      self.__call_ea = None
      self.__cls = cls
      self.__vf_offset = None

      return

   def get_call_ea(self):
      return self.__call_ea

   def get_cls(self):
      return self.__cls

   def get_vf_offset(self):
      return self.__vf_offset

   def set_call_ea(self, value):
      self.__call_ea = value

   def set_cls(self, value):
      self.__cls = value

   def set_vf_offset(self, value):
      self.__vf_offset = value

   def del_call_ea(self):
      del self.__call_ea

   def del_cls(self):
      del self.__cls

   def del_vf_offset(self):
      del self.__vf_offset

   def apply(self):
      pass

   call_ea = property(get_call_ea, set_call_ea, del_call_ea, "call_ea's docstring")
   cls = property(get_cls, set_cls, del_cls, "class_name's docstring")
   vf_offset = property(get_vf_offset, set_vf_offset, del_vf_offset, "vf_offset's docstring")

# =============================================================================
# End class


# =============================================================================
# End class

class PyClassMethod(object):
   '''
   This class represents a class method
   '''
   def __init__(self, meth_name=None, cls=None, ea=None, ctor=False, dtor=False, virt=False, imp=False, udn=False):

         # Set the formatter for this object
         self.__start_ea = None
         if ea != None:
            self.__start_ea = int(ea)

         self.__method_name = None
         if meth_name != None:
               self.__method_name = meth_name

         self.__cls = None
         if cls != None:
            self.__cls = cls

         self.__userdef_name = udn
         self.__is_ctor = ctor
         self.__is_dtor = dtor
         self.__is_virtual = virt
         self.__is_import = imp

         return

   def __str__(self):

      return "%s @ %x" % (self.__method_name, self.__start_ea)

   def get_cls(self):
      return self.__cls

   def get_is_virtual(self):
      return self.__is_virtual

   def get_is_import(self):
      return self.__is_import

   def get_is_ctor(self):
      return self.__is_ctor

   def get_is_dtor(self):
      return self.__is_dtor

   def get_method_name(self):
      return self.__method_name

   def get_start_ea(self):
      return self.__start_ea

   def get_userdef_name(self):
      return self.__userdef_name

   def set_is_virtual(self, value):
      self.__is_virtual = value

   def set_is_import(self, value):
      self.__is_import = value

   def set_cls(self, value):
      self.__cls = value

   def set_is_ctor(self, value):
      self.__is_ctor = value

   def set_is_dtor(self, value):
      self.__is_dtor = value

   def set_method_name(self, value):
      self.__method_name = value

   def set_start_ea(self, value):
      self.__start_ea = value

   def set_userdef_name(self, value):
      self.__userdef_name = value

   # properties for class methods
   userdef_name = property(get_userdef_name, set_userdef_name, None, None)
   method_name = property(get_method_name, set_method_name, None, None)
   is_virtual = property(get_is_virtual, set_is_virtual, None, None)
   is_import = property(get_is_import, set_is_import, None, None)
   is_ctor = property(get_is_ctor, set_is_ctor, None, None)
   is_dtor = property(get_is_dtor, set_is_dtor, None, None)
   cls = property(get_cls, set_cls, None, None)
   start_ea = property(get_start_ea, set_start_ea, None, None)

# =============================================================================
# End class


class PyClassVftable(object):

   def __init__(self, vft_ea=None, cls=None):
      '''
      Represents a VFtable
      '''

      self.__vftable_ea = None
      if vft_ea != None:
         self.__vftable_ea = vft_ea

      self.__cls = None
      if cls != None:
         self.__cls = cls

      self.__vfuncs = {}
      self.__vtable_name = None

      self.__id = idc.BADADDR

      return

   def __str__(self):
      t = "Vftable  %s @ %x\n" % (self.__vtable_name, self.__vftable_ea)
      for k, v in self.__vfuncs.iteritems():
            t += "\tvirtual %x @ %x\n" % (v.start_ea, k)
      return t

   def has_vfuncs(self):
      return not self.__vfuncs

   def get_vftable_ea(self):
      return self.__vftable_ea

   def get_vftable_name(self):
      return self.__vtable_name

   def get_cls(self):
      return self.__cls

   def set_vftable_ea(self, value):
      self.__vftable_ea = value

   def set_vftable_name(self, value):
      self.__vtable_name = value

   def set_cls(self, value):
      self.__cls = value

   def add_virtual_function(self, value, offset):
      self.__vfuncs[offset] = value

   def get_virtual_functions(self):
      return self.__vfuncs

   def set_id(self, value):
      self.__id = value
      return

   def get_id(self):
      return self.__id

   # Properties
   start_ea = property(get_vftable_ea, set_vftable_ea, None, None)
   vtable_name = property(get_vftable_name, set_vftable_name, None, None)
   cls = property(get_cls, set_cls, None, None)
   virtual_functions = property(get_virtual_functions, None, None, None)
   id = property(get_id, set_id, None, None)

# =============================================================================
# End class

class PyClassMember(object):
   '''
   Represents a class member
   '''

   def __init__(self, cls=None, mem_type=None, count=None, mem_name=None, cls_mem=None):
      '''
      initialize class member
      '''
      self.__member_name = mem_name

      self.__type = None
      if mem_type != None:
         self.set_type(mem_type)

      self.__type_count = None
      if count != None:
         self.__type_count = int(count)

      self.__cls = cls

      self.__class_mem = cls_mem

      self.__id = idc.BADADDR

      self.__is_parent = False

      self.__is_vfptr = False

      self.__offset = -1

      return

   def __str__(self):
      '''
      Return member as string
      '''
      return "%s (%x)" % (self.__member_name, self.__id)

   # property getters/setters

   def get_member_name(self):
      return self.__member_name

   def get_type(self):
      return self.__type

   def get_type_count(self):
      return self.__type_count

   def get_cls(self):
      return self.__cls

   def get_class_member(self):
      return self.__class_mem

   def set_class_member(self, value):
      self.__class_mem = value
      if self.__type_size == None:
         self.__type_size = self.__class_mem.size() #idc.GetStrucSize(idc.GetStrucIdByName(self.value))

      return

   def set_member_name(self, value):
      self.__member_name = value
      return

   def set_type_count(self, value):
      self.__type_count = int(value)
      return

   def get_type_size(self):
      return self.__type_size

   def set_type(self, value):
      '''
      the ID for the struct member_type must be supplied
      the member_type can either by primitive :or a structure. If it is a struct :or
      string, then size is required
      '''

      if value == 'vfptr':
         self.__is_vfptr = True
         self.__type = FF_DWRD
         self.__type_size = 4

      # The amount to scale the type
      elif value == 'dword':
         self.__type = FF_DWRD
         self.__type_size = 4

      elif value == 'word':
         self.__type = FF_WORD
         self.__type_size = 2

      elif value == 'byte':
         self.__type_size = 1
         self.__type = FF_BYTE

      elif value == 'asci':
         self.__type_size = 1
         self.__type = FF_ASCI

      elif value == 'qword':
         self.__type_size = 8
         self.__type = FF_QWRD

      elif value == 'struc':
         self.__type = FF_STRU
         if self.cls != None:
            self.__type_size = idc.GetStrucSize(idc.GetStrucIdByName(self.cls.ida_name))
         else:
            self.__type_size = BADADDR
      return

   def set_cls(self, value):
      self.__cls = value

   def set_id(self, value):
      self.__id = value
      return

   def set_isvfptr(self, value):
      self.__is_vfptr = value
      return

   def get_isvfptr(self):
      return self.__is_vfptr

   def get_id(self):
      return self.__id

   def get_size(self):
      return self.__size

   def set_size(self, value):
      self.__size = value
      return

   def get_isparent(self):
      return self.__is_parent

   def set_isparent(self,value):
      self.__is_parent = value

   def get_member_offset(self):
      return self.__offset

   def set_member_offset(self,value):
      self.__offset = value

   # Properties for class members

   member_name = property(get_member_name, set_member_name, None, None)
   is_parent = property(get_isparent, set_isparent, None, None)
   is_vfptr = property(get_isvfptr, set_isvfptr, None, None)
   member_type = property(get_type, set_type, None, None)
   class_member = property(get_class_member, set_class_member, None, None)
   cls = property(get_cls, set_cls, None, None)
   count = property(get_type_count, set_type_count, None, None)
   offset = property(get_member_offset, set_member_offset, None, None)
   size = property(get_type_size, None, None, None)
   id = property(get_id, set_id, None, None)

# =============================================================================
# End class

class PyClassStructure(object):
   '''
   Represents C++ class/structure
   '''

   def __init__(self, struc_def):
      '''
      Builds PyClassStructure
      '''
      self.__methods = []
      self.__vftables = {}

      # members and parents take up space
      self.__members = {}
      self.__parents = {}

      self.__vfcalls = []
      self.__vfcalls = []

      self.__id = idc.BADADDR   # This is set when applied

      self.__applied = False

      self.__size = int(struc_def['Size'],10)

      self.__demangled_name = struc_def['DemangledName']

      self.__name = struc_def['Name']

      # set the IDA name
      self.__ida_name = sanitize_name(self.__name)

      if self.__demangled_name != "":
         self.__ida_name = sanitize_name(self.__demangled_name)

      return

   def __eq__(self,other):
      if other == None: return False
      return self.__id == other.__id and self.__name == other.__name


   def __str__(self):
      '''
      String representation of C++ class
      '''
      folks = ""
      for o, p in self.__parents.iteritems():
         folks += "%s" % (p.ida_name)

      s = "class %s" % self.__ida_name
      if len(folks) > 0:
         s += " : %s" % folks

      s += " { \n"
      for m in self.__members:
         s += "\t%s @ %s\n" % (self.__members[m], m)

      for t in self.__methods:
         s += "\t%s\n" % t

      for v in self.__vftables:
         s += "\t%s\n" % str(v)

      return "%s}" % s

   # property getters/setters

   def get_ida_name(self):
      return self.__ida_name

   def set_ida_name(self, value):
      self.__ida_name = value
      return

   def get_demangled_name(self):
      return self.__demangled_name

   def set_demangled_name(self, value):
      self.__demangled_name = value
      return

   def get_name(self):
      return self.__name

   def set_name(self, value):
      self.__name = value
      return

   def add_member(self, member, off):
      '''
      Add the member, ensuring that the required parameters are specified
      '''
      member.cls = self
      self.__members[off] = member

      return

   def add_method(self, method):

      method.cls = self
      self.__methods.append(method)

      return

   def add_vftable(self, vft, vfptr):
      self.__vftables[vfptr] = vft
      return

   def add_parent(self, parent, off):
      self.__parents[off] = parent
      return

   def add_usage(self, usage):
      self.__vfcalls.append(usage)
      return

   def has_members(self):
      return not self.__members

   def has_methods(self):
      return not self.__methods

   def has_vftable(self):
      return not self.__vftables

   def get_members(self):
      return self.__members

   def get_methods(self):
      return self.__methods

   def get_vftables(self):
      return self.__vftables

   def set_vftables(self, value):
      self.__vftables = value

   def get_parents(self):
      return self.__parents

   def set_id(self, value):
      self.__id = value
      return

   def get_id(self):
      return self.__id

   def set_applied(self, value):
      self.__applied = value
      return

   def get_applied(self):
      return self.__applied

   def get_size(self):
      return self.__size

   def set_size(self,value):
      self.__size = value
      return

   def get_usages(self):
      return self.__vfcalls

   def set_usages(self,value):
      self.__vfcalls = value

   def get_vfcalls(self):
      return self.__vfcalls

   def set_vfcalls(self,value):
      self.__vfcalls = value

   # Properties of class structures

   demangled_name = property(get_demangled_name, set_demangled_name, None, None)
   ida_name = property(get_ida_name, set_ida_name, None, None)
   name = property(get_name, set_name, None, None)
   members  = property(get_members, None, None, None)
   methods  = property(get_methods, None, None, None)
   vftables = property(get_vftables, set_vftables, None, None)
   parents  = property(get_parents, None, None, None)
   id       = property(get_id, set_id, None, None)
   size     = property(get_size,set_size, None, None)
   applied  = property(get_applied, set_applied, None, None)
   usages   = property(get_usages, set_usages, None, None)
   vfcalls  = property(get_vfcalls, set_vfcalls, None, None)

# =============================================================================
# End class


class PyOOAnalyzerMethodTreeItem(QTreeWidgetItem):
   '''
   This is a method element in the class viewer tree
   '''
   def __init__(self,parent, meth):

      super(PyOOAnalyzerMethodTreeItem, self).__init__( parent )
      self.method = meth
      self.setText(0, self.method.method_name)


class PyOOAnalyzerMemberTreeItem(QTreeWidgetItem):
   '''
   This is a member element in the class viewer tree
   '''

   def __init__(self, parent, mem=None):

      super(PyOOAnalyzerMemberTreeItem, self).__init__( parent )
      self.member = mem
      self.setText(0, self.member.member_name)


class PyOOAnalyzerStructTreeItem(QTreeWidgetItem):
   '''
   This is a class element in the class viewer tree
   '''

   def __init__(self, parent, cls=None):

      super(PyOOAnalyzerStructTreeItem, self).__init__( parent )
      self.class_struct = cls
      self.setText(0, self.class_struct.ida_name)

class PyOOAnalyzerExpForm(idaapi.PluginForm):
   '''
   This is the main class viewer form.
   '''
   def __init__(self):

      super(PyOOAnalyzerExpForm, self).__init__()

      self.__objdigger = None

      self.cls_tree = None
      self.idbhook = None
      self.idphook = None

      # the name of the IDA netnode that contains class information
      self.__NODE_NAME = "$OBJD"

      self.__visible = False

      return

   def start_ida_hooks(self):

      if self.idbhook == None:
         self.idbhook = PyOOAnalyzerIDBHooks(self.__objdigger, self)
         self.idbhook.hook()

      if self.idphook == None:
         self.idphook = PyOOAnalyzerIDPHooks(self.__objdigger, self)
         self.idphook.hook()


   def remove_ida_hooks(self):

      if self.idbhook != None:
         self.idbhook.unhook()
         self.idbhook = None

      if self.idphook != None:
         self.idphook.unhook()
         self.idphook = None

   def populate_class_list(self):
      '''
      Initialize the class viewer
      '''

      cls_list = self.__objdigger.get_classes()
      for cls in cls_list:
         cls_entry = PyOOAnalyzerStructTreeItem(self.cls_tree, cls)

         cls_methods = QTreeWidgetItem(cls_entry)
         cls_methods.setText(0,"Methods")

         for m in cls.methods:
            PyOOAnalyzerMethodTreeItem(cls_methods, m)

         cls_members = QTreeWidgetItem(cls_entry)
         cls_members.setText(0,"Members")

         for off, mbr in cls.members.iteritems():
            if mbr.is_parent == False:
               PyOOAnalyzerMemberTreeItem(cls_members, mbr)

         if len(cls.parents) > 0:
            cls_parents = QTreeWidgetItem(cls_entry)
            cls_parents.setText(0,"Parents")
            for o, p in cls.parents.iteritems():
               # Parents are really special members that are class types
               PyOOAnalyzerStructTreeItem(cls_parents, p)

      return

   def navigate(self, event):
      '''
      Enable 1-click navigation to class methods
      '''

      self.cls_tree.blockSignals(True)

      item = self.cls_tree.currentItem()
      if type(item) is PyOOAnalyzerMethodTreeItem:
         idaapi.jumpto(item.method.start_ea)

      self.cls_tree.blockSignals(False)

      return

   def update_class_method(self, cid, old_name, new_name):
      '''
      Update the class viewer in response to a method name change elsewhere in
      the IDB
      '''

      self.cls_tree.blockSignals(True)

      iterator = QTreeWidgetItemIterator(self.cls_tree,
                            QTreeWidgetItemIterator.NotHidden)

      item = iterator.value()

      terminate = False
      while item and not terminate:
         if type(item) is PyOOAnalyzerStructTreeItem:
            if item.class_struct.id == cid:

               # Have to check for because parents are stuct items,
               # thus we may be in a parent
               if item.childCount() > 0:
                  meth_group = item.child(0) # should be methods
                  if meth_group != None:
                     if meth_group.text(0) == "Methods":

                        i=0
                        while i<meth_group.childCount():
                           meth_item = meth_group.child(i)
                           if meth_item:

                              if type(meth_item) is PyOOAnalyzerMethodTreeItem:
                                 if meth_item.text(0) == old_name:
                                    meth_item.setText(0,new_name)
                                    terminate = True
                                    break
                           i += 1

         iterator += 1
         item = iterator.value()

      self.cls_tree.blockSignals(False)


   def update_class_member(self, cid, old_name, new_name):
      '''
      Update the class viewer in response to a member name change elsewhere in
      the IDB
      '''

      self.cls_tree.blockSignals(True)

      iterator = QTreeWidgetItemIterator(self.cls_tree,
                            QTreeWidgetItemIterator.NotHidden)

      item = iterator.value()
      terminate = False
      while item and not terminate:
         if type(item) is PyOOAnalyzerStructTreeItem:
            if item.class_struct.id == cid:

               # Have to check for because parents are stuct items,
               # thus we may be in a parent
               if item.childCount() > 0:
                  mbr_group = item.child(1) # should be members
                  if mbr_group != None:

                     if mbr_group.text(0) == "Members":
                        i=0
                        while i< mbr_group.childCount():
                           mem_item = mbr_group.child(i)
                           if mem_item:
                              if type(mem_item) is PyOOAnalyzerMemberTreeItem:
                                 if mem_item.text(0) == old_name:
                                    mem_item.setText(0,new_name)
                                    terminate = True
                                    break
                           i += 1

         iterator += 1
         item = iterator.value()

      self.cls_tree.blockSignals(False)

   def update_class(self, old_name, new_name):
      '''
      Update the class viewer in response to a class name change elsewhere in
      the IDB
      '''

      self.cls_tree.blockSignals(True)

      iterator = QTreeWidgetItemIterator(self.cls_tree,
                            QTreeWidgetItemIterator.NotHidden)

      item = iterator.value()
      while item:
         if item.text(0) == old_name:
            item.setText(0, new_name)
         else:
            # rename parents of this item
            if item.childCount() == 3:
               par_group = item.child(3) # should be members
               if par_group != None:
                  if par_group.text(0) == "Parents":
                     i=0
                     while i<par_group.childCount():
                        par_item = mbr_group.child(i)
                        if par_item:
                           if par_item.text(0) == old_name:
                              par_item.setText(0, new_name)
         iterator += 1
         item = iterator.value()

      self.cls_tree.blockSignals(False)

      return

   def __edit_member_from_class_viewer(self, item):
      '''
      Edit the class member from the Class Viewer
      '''
      member = item.member
      old_member_name = member.member_name
      new_member_name = idc.AskStr(old_member_name, "Enter new member name")

      if new_member_name == None:
         self.cls_tree.blockSignals(False)
         return

      # cid = idc.GetStrucIdByName(member.member_name
      cls_members = idautils.StructMembers(member.cls.id)

      for [off, n, s] in cls_members:
         if n == member.member_name:

            if idc.SetMemberName(member.cls.id, off, str(new_member_name)) != 0:
               item.setText(0,str(new_member_name))

               cls_list = self.__objdigger.get_classes()
               for c in cls_list:
                  for moff, mem in c.members.iteritems():
                     if mem.member_name == old_member_name:
                        mem.member_name = new_member_name
            else:
               idc.Warning("Cannot rename member to %s, the name already exists :or is malformed!" % new_member_name)

      return

   def __edit_method_from_class_viewer(self,item):
      '''
      Handle method change request initiated from Class Viewer
      '''
      method = item.method
      old_method_name = method.method_name
      new_method_name = idc.AskStr(old_method_name, "Enter new method name")

      if new_method_name == None:
         self.cls_tree.blockSignals(False)
         return

      funcs = idautils.Functions()

      for f in funcs:
         fname = idc.GetFunctionName(f)
         if fname != None:
            if fname == old_method_name:
               if idc.MakeName(f, new_method_name) != 0:

                  cls_list = self.__objdigger.get_classes()
                  for c in cls_list:
                     for m in c.methods:

                        if m.method_name == old_method_name or m.method_name == new_method_name:
                           m.method_name = new_method_name

                           cmt = m.method_name.replace('_', '::', 1)

                           # the method is a virtual function
                           if m.is_virtual == True:
                              cmt = "virtual %s" % cmt

                              # rename virtual function in vftable structure
                              for off, vt in c.vftables.iteritems():
                                 for vfoff,vf in vt.virtual_functions.iteritems():
                                    if vf.start_ea == m.start_ea:

                                       global ignore_renamed
                                       ignore_renamed = True
                                       idc.SetMemberName(vt.id, 4*vfoff, new_method_name)
                                       ignore_renamed = False

                                       vf.method_name = new_method_name
                                       break

                           if method.is_ctor == True: cmt += " (constructor)"

                           if method.is_dtor == True: cmt += " (destructor)"

                           idc.SetFunctionCmt(method.start_ea, cmt, 1)

                  item.setText(0,str(new_method_name))
               else:
                  idc.Warning("Cannot rename method to %s, the name already exists!" % new_method_name)

      return

   def __edit_class_from_class_viewer(self, item):
      '''
      Handle class name change request initiated from Class Viewer
      '''

      old_name = item.class_struct.ida_name
      cid = idaapi.get_struc_id(str(old_name))

      if (cid is not None) and (cid != 0) and (cid != idc.BADADDR):

         new_name = idc.AskStr(old_name, "Enter new class name:")

         if new_name == None:
            self.cls_tree.blockSignals(False)
            return

         if idc.SetStrucName(cid, new_name) != 0:
            item.setText(0,str(new_name))

            cls_list = self.__objdigger.get_classes()
            for c in cls_list:
               if c.ida_name == old_name:
                  c.ida_name = new_name

         else:
            idc.Warning("Cannot rename class to %s, the name already exists!" % new_name)
      else:
         idc.Warning("Cannot rename class before it is applied")

      return

   def edit_class_item(self, event):

      self.cls_tree.blockSignals(True)

      item = self.cls_tree.currentItem()

      if type(item) is PyOOAnalyzerMemberTreeItem:
         self.__edit_member_from_class_viewer(item)

      elif type(item) is PyOOAnalyzerMethodTreeItem:
         self.__edit_method_from_class_viewer(item)

      elif type(item) is PyOOAnalyzerStructTreeItem or type(item) is PyOOAnalyzerParentTreeItem:
         self.__edit_class_from_class_viewer(item)

      self.cls_tree.blockSignals(False)


   def OnCreate(self, form):

      # Get parent widget

      if ida_version < 6.9:
        self.parent = self.FormToPySideWidget(form)
      else:
        self.parent = self.FormToPyQtWidget(form);

      # Create cls_tree control
      self.cls_tree = QTreeWidget()
      headerItem = QTreeWidgetItem()
      headerItem.setText(0,"Class")
      headerItem.setText(1,"State")

      self.cls_tree.setHeaderItem(headerItem)
      self.cls_tree.setWindowTitle("OOAnalzyer Results")
      self.cls_tree.setColumnWidth(0, 200)

      self.cls_tree.itemSelectionChanged.connect(lambda : self.navigate( self.cls_tree.currentItem()))

      # install the context menu
      self.cls_tree.setContextMenuPolicy(Qt.CustomContextMenu)
      self.cls_tree.customContextMenuRequested.connect(self.open_menu)

      # Create layout
      layout = QVBoxLayout()
      layout.addWidget(self.cls_tree)

      self.populate_class_list()
      # Populate PluginForm
      self.parent.setLayout(layout)

      applied_cls = self.__objdigger.get_applied_classes()
      for c in applied_cls:
         self.__mark_applied(c)

      return

   def open_menu(self, position):

      menu = QMenu()
      renameAction = menu.addAction("Rename")

      # can only apply classes
      applyAction = None
      gotoDefAction = None

      item = self.cls_tree.currentItem()
      if type(item) is PyOOAnalyzerStructTreeItem:
         cls = item.class_struct
         if cls.applied == False:
            applyAction = menu.addAction("Apply")
         gotoDefAction = menu.addAction("Open Definition")

      action = menu.exec_(QCursor.pos())

      if action == applyAction:
         self.apply_action()
      elif action == gotoDefAction:
         self.goto_def_action()
      elif action == renameAction:
         self.rename_action()

      return

   def apply_class_item(self, item):
      '''
      Apply a class
      '''
      if type(item) is PyOOAnalyzerStructTreeItem:

         applied_classes = self.__objdigger.get_applied_classes()

         if self.__objdigger.apply_struct(item.class_struct):

            new_applied_classes = self.__objdigger.get_applied_classes()

            # mark all the newly applied classes
            delta = [x for x in new_applied_classes if x not in applied_classes]

            for c in delta:
               self.__mark_applied(c)
      else:
         print "Not applying because not struct"

      return


   def __mark_applied(self, applied_class):
      '''
      Mark the classes that have been applied
      '''
      root = self.cls_tree.invisibleRootItem()
      child_count = root.childCount()

      for i in range(child_count):
         cur_item = root.child(i)
         if type(cur_item) is PyOOAnalyzerStructTreeItem:
            if applied_class.ida_name == cur_item.class_struct.ida_name:
               cur_item.setBackground(0,QBrush(Qt.green,Qt.Dense7Pattern))
               font = cur_item.font(0)
               font.setBold(True)
               cur_item.setFont(0,font)
               cur_item.setText(1,"Applied")

   def apply_action(self):
      '''
      Execute the apply action
      '''
      item = self.cls_tree.currentItem()
      self.apply_class_item(item)

   def goto_def_action(self):
      '''
      Execute the goto definition action
      '''
      item = self.cls_tree.currentItem()
      cls = item.class_struct
      if cls.applied == True:
         if ida_version < 6.9:
            idaapi.open_structs_window(item.class_struct.id)
         else:
            ida_kernwin.open_structs_window(item.class_struct.id)
      else:
         idc.Warning("You must apply class '%s' before you can open its definition" %  item.class_struct.ida_name)

   def rename_action(self):
      '''
      Execute the rename action
      '''
      item = self.cls_tree.currentItem()
      self.edit_class_item(item)

   def __save_to_idb(self):
      '''
      Save the JSON to a netnode
      '''
      self.__node = idaapi.netnode()

      if not self.__node.create(self.__NODE_NAME):

         # node exists - reset it
         self.__node.delblob(0,'O')
         self.__node.create(self.__NODE_NAME)


      if self.__objdigger:

         cls_list = self.__objdigger.get_classes()
         for c in cls_list:
            print "Saving class: %s" % c.ida_name

         if type(self.__objdigger) == PyOOAnalyzer:
            data = pickle.dumps(self.__objdigger)
            self.__node.setblob(data, 0, 'I')
         else:
            print "Can't save information to IDB"

      return

   def __load_from_idb(self):
      '''
      Load previously applied JSON
      '''
      self.__node = idaapi.netnode()
      if not self.__node.create(self.__NODE_NAME):
         # node exists - fetch it

         data = self.__node.getblob(0, 'I')
         if not data:
            return None

         loaded_data = pickle.loads(data)

         return loaded_data

      return None

   def __load_from_json_file(self, json_file):
      '''
      Parse the JSON file
      '''
      if json_file != None:

         if self.__objdigger.set_json_file(json_file):
            print "Opened JSON file %s" % json_file
         else:
            idc.Warning("Could not open %s" % json_file)
            return False

      if self.__objdigger.is_parsed() == False: #not parsed yet
         result,msg = self.__objdigger.parse()
         if result == False:
            idc.Warning("Could not parse JSON: %s" % msg)
            return False

      parse_results = self.__objdigger.get_parse_results()
      if parse_results == None:
         return None,0,0,0

      num_classes = 0
      num_vcalls = 0
      num_usages = 0

      if "NumClasses" in parse_results:
         num_classes = parse_results["NumClasses"]
      if "NumVcalls" in parse_results:
         num_vcalls = parse_results["NumVcalls"]
      if "NumUsages" in parse_results:
         num_usages = parse_results["NumUsages"]

      res_str = """
Successfully parsed JSON file: "%s".

The following C++ constructs are ready to apply:

  * %s class structures
  * %s object usages
  * %s virtual function calls

Press \"Yes\" to apply these items to the IDB. Press no to apply them manually (Note that virtual function calls will be resolved automatically)
""" % (self.__objdigger.get_json_filename(),num_classes,num_usages,num_vcalls)

      return res_str,num_classes,num_vcalls,num_usages

   def OnClose(self, form):
      """
      Called when the plugin form is closed
      """

      global clsExpForm

      self.__save_to_idb()

      clsExpForm.remove_ida_hooks()

      self.__visible = False

      clsExpForm = None

      return

   def __setup_form(self):
      '''
      set up form data
      '''

      objd = self.__load_from_idb()
      if objd:
         print "OOAnalyzer class information found in IDB, opening Class Viewer"

         # mark previously applied classes
         self.__objdigger = objd

      else:

         # load the class spec from a JSON file

         json_file = idc.AskFile(0, "*.json", "Open JSON C++ specification file")
         if not json_file:
            return False

         self.__objdigger = PyOOAnalyzer()

         # if everything applies OK, then show the form
         parse_results,nc,nvc,nu = self.__load_from_json_file(json_file)

         if parse_results != None:
            form_msg = """CERT OOAnalyzer v%.1f
%s
"""%(VERSION,parse_results)

            do_apply = idc.AskYN(1, form_msg)

            if do_apply != 0:
               print "Applying all results"

               self.__objdigger.apply_all_structs()

            # always apply virtual function calls
            self.__objdigger.apply_vfcalls()
            print "Apply some results"


         else:
            idc.Warning("No C++ data structures found in '%s'" % json_file)
            return False

      print "OOAnalyzer Plugin version %s done" % VERSION

      return True

   def Show(self):

      if not self.__visible:
         if self.__setup_form():

            if self.idbhook == None and self.idphook == None:
               self.start_ida_hooks()

            self.__visible = True
            return PluginForm.Show(self,"OOAnalyzer Class Viewer", options = PluginForm.FORM_PERSIST)
         else:
            return -1

   def is_visible(self):
      return self.__visible

class PyOOAnalyzerIDPHooks(IDP_Hooks):

   def __init__(self,objd, frm):

      IDP_Hooks.__init__(self)

      self.__objdigger = objd
      self.__form = frm

      return


   def renamed(self, *args):
      '''
      Something in the database has been renamed
      '''
      ea = args[0]
      new_name = args[1]
      local_name = args[2]
      global ignore_renamed
      if ignore_renamed: return IDP_Hooks.renamed(self, ea, new_name, local_name)

      # a function has been renamed
      if idc.GetFunctionName(ea) != "":
         cls_model = self.__objdigger.get_classes()
         for c in cls_model:
            for m in c.methods:
               if m.start_ea == ea:

                  self.__form.update_class_method(c.id, m.method_name, new_name)
                  m.method_name = new_name

                  if m.is_virtual:

                     # rename function name in vftable structure
                     for off, vt in c.vftables.iteritems():
                        for vfoff,vf in vt.virtual_functions.iteritems():

                           if vf.start_ea == m.start_ea:

                              ignore_renamed = True
                              idc.SetMemberName(vt.id, 4*vfoff, new_name)

                              ignore_renamed = False

                              vf.method_name = new_name
                              break

                  return IDP_Hooks.renamed(self, ea, new_name, local_name)

      return IDP_Hooks.renamed(self, ea, new_name, local_name)


class PyOOAnalyzerIDBHooks(idaapi.IDB_Hooks):

   def __init__(self, objd, frm):

      self.form = frm
      self.__objdigger = objd

      idaapi.IDB_Hooks.__init__(self)


   def struc_member_renamed(self, *args):
      '''
      A structure member has been renamed
      '''
      global ignore_renamed
      if ignore_renamed: return 0

      struc = args[0]
      mbr = args[1]

      class_model = self.__objdigger.get_classes()
      for c in class_model:
         if c.id == struc.id:

            changed_name = idc.GetMemberName(c.id, int(mbr.soff))

            for off, m in c.members.iteritems():
               if off == mbr.soff:
                  if m:
                     self.form.update_class_member(c.id, m.member_name, changed_name)
                     m.member_name = changed_name
                     return 0

      # Update virtual functions if they are changed
      for c in class_model:
         for off, vt in  c.vftables.iteritems():
            if struc.id == vt.id:

               changed_name = idc.GetMemberName(vt.id, int(mbr.soff))

               for vfoff, vf in vt.virtual_functions.iteritems():

                  # this has to be scaled
                  if (vfoff*4) == mbr.soff:
                     if vt:
                        self.form.update_class_method(c.id, vf.method_name, changed_name)
                        vf.method_name = changed_name

                        ignore_renamed = True
                        idc.MakeName(vf.start_ea,changed_name)
                        ignore_renamed = False

                        return 0
      return 0

   def struc_renamed(self, *args):
      '''
      A structure was renamed in the IDB
      '''
      renamed_struc = args[0]

      class_model = self.__objdigger.get_classes()
      for c in class_model:
         if c.id == renamed_struc.id:

            new_name = idc.GetStrucName(renamed_struc.id)
            if new_name != None:

               self.form.update_class(c.ida_name, new_name)

               c.ida_name = new_name
               for off, m in c.members.iteritems():
                  m.ida_name = new_name

               for mtd in c.methods:
                  cmt = "%s::%s"  % (c.ida_name, mtd.method_name)
                  if mtd.is_virtual == True: cmt = "virtual %s" % cmt
                  if mtd.is_ctor == True: cmt += " (constructor)"
                  if mtd.is_dtor == True: cmt += " (destructor)"
                  idc.SetFunctionCmt(mtd.start_ea, cmt, 1)

               for off, v in c.vftables.iteritems():
                  v.cls.ida_name = new_name

                  new_vft_name = generate_vftable_name(self.__objdigger.get_classes(), v, c, off)

                  idc.MakeName(v.start_ea, "%s_%x" % (new_vft_name, v.start_ea))
                  idc.SetStrucName(v.id,new_vft_name)
                  idc.SetStrucComment(v.id, v.cls.ida_name + " virtual function table", 1)

               break

      return 0

# =============================================================================
# This is the entry point for the plugin

class PyOOAnalyzer_plugin(plugin_t):
   '''
   Main plugin class
   '''

   flags = PLUGIN_UNL

   comment = "IDA OOAnalyzer plugin"
   help = "Email jsg@cert.org"
   wanted_name = "OOAnalyzer"
   wanted_hotkey = "F3"


   def init(self):
      '''
      Create the Plugin
      '''

      return PLUGIN_OK

   def run(self, arg):
      '''
      Run the plugin
      '''

      try:
         # is the Class Viewer already open?
         class_viewer = idaapi.find_tform("OOAnalyzer Class Viewer")
         if class_viewer != None:
            print "OOAnalyzer Class Viewer already open"
            return

         global clsExpForm
         global ignore_renamed

         ignore_renamed = False
         clsExpForm = None

         print "\n\nOOAnalyzer Plugin version %s loaded" % VERSION

         if clsExpForm is None:
            clsExpForm = PyOOAnalyzerExpForm()
            clsExpForm.Show()

         idaapi.set_dock_pos('OOAnalyzer Class Viewer','Functions window',idaapi.DP_BOTTOM)
      except Exception, e:
         traceback.print_exc()
         print e

      return

   def term(self):
      print "OOAnalyzer Plugin version %s done" % VERSION
      return

def PLUGIN_ENTRY():
   try:
      return PyOOAnalyzer_plugin()
   except Exception, e:
      traceback.print_exc()
      print e
   return None
