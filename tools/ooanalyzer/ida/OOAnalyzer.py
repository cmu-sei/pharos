'''Created on Jan 8, 2014

@version: 2.0
@organization: CERT Malicious Code Team
@author: jsg

This is the IDA plugin to apply OOAnalyzer output into IDA
Pro. Version 2.0 is the first version that works with OOAnalyzer.

'''
try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtGui import *
    from PyQt5.QtCore import *
    import six
    import logging
    import zlib
    import traceback
    import re
    import copy
    import json
    from abc import ABCMeta, abstractmethod
    import sys
    import codecs
    import ida_bytes
    import ida_idp
    import ida_kernwin
    import ida_name
    import ida_struct
    import ida_ua
    import ida_xref
    import idaapi
    import idaapi
    import idautils
    import idc
except ImportError:
    print("Could not import IDA Python modules")
    sys.exit(-1)

# In lieu of using "six", let's make out own Python2/3 changes ourselves.
python_version_2 = (sys.version_info[0] == 2)

PLUGIN_VERSION = 2.0

EXPECTED_JSON_VERSION = "2.2.0"

BLOB_SIZE = 1024
OUR_NETNODE = "$ com.williballenthin"
INT_KEYS_TAG = 'M'
STR_KEYS_TAG = 'N'
STR_TO_INT_MAP_TAG = 'O'
INT_TO_INT_MAP_TAG = 'P'
OOA_JSON = "OOA_JSON"
APPLIED_CLASS_NAMES = "OOA_APPLIED"

logger = logging.getLogger(__name__)

# get the IDA version number
ida_major, ida_minor = list(map(int, idaapi.get_kernel_version().split(".")))
using_ida7api = (ida_major > 6)

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
    lineage of overwritten vftptrs
    '''

    lineage = []
    c = cls

    while c is not None:

        if c in lineage:
            print("WARNING: Class %s is in it's own lineage. This shouldn't happen" % c)
            break

        lineage.append(c)

        # add the current parent
        if off in c.parents:

            # go to the next parent at this offset. This will capture over-written vftptrs
            c = next(
                (pc for pc in classes if c.parents[off].name == pc.name), None)

            if c is None:
                print("WARNING: Unable to find correct parent")
                assert False

        else:
            c = None

    vft_parts = []
    for x in lineage:
        if x.ida_name != "":
            vft_parts.append(x.ida_name)
        else:
            vft_parts.append(x.name)

    vft_name = "_".join(str(y) for y in vft_parts)

    print("Vritual function table name %s_vftable" % vft_name)
    return "%s_vftable" % vft_name

# The code below was taken from:
# 
# https://github.com/williballenthin/ida-netnode/tree/master
#  
# To manage storage in an IDA IDB.

class NetnodeCorruptError(RuntimeError):
    pass

class Netnode(object):
    """
    A netnode is a way to persistently store data in an IDB database.
    The underlying interface is a bit weird, so you should read the IDA
      documentation on the subject. Some places to start:

      - https://www.hex-rays.com/products/ida/support/sdkdoc/netnode_8hpp.html
      - The IDA Pro Book, version 2

    Conceptually, this netnode class represents is a key-value store
      uniquely identified by a namespace.

    This class abstracts over some of the peculiarities of the low-level
      netnode API. Notably, it supports indexing data by strings or
      numbers, and allows values to be larger than 1024 bytes in length.

    This class supports keys that are numbers or strings.
    Values must be JSON-encodable. They can not be None.

    Implementation:
     (You don't have to worry about this section if you just want to
        use the library. Its here for potential contributors.)

      The major limitation of the underlying netnode API is the fixed
        maximum length of a value. Values must not be larger than 1024
        bytes. Otherwise, you must use the `blob` API. We do that for you.

      The first enhancement is transparently zlib-encoding all values.

      To support arbitrarily sized values with keys of either int or str types,
        we store the values in different places:

        - integer keys with small values: stored in default supval table
        - integer keys with large values: the data is stored in the blob
           table named 'M' using an internal key. The link from the given key
           to the internal key is stored in the supval table named 'P'.
        - string keys with small values: stored in default hashval table
        - string keys with large values: the data is stored in the blob
           table named 'N' using an integer key. The link from string key
           to int key is stored in the supval table named 'O'.
    """

    def __init__(self, netnode_name):
        self._netnode_name = netnode_name
        self._n = idaapi.netnode(netnode_name, 0, True)

    @staticmethod
    def _decompress(data):
        '''
        args:
          data (bytes): the data to decompress

        returns:
          bytes: the decompressed data.
        '''
        return zlib.decompress(data)

    @staticmethod
    def _compress(data):
        '''
        args:
          data (bytes): the data to compress

        returns:
          bytes: the compressed data.
        '''
        return zlib.compress(data)

    @staticmethod
    def _encode(data):
        '''
        args:
          data (object): the data to serialize to json.

        returns:
          bytes: the ascii-encoded serialized data buffer.
        '''
        return json.dumps(data).encode("ascii")

    @staticmethod
    def _decode(data):
        '''
        args:
          data (bytes): the ascii-encoded json serialized data buffer.

        returns:
          object: the deserialized object.
        '''
        return json.loads(data.decode("ascii"))

    def _intdel(self, key):
        assert isinstance(key, six.integer_types)

        did_del = False
        storekey = self._n.supval(key, INT_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey)
            self._n.delblob(storekey, INT_KEYS_TAG)
            self._n.supdel(key, INT_TO_INT_MAP_TAG)
            did_del = True
        if self._n.supval(key) is not None:
            self._n.supdel(key)
            did_del = True

        if not did_del:
            raise KeyError("'{}' not found".format(key))

    def _get_next_slot(self, tag):
        '''
        get the first unused supval table key, or 0 if the
         table is empty.
        useful for filling the supval table sequentially.
        '''
        slot = self._n.suplast(tag)
        if slot is None or slot == idaapi.BADNODE:
            return 0
        else:
            return slot + 1

    def _intset(self, key, value):
        assert isinstance(key, six.integer_types)
        assert value is not None

        try:
            self._intdel(key)
        except KeyError:
            pass

        if len(value) > BLOB_SIZE:
            storekey = self._get_next_slot(INT_KEYS_TAG)
            self._n.setblob(value, storekey, INT_KEYS_TAG)
            self._n.supset(key, str(storekey).encode(
                'utf-8'), INT_TO_INT_MAP_TAG)
        else:
            self._n.supset(key, value)

    def _intget(self, key):
        assert isinstance(key, six.integer_types)

        storekey = self._n.supval(key, INT_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey.decode('utf-8'))
            v = self._n.getblob(storekey, INT_KEYS_TAG)
            if v is None:
                raise NetnodeCorruptError()
            return v

        v = self._n.supval(key)
        if v is not None:
            return v

        raise KeyError("'{}' not found".format(key))

    def _strdel(self, key):
        assert isinstance(key, (str))

        did_del = False
        storekey = self._n.hashval(key, STR_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey.decode('utf-8'))
            self._n.delblob(storekey, STR_KEYS_TAG)
            self._n.hashdel(key, STR_TO_INT_MAP_TAG)
            did_del = True
        if self._n.hashval(key):
            self._n.hashdel(key)
            did_del = True

        if not did_del:
            raise KeyError("'{}' not found".format(key))

    def _strset(self, key, value):
        assert isinstance(key, (str))
        assert value is not None

        try:
            self._strdel(key)
        except KeyError:
            pass

        if len(value) > BLOB_SIZE:
            storekey = self._get_next_slot(STR_KEYS_TAG)
            self._n.setblob(value, storekey, STR_KEYS_TAG)
            self._n.hashset(key, str(storekey).encode(
                'utf-8'), STR_TO_INT_MAP_TAG)
        else:
            self._n.hashset(key, bytes(value))

    def _strget(self, key):
        assert isinstance(key, (str))

        storekey = self._n.hashval(key, STR_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey.decode('utf-8'))
            v = self._n.getblob(storekey, STR_KEYS_TAG)
            if v is None:
                raise NetnodeCorruptError()
            return v

        v = self._n.hashval(key)
        if v is not None:
            return v

        raise KeyError("'{}' not found".format(key))

    def __getitem__(self, key):
        if isinstance(key, str):
            v = self._strget(key)
        elif isinstance(key, six.integer_types):
            v = self._intget(key)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

        data = self._decompress(v)
        return self._decode(data)

    def __setitem__(self, key, value):
        '''
        does not support setting a value to None.
        value must be json-serializable.
        key must be a string or integer.
        '''
        assert value is not None

        v = self._compress(self._encode(value))
        if isinstance(key, str):
            self._strset(key, v)
        elif isinstance(key, six.integer_types):
            self._intset(key, v)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

    def __delitem__(self, key):
        if isinstance(key, str):
            self._strdel(key)
        elif isinstance(key, six.integer_types):
            self._intdel(key)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, zlib.error):
            return default

    def __contains__(self, key):
        try:
            if self[key] is not None:
                return True
            return False
        except (KeyError, zlib.error):
            return False

    def _iter_int_keys_small(self):
        # integer keys for all small values
        i = None
        if using_ida7api:
            i = self._n.supfirst()
        else:
            i = self._n.sup1st()
        while i != idaapi.BADNODE:
            yield i
            if using_ida7api:
                i = self._n.supnext(i)
            else:
                i = self._n.supnxt(i)

    def _iter_int_keys_large(self):
        # integer keys for all big values
        if using_ida7api:
            i = self._n.supfirst(INT_TO_INT_MAP_TAG)
        else:
            i = self._n.sup1st(INT_TO_INT_MAP_TAG)
        while i != idaapi.BADNODE:
            yield i
            if using_ida7api:
                i = self._n.supnext(i, INT_TO_INT_MAP_TAG)
            else:
                i = self._n.supnxt(i, INT_TO_INT_MAP_TAG)

    def _iter_str_keys_small(self):
        # string keys for all small values
        if using_ida7api:
            i = self._n.hashfirst()
        else:
            i = self._n.hash1st()
        while i != idaapi.BADNODE and i is not None:
            yield i
            if using_ida7api:
                i = self._n.hashnext(i)
            else:
                i = self._n.hashnxt(i)

    def _iter_str_keys_large(self):
        # string keys for all big values
        if using_ida7api:
            i = self._n.hashfirst(STR_TO_INT_MAP_TAG)
        else:
            i = self._n.hash1st(STR_TO_INT_MAP_TAG)
        while i != idaapi.BADNODE and i is not None:
            yield i
            if using_ida7api:
                i = self._n.hashnext(i, STR_TO_INT_MAP_TAG)
            else:
                i = self._n.hashnxt(i, STR_TO_INT_MAP_TAG)

    def iterkeys(self):
        for key in self._iter_int_keys_small():
            yield key

        for key in self._iter_int_keys_large():
            yield key

        for key in self._iter_str_keys_small():
            yield key

        for key in self._iter_str_keys_large():
            yield key

    def keys(self):
        return [k for k in list(self.iterkeys())]

    def itervalues(self):
        for k in list(self.keys()):
            yield self[k]

    def values(self):
        return [v for v in list(self.itervalues())]

    def iteritems(self):
        for k in list(self.keys()):
            yield k, self[k]

    def items(self):
        return [(k, v) for k, v in list(self.iteritems())]

    def kill(self):
        self._n.kill()
        self._n = idaapi.netnode(self._netnode_name, 0, True)


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

        self.__is_parsed = False

        # this is the results of parsing
        self.__parse_results = {"NumUsages": 0}

        self.__applied_classes = {}

        return

    def set_classes(self, other_classes):
        self.__classes = copy.deepcopy(other_classes)

    def __str__(self):
        '''
        Convert a class to a string
        '''
        s = ""
        for c in self.__classes:
            s += "%s\n" % c
        return s

    def set_json_file(self, jsn_file):
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

    def find_name(self, ea):
        for cls in self.__classes:
            for method in cls.methods:
                if method.start_ea == ea:
                    return method.method_name
        return None

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
        """
        Parse the JSON object into a Python dictionary. Parse methods are responsible for properly
        setting the type of data. addresses are always base 16 and offsets are always in base 10
        """

        def _byteify(data):
            # if this is a unicode string, return its string representation
            if python_version_2:
                if isinstance(data, basestring):
                    return str(data.encode('utf-8').decode())
            else:
                if isinstance(data, str):
                    return str(data.encode('utf-8').decode())

            # if this is a list of values, return list of byteified values
            if isinstance(data, list):
                return [_byteify(item) for item in data]

            # if this is a dictionary, return dictionary of byteified keys and values
            # but only if we haven't already byteified it
            if isinstance(data, dict):
                if python_version_2:
                    return {_byteify(key): _byteify(value) for key, value in data.iteritems()}
                else:
                    return {_byteify(key): _byteify(value) for key, value in data.items()}

            # if it's anything else, return it in its original form
            return data

        if self.__json_data == None:
            return [False, "File not specified"]

        data = None
        try:
            data = json.loads(self.__json_data, object_hook=_byteify)
        except Exception as e:
            print("JSON parsing error: %s" % e)
            return [False, "JSON parsing error: %s" % e]

        file_version = data["version"] if "version" in data else "unknown"
        if file_version != EXPECTED_JSON_VERSION:
            return [False, "Expected JSON version '%s' but found '%s' instead. Aborting." % (EXPECTED_JSON_VERSION, file_version)]

        if "filemd5" in data:
            jsonMd5 = data["filemd5"]
            # Some IDA give a binary encoded version, and some give it in ascii already!
            idaMd5 = idautils.GetInputFileMD5()
            idaMd52 = codecs.encode(idaMd5, 'hex').decode("ascii")
            if jsonMd5.lower() != idaMd5.lower() and jsonMd5.lower() != idaMd52.lower():
                print(jsonMd5, idaMd5)
                if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, "There was a hash mismatch.  This JSON may be for a different file '%s'.  Do you want to import anyway?" % data["filename"]) == ida_kernwin.ASKBTN_NO:
                    return [False, "User aborted after hash mismatch"]

        print("Parsing JSON structures ...")
        self.__parse_structs(data["structures"])
        print("Completed Parsing JSON structures file: %s classes found" %
              len(self.__classes))

        self.__parse_vf_calls(data['vcalls'])
        print("Completed Parsing JSON class usages")

        self.__is_parsed = True
        return [True, "OK"]

    def apply(self):
        '''
        Apply classes, then usages
        '''

        print("Applying class structures")

        self.__apply_structs()

        print("Applying class virtual function calls")

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

                    print("Applying class %s" % c.ida_name)

                    self.apply_class(c)

                    c.applied = True
                    result = True
                    break
                else:
                    print("Class %s already applied" % c.name)
                    result = False
                    break

        return result

    def __parse_structs(self, structs):
        '''
        Parse the structures defined in the JSON file. The order here matters:

           * vftables must be parsed before methods because vftables contain additional methods
        '''
        self.__parse_results["NumClasses"] = len(structs)

        for s in structs.values():
            # use the ID of the current struct, if it exists
            c = PyClassStructure(s)

            #  The class must be created for members to work
            self.__classes.append(c)

            print("Found class %s" % c.ida_name)

        for s in structs.values():
            # Now fill out the structures
            for c in self.__classes:
                if c.name == s['name']:

                    cid = ida_struct.get_struc_id(c.ida_name)
                    if cid != idaapi.BADADDR:
                        c.id = cid

                    self.__parse_methods(c, s['methods'])
                    self.__parse_vftables(c, s['vftables'])
                    self.__parse_members(c, s['members'])

        # this point each class structure is loaded
        self.__classes_found = True

        return

    def __parse_members(self, cls, members):
        '''
        Add each member specified
        '''

        print("Parsing %d members for class %s ..." %
              (len(members), cls.ida_name))

        for m in members.values():
            offset = int(m['offset'], 16)
            if offset > 0x7FFFFFFF:
                offset -= 0x100000000

            if offset < 0:
                print("WARNING: Negative member offset (%d) found - discarding" % offset)
                continue

            # valid member - create it
            mem = PyClassMember(cls, m['type'], m['size'])
            mem.cls = cls
            mem.base = m['base']
            mem.member_name = m['name']

            self.__parse_member_usages(cls, m['usages'])

            if mem.member_type == ida_bytes.FF_STRUCT:

                mem.class_member_name = m['struc']  # This could be mangled

                # Search for the parsed class information
                cls_mem = None
                for c in self.__classes:
                    if mem.class_member_name == c.name:
                        cls_mem = c
                        break

                assert cls_mem is not None, "Unable to find class member struct %s" % mem.class_member_name

                mem.class_member = cls_mem

                if m['parent']:
                    # this is a parent
                    mem.is_parent = True
                    cls.add_parent(cls_mem, offset)
                    print("   - Found class parent, name: '%s', type: %s" %
                          (mem.member_name, mem.class_member.ida_name))
                else:
                    print("   - Found class member, name: '%s', type: %s" %
                          (mem.member_name, mem.class_member.ida_name))

            else:
                mem.class_member = None
                print("   - Found member '%s' @ offset 0x%x" %
                      (mem.member_name, offset))

            # offset of this member
            mem.offset = offset

            # add the new member if it is not from the base class
            if not mem.base:
                cls.add_member(mem, offset)

            if cls.id != idaapi.BADADDR:
                mid = idc.get_member_id(cls.id, offset)
                if mid != -1:
                    mem.id = mid

        print("Members parsed")

        return

    def __parse_methods(self, cls, methods):
        '''
        Parse the methods defined in the JSON file
        '''

        print("Parsing %d methods for class %s ..." %
              (len(methods), cls.ida_name))

        for m in methods.values():

            meth = PyClassMethod()

            meth.cls = cls
            meth.is_virtual = False  # no traditional methods are virtual

            meth.is_ctor = False
            meth.is_dtor = False
            if m['type'] == "ctor":
                meth.is_ctor = True
            elif m['type'] == "dtor" or m['type'] == "deldtor":
                meth.is_dtor = True

            #  this method is imported
            meth.is_import = False
            if m['import']:
                meth.is_import = True

            meth.start_ea = int(m['ea'], 16)

            meth.method_name = m['name']
            meth.demangled_name = m['demangled_name'] if m['demangled_name'] != "" else None
            meth.userdef_name = False

            flags = ida_bytes.get_flags(meth.start_ea)

            # In vs2010/Lite/oo, there is a function tail at 0x403ed0.  Unfortunately another
            # function tail calls that chunk, and get_func(0x403ed0) refers to the larger one.
            # This results in IDA helpfully saying that the function at 0x403ed0 is named
            # sub_402509.  Thanks IDA!
            idafunc = idaapi.get_func(meth.start_ea)
            is_func = idafunc is not None and idafunc.start_ea == meth.start_ea

            has_name = is_func \
                and ida_bytes.has_name(flags) \
                and ida_bytes.has_user_name(flags) \
                and idc.get_func_name(meth.start_ea) != ""
            # Does IDA have a name for this function?
            if has_name:
                meth.method_name = idc.get_func_name(meth.start_ea)
                meth.demangled_name = idc.demangle_name(meth.method_name,
                                                        idc.get_inf_attr(idc.INF_SHORT_DN))
                meth.demangled_name = meth.demangled_name if meth.demangled_name != "" else None
                meth.userdef_name = True

            print("   - Method %s parsed" % meth.method_name)

            cls.add_method(meth)

        print("All methods parsed")

        return

    def __parse_vftables(self, cls, vftables):
        '''
        Parse the vftables defined in the JSON file
        '''

        print("Parsing %s vftables for class %s ..." %
              (len(vftables), cls.ida_name))

        for v in vftables.values():

            vftptr_off = int(v['vftptr'], 16)
            if vftptr_off < 0:
                print(
                    "   WARNING: Negative virtual function pointer offset found (%d) - discarding" % vftptr_off)
                continue

            vft = PyClassVftable()
            vft.cls = cls
            vft.length = int(v['length'])
            vft.start_ea = int(v['ea'], 16)

            for entry in v['entries'].values():
                start_ea = int(entry['ea'], 16)

                # Look up method instead of duplicating code
                meth = next(
                    method for method in cls.methods if method.start_ea == start_ea)
                assert meth is not None

                vft.add_virtual_function(meth, int(entry['offset']))

            print("   - Adding vtable %x at offset %d" %
                  (vft.start_ea, vftptr_off))
            print("")

            vft_name = generate_vftable_name(
                self.__classes, vft, cls, vftptr_off)
            vftid = ida_struct.get_struc_id(vft_name)
            if vftid != idaapi.BADADDR:
                vft.id = vftid
            cls.add_vftable(vft, vftptr_off)

        print("Vftables parsed")

        return

    def __parse_member_usages(self, cls, mem_usages):
        '''
        Parse member usages and enqueue them for processing.
        '''
        self.__parse_results["NumUsages"] += len(mem_usages)
        for ea in mem_usages:
            mu = PyMemberUsage()
            mu.ida_name = cls.ida_name
            mu.ea = int(ea, 16)
            mu.cid = idaapi.BADADDR
            cls.add_usage(mu)
        return

    def __parse_vf_calls(self, vcalls):
        '''
        Parse virtual function calls
        '''
        print("Parsing %s virtual function calls ..." % (len(vcalls)))
        self.__parse_results["NumVcalls"] = len(vcalls)

        for call_ea, targets in vcalls.items():
            vc = PyVirtualFunctionCallUsage()
            vc.call_ea = int(call_ea, 16)

            for t in targets['targets']:
                vc.add_target_ea(int(t, 16))

            print("Parsed virtual function call: %s" % vc)

            self.__vfcalls.append(vc)

        return

    # The following methods concern applying the parsed JSON file to an IDB

    def apply_class(self, cls):
        '''
        Apply the class
        '''

        print("================================================")
        print("Applying class '%s'" % cls.ida_name)

        if cls.ida_name in self.__applied_classes:
            print("class '%s' is already applied" % cls.ida_name)
            return cls.id

        cls.id = ida_struct.add_struc(0, cls.ida_name, 0)
        cls.ptr = ida_struct.get_struc(cls.id)
        # Save the ID of this struct
        self.__applied_classes[cls.ida_name] = cls

        if cls.demangled_name != "":
            ida_struct.set_struc_cmt(
                cls.id, "Original mangled name: %s" % cls.name, 1)

        if len(cls.members) > 0:
            print("Applying %d members ..." % len(cls.members))
            for moff, mem in cls.members.items():
                self.__apply_member(cls, mem, moff)
            print("Members applied")
        else:
            print("Class with no members not allowed by IDA Pro, creating dummy member")

            idc.add_struc_member(
                cls.id, "EMPTY", 0, ida_bytes.FF_BYTE | ida_bytes.FF_DATA, 0xffffffff, 1)
        if len(cls.parents) > 0:
            print("Applying %d parents ..." % len(cls.parents))
            for poff, par in cls.parents.items():
                self.__apply_parent(cls, par, poff)
            print("Parents applied")

        if len(cls.vftables) > 0:
            print("Applying %d vftables ..." % len(cls.vftables))
            for voff, vft in cls.vftables.items():
                self.__apply_vftable(cls, vft, voff)
            print("Vftables applied")

        if len(cls.methods) > 0:
            print("Applying %d methods ..." % len(cls.methods))
            for n in cls.methods:
                self.__apply_method(n)
            print("Methods applied")

        if len(cls.usages) > 0:
            print("Applying %d usages ..." % len(cls.usages))
            for u in cls.usages:
                u.cid = cls.id
                u.apply()
            print("Methods applied")

        print("Applied class '%s'" % cls.ida_name)
        print("================================================\n")

        cls.applied = True

        return cls.id

    def __apply_member(self, cls, mem, off):
        '''
        Apply members of this class to the IDB
        '''

        if mem.is_parent:
            return

        nbytes = idaapi.BADADDR
        if mem.member_type == ida_bytes.FF_STRUCT:
            if mem.class_member.ida_name not in self.__applied_classes:
                self.apply_class(mem.class_member)
                print("Applying class member: %s" %
                      str(mem.class_member.ida_name))

            nbytes = ida_struct.get_struc_size(
                ida_struct.get_struc(mem.class_member.id))
            mem_type = ida_bytes.FF_STRUCT | ida_bytes.FF_DATA

            idc.add_struc_member(cls.id, mem.member_name,
                                 off, mem_type, mem.class_member.id, nbytes)

        else:
            # non-struct member
            nbytes = mem.size
            idc.add_struc_member(cls.id, mem.member_name,
                                 off, mem.member_type, 0xffffffff, nbytes)

        # save the member ID
        mem.id = idc.get_member_id(cls.id, off)
        if mem.id == -1:
            print("WARNING: Adding member at offset %d to %s failed" %
                  (off, cls.ida_name))

        return

    def apply_method(self, method):
        self.__apply_method(method)

    def __apply_method(self, method):
        '''
        Apply methods of this class to the IDB
        '''

        method_name = method.demangled_name if method.demangled_name is not None else method.method_name

        cmt = cmt = "%s::%s" % (method.cls.ida_name, method_name)

        if method.is_virtual == True:
            cmt = "virtual %s" % cmt

        if method.is_ctor == True:
            cmt += " (constructor)"

        if method.is_dtor == True:
            cmt += " (destructor)"

        idafunc = idaapi.get_func(method.start_ea)
        is_func = idafunc is not None and idafunc.start_ea == method.start_ea
        if is_func:
            # Check for existing name
            if idc.get_name_ea_simple(method_name) != idaapi.BADADDR:
                method_name += "_%x" % method.start_ea

            print("Renaming %s to %s" %
                  (idc.get_func_name(method.start_ea), method_name))

            idc.set_name(method.start_ea, method_name,
                         ida_name.SN_NOCHECK | ida_name.SN_FORCE)
        else:
            print("Not renaming the function at %#x %s because it is not a function in IDA!" % (
                method.start_ea, method_name))

        idc.set_func_cmt(method.start_ea, cmt, 1)

        return

    def __apply_vftable(self, cls, vft, off):
        '''
        Apply the parsed vftable(s) for this class
        '''

        vft_name = generate_vftable_name(self.__classes, vft, cls, off)

        print("Applying vftable: %s" % (vft_name))

        idc.set_name(vft.start_ea, "%s_%x" %
                     (vft_name, vft.start_ea), ida_name.SN_CHECK)

        vftid = ida_struct.add_struc(0, vft_name, 0)

        # this will likely occur if the structure name is already present in the IDB.
        if vftid == idaapi.BADADDR:
            print("Vtable already exists!")
            n = 1  # simply create an indexed struct
            while vftid == idaapi.BADADDR:
                vft_name = "%s_%d" % (vft_name, n)

                vftid = ida_struct.add_struc(0, vft_name, 0)
                n += 1

        vft.id = vftid
        vft.ptr = ida_struct.get_struc(vft.id)

        ida_struct.set_struc_cmt(
            vftid, vft.cls.ida_name + " virtual function table", 1)

        print("VFtable length = %d" % vft.length)

        for vt_index in range(0, vft.length):
            vt_off = vt_index * 4

            # Where the entry points to
            ea = idc.get_wide_dword(vft.start_ea + vt_off)

            # Look up the name in the virtual function table entries.  This only contains
            # functions believed to be defined on the current class, and will probably be
            # removed.
            if vt_index in vft.virtual_functions:
                name = vft.virtual_functions[vt_index].method_name
            else:
                name = self.find_name(ea)
                if name is None:
                    # Last resort: Use whatever name IDA has
                    name = idc.get_func_name(ea)

            # print("Virtual function entry index %d using name %s" % (vt_index, name))

            # Mark the entry as a dword
            ida_bytes.create_data(vft.start_ea + vt_off,
                                  ida_bytes.FF_DWORD, 4, idaapi.BADADDR)

            res = idc.add_struc_member(vft.id,
                                       str(name),
                                       vt_off,
                                       ida_bytes.FF_DWORD,
                                       0xffffffff,
                                       4)
            if res == ida_struct.STRUC_ERROR_MEMBER_NAME:
                name = "%s_%d" % (name, vt_index)
                res = idc.add_struc_member(vft.id,
                                           str(name),
                                           vt_off,
                                           ida_bytes.FF_DWORD,
                                           0xffffffff,
                                           4)

            # Add comment with the original value
            idc.set_member_cmt(vftid, vt_off, ida_hexify(ea), 1)

        # add the vftptr :or rename existing member to vftptr
        vptr_name = "vftptr_0x%s" % ida_hexify(off)

        if idc.get_member_name(cls.id, off) == None:
            # there is no member at this offset
            idc.add_struc_member(cls.id, vptr_name, off,
                                 ida_bytes.FF_DWORD, 0xffffffff, 4)
            idc.set_member_cmt(cls.id, off, vft_name, 1)
        else:
            # There is a member at this offset

            if (idc.get_member_flag(cls.id, off) & ida_bytes.DT_TYPE) != ida_bytes.FF_STRUCT:
                # there is already a member defined at this offset, change it to a vftptr
                # ida_struct.set_member_name(cls.ptr, off, vptr_name)
                idc.set_member_type(
                    cls.id, off, ida_bytes.FF_DWORD, 0xFFFFFFFF, 4)

        # set the vtable name on the global class list
        for c in self.__classes:
            if c.ida_name == cls.ida_name:
                c.vftables[off].vtable_name = vft_name
                break

        return

    def __apply_parent(self, cls, parent, off):
        '''
        Apply the parent classes to the IDB. This may (should) overwrite a virtual function pointer
        '''
        print("Applying parent: %s" % parent.ida_name)

        if parent.id == idaapi.BADADDR:
            self.apply_class(parent)

            # add the variable for the parent
        nbytes = ida_struct.get_struc_size(parent.id)
        name = "parent_%s" % ida_hexify(off)

        print("Parent ID: %s size: %d" % (parent.id, nbytes))

        # apply the parent, deleting any empty members :or vftptrs
        result = idc.add_struc_member(
            cls.id, name, off, ida_bytes.FF_STRUCT | ida_bytes.FF_DATA, parent.id, nbytes)
        if result == ida_struct.STRUC_ERROR_MEMBER_OFFSET:
            idc.del_struc_member(cls.id, off)
            idc.add_struc_member(
                cls.id, name, off, ida_bytes.FF_STRUCT | ida_bytes.FF_DATA, parent.id, nbytes)

        return

    def get_applied_classes(self):
        '''
        Return a list of classes that have been applied
        '''
        return [cls for name, cls in self.__applied_classes.items()]

    def apply_all_structs(self):
        '''
        Apply the parsed classes. The basic algorithm is to iteratively apply
        structs for classes without parents. Eventually all structs will have
        their parents applied
        '''

        print("OOAnalyzer has %d classes to apply:" % len(self.__classes))

        for c in self.__classes:
            if c.demangled_name != "":
                print("   * %s (Demangled name: %s)" %
                      (c.name, c.demangled_name))
            else:
                print("   * %s" % (c.name))

        worklist_count = len(self.__classes)
        # while all classes are not complete

        while worklist_count > 0:

            # idaapi.show_wait_box("Applying class %s ..." % c.demangled_name)

            for c in self.__classes:

                # Has this class been applied
                if c.applied == True:
                    continue

                do_apply = True
                missing_member = ""

                # if this class has members, check for sub classes
                if c.members:
                    for o, m in c.members.items():

                        if m == None:
                            continue
                        if m.member_type == ida_bytes.FF_STRUCT:

                            if m.class_member == None:
                                continue

                            if m.class_member.ida_name not in self.__applied_classes:
                                # don't apply members with structs that are not yet applied
                                do_apply = False
                                missing_member = m.class_member.ida_name
                                break

                if do_apply:
                    print("Applying class '%s'" % c.ida_name)
                    self.apply_class(c)
                    c.applied = True
                    worklist_count -= 1

                else:
                    print("Delaying application of class '%s' because cannot find member class '%s'" % (
                        c.ida_name, missing_member))

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

    OP_REG = ida_ua.o_reg     # 1
    OP_MEM_REF = ida_ua.o_mem     # 2
    OP_REG_INDEX = ida_ua.o_phrase  # 3
    OP_REG_INDEX_DISP = ida_ua.o_displ   # 4
    OP_IMMEDIATE = ida_ua.o_imm     # 5

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
        print("================================================")
        for t in self.__targets:
            print("Applying virtual function call %x -> %x" %
                  (self.__call_ea, t))

            ida_xref.add_cref(self.__call_ea, t,
                              ida_xref.XREF_USER | ida_xref.fl_F)

            cmt = idc.GetCommentEx(self.__call_ea, 0)
            if cmt != None:
                cmt = cmt + ", %s" % ida_hexify(t)
                print("Multiple virtual function calls detected at %x (%s)" %
                      (self.__call_ea, cmt))

            else:
                cmt = "%s" % ida_hexify(t)

            idc.set_cmt(self.__call_ea, cmt, 0)

        print("================================================")

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
        self.__cid = idaapi.BADADDR

        return

    def apply(self):
        '''
        Apply a usage
        '''

        if self.__ida_name is None:
            return False

        if self.__cid == idaapi.BADADDR:
            print("*** Cannot apply because bad ID")
            return False

        print("================================================")
        print("Applying class %s to %x" % (self.__ida_name, self.__ea))
        print("================================================")

        # there must be two and only two operands, assume 1 and check for 2
        n = 0
        if idc.get_operand_type(self.__ea, 1) in [self.OP_REG_INDEX, self.OP_REG_INDEX_DISP]:
            n = 1

        idc.op_stroff(self.__ea, n, self.__cid, 0)

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

    call_ea = property(get_call_ea, set_call_ea,
                       del_call_ea, "call_ea's docstring")
    cls = property(get_cls, set_cls, del_cls, "class_name's docstring")
    vf_offset = property(get_vf_offset, set_vf_offset,
                         del_vf_offset, "vf_offset's docstring")

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

    def get_best_method_name(self):
        if self.demangled_name is not None:
            s = self.demangled_name
            return re.sub(r'^.*?::', '', s)
        else:
            return self.method_name

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

        self.__id = idaapi.BADADDR

        return

    def __str__(self):
        t = "Vftable  %s @ %x\n" % (self.__vtable_name, self.__vftable_ea)
        for k, v in self.__vfuncs.items():
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

    def __init__(self, cls, mem_type, size):
        '''
        initialize class member
        '''

        self.__cls = cls
        self.__type_size = size
        self.set_type(mem_type, size)

        self.__member_name = None
        self.__class_mem = None

        self.__id = idaapi.BADADDR

        self.__is_parent = False

        self.__is_vftptr = False

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

    def get_cls(self):
        return self.__cls

    def get_class_member(self):
        return self.__class_mem

    def set_class_member(self, value):
        self.__class_mem = value
        if self.__type_size == None and self.__class_mem != None:
            # ida_struct.get_struc_size(idc.GetStrucIdByName(self.value))
            self.__type_size = self.__class_mem.size()

        return

    def set_member_name(self, value):
        self.__member_name = value
        return

    def get_type_size(self):
        return self.__type_size

    def set_type(self, value, size):
        '''
        the ID for the struct member_type must be supplied
        the member_type can either by primitive :or a structure. If it is a struct :or
        string, then size is required
        '''

        if value == 'vftptr':
            self.__is_vftptr = True
            self.__type = ida_bytes.FF_DWORD

        elif value == 'struc':
            self.__type = ida_bytes.FF_STRUCT

        elif value == '':
            d = {1: ida_bytes.FF_BYTE,
                 2: ida_bytes.FF_WORD,
                 4: ida_bytes.FF_DWORD}
            self.__type = d.get(size, None)
            if self.__type is None:
                # XXX: We should really have a marker here so that in apply_member we create a
                # dummy type of the appropriate size.
                print("WARNING: Unknown type for size %d" % size)
                self.__type = ida_bytes.FF_BYTE
        else:
            print("WARNING: Unknown type %s" % value)
            assert (False)

        return

    def set_cls(self, value):
        self.__cls = value

    def set_id(self, value):
        self.__id = value
        return

    def set_isvftptr(self, value):
        self.__is_vftptr = value
        return

    def get_isvftptr(self):
        return self.__is_vftptr

    def get_id(self):
        return self.__id

    def get_size(self):
        return self.__size

    def set_size(self, value):
        self.__size = value
        return

    def get_isparent(self):
        return self.__is_parent

    def set_isparent(self, value):
        self.__is_parent = value

    def get_member_offset(self):
        return self.__offset

    def set_member_offset(self, value):
        self.__offset = value

    # Properties for class members

    member_name = property(get_member_name, set_member_name, None, None)
    is_parent = property(get_isparent, set_isparent, None, None)
    is_vftptr = property(get_isvftptr, set_isvftptr, None, None)
    member_type = property(get_type, set_type, None, None)
    class_member = property(get_class_member, set_class_member, None, None)
    cls = property(get_cls, set_cls, None, None)
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

        self.__id = idaapi.BADADDR   # This is set when applied

        self.__applied = False

        self.__size = struc_def['size']

        self.__demangled_name = struc_def['demangled_name']

        self.__name = struc_def['name']

        # set the IDA name
        self.__ida_name = sanitize_name(self.__name)

        if self.__demangled_name != "":
            self.__ida_name = sanitize_name(self.__demangled_name)

        return

    def __eq__(self, other):
        if other == None:
            return False
        return self.__id == other.__id and self.__name == other.__name

    def __str__(self):
        '''
        String representation of C++ class
        '''
        folks = ""
        for o, p in self.__parents.items():
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

    def get_best_name(self):
        dn = self.get_demangled_name()
        if dn is not None and dn != "":
            return dn
        else:
            return self.get_name()

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

    def add_vftable(self, vft, vftptr):
        self.__vftables[vftptr] = vft
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

    def set_size(self, value):
        self.__size = value
        return

    def get_usages(self):
        return self.__vfcalls

    def set_usages(self, value):
        self.__vfcalls = value

    def get_vfcalls(self):
        return self.__vfcalls

    def set_vfcalls(self, value):
        self.__vfcalls = value

    # Properties of class structures

    demangled_name = property(
        get_demangled_name, set_demangled_name, None, None)
    ida_name = property(get_ida_name, set_ida_name, None, None)
    name = property(get_name, set_name, None, None)
    members = property(get_members, None, None, None)
    methods = property(get_methods, None, None, None)
    vftables = property(get_vftables, set_vftables, None, None)
    parents = property(get_parents, None, None, None)
    id = property(get_id, set_id, None, None)
    size = property(get_size, set_size, None, None)
    applied = property(get_applied, set_applied, None, None)
    usages = property(get_usages, set_usages, None, None)
    vfcalls = property(get_vfcalls, set_vfcalls, None, None)

# =============================================================================
# End class


class PyOOAnalyzerMethodTreeItem(QTreeWidgetItem):
    '''
    This is a method element in the class viewer tree
    '''

    def __init__(self, parent, meth):

        super(PyOOAnalyzerMethodTreeItem, self).__init__(parent)
        self.method = meth
        self.setText(0, self.method.get_best_method_name())


class PyOOAnalyzerMemberTreeItem(QTreeWidgetItem):
    '''
    This is a member element in the class viewer tree
    '''

    def __init__(self, parent, mem=None):

        super(PyOOAnalyzerMemberTreeItem, self).__init__(parent)
        self.member = mem
        self.setText(0, self.member.member_name)


class PyOOAnalyzerStructTreeItem(QTreeWidgetItem):
    '''
    This is a class element in the class viewer tree
    '''

    def __init__(self, parent, cls=None):

        super(PyOOAnalyzerStructTreeItem, self).__init__(parent)
        self.class_struct = cls
        self.setText(0, self.class_struct.get_best_name())


class PyOOAnalyzerExpForm(idaapi.PluginForm):
    '''
    This is the main class viewer form.
    '''

    def __init__(self):

        super(PyOOAnalyzerExpForm, self).__init__()

        self.__ooanalyzer = None

        self.cls_tree = None
        self.idbhook = None
        self.idphook = None
        self.__node = Netnode("$ cert.ooanalyzer")

        # the name of the IDA netnode that contains class information
        self.__NODE_NAME = "$OBJD"

        self.__visible = False

        return

    def start_ida_hooks(self):

        if self.idbhook == None:
            self.idbhook = PyOOAnalyzerIDBHooks(self.__ooanalyzer, self)
            self.idbhook.hook()

        if self.idphook == None:
            self.idphook = PyOOAnalyzerIDPHooks(self.__ooanalyzer, self)
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

        cls_list = self.__ooanalyzer.get_classes()
        for cls in cls_list:
            cls_entry = PyOOAnalyzerStructTreeItem(self.cls_tree, cls)

            cls_methods = QTreeWidgetItem(cls_entry)
            cls_methods.setText(0, "Methods")

            for m in cls.methods:
                PyOOAnalyzerMethodTreeItem(cls_methods, m)

            cls_members = QTreeWidgetItem(cls_entry)
            cls_members.setText(0, "Members")

            for off, mbr in cls.members.items():
                if mbr.is_parent == False:
                    PyOOAnalyzerMemberTreeItem(cls_members, mbr)

            if len(cls.parents) > 0:
                cls_parents = QTreeWidgetItem(cls_entry)
                cls_parents.setText(0, "Parents")
                for o, p in cls.parents.items():
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
                        meth_group = item.child(0)  # should be methods
                        if meth_group != None:
                            if meth_group.text(0) == "Methods":

                                i = 0
                                while i < meth_group.childCount():
                                    meth_item = meth_group.child(i)
                                    if meth_item:

                                        if type(meth_item) is PyOOAnalyzerMethodTreeItem:
                                            if meth_item.text(0) == old_name:
                                                meth_item.setText(0, new_name)
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
                        mbr_group = item.child(1)  # should be members
                        if mbr_group != None:

                            if mbr_group.text(0) == "Members":
                                i = 0
                                while i < mbr_group.childCount():
                                    mem_item = mbr_group.child(i)
                                    if mem_item:
                                        if type(mem_item) is PyOOAnalyzerMemberTreeItem:
                                            if mem_item.text(0) == old_name:
                                                mem_item.setText(0, new_name)
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
                    par_group = item.child(3)  # should be members
                    if par_group != None:
                        if par_group.text(0) == "Parents":
                            i = 0
                            while i < par_group.childCount():
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
        new_member_name = ida_kernwin.ask_str(
            old_member_name, 0, "Enter new member name")

        if new_member_name == None:
            self.cls_tree.blockSignals(False)
            return

        # cid = ida_struct.get_struc_id(member.member_name
        cls_members = idautils.StructMembers(member.cls.id)

        for [off, n, s] in cls_members:
            if n == member.member_name:

                if idc.set_member_name(member.cls.id, off, str(new_member_name)) != 0:
                    item.setText(0, str(new_member_name))

                    cls_list = self.__ooanalyzer.get_classes()
                    for c in cls_list:
                        for moff, mem in c.members.items():
                            if mem.member_name == old_member_name:
                                mem.member_name = new_member_name
                else:
                    ida_kernwin.warning(
                        "Cannot rename member to %s, the name already exists or is malformed!" % new_member_name)

        return

    def __edit_method_from_class_viewer(self, item):
        '''
        Handle method change request initiated from Class Viewer
        '''
        method = item.method
        old_method_name = method.method_name
        new_method_name = ida_kernwin.ask_str(
            old_method_name, 0, "Enter new method name")

        if new_method_name == None:
            self.cls_tree.blockSignals(False)
            return

        cls = item.parent().parent().class_struct

        m = next(m for m in cls.methods if m.start_ea == method.start_ea)
        m.method_name = new_method_name
        m.userdef_name = True
        # Rename the function
        self.__ooanalyzer.apply_method(m)
        item.setText(0, m.get_best_method_name())

        # XXX: Rename all vftable structures.
        # # the method is a virtual function
        # if m.is_virtual == True:
        #     cmt = "virtual %s" % cmt

        #     # rename virtual function in vftable structure
        #     for off, vt in c.vftables.items():
        #         for vfoff, vf in vt.virtual_functions.items():
        #             if vf.start_ea == m.start_ea:

        #                 global ignore_renamed
        #                 ignore_renamed = True
        #                 idc.set_member_name(
        #                     vt.id, 4*vfoff, new_method_name)
        #                 ignore_renamed = False

        #                 vf.method_name = new_method_name
        #                 break

        return

    def __edit_class_from_class_viewer(self, item):
        '''
        Handle class name change request initiated from Class Viewer
        '''

        old_name = item.class_struct.ida_name
        cid = idaapi.get_struc_id(str(old_name))

        if (cid is not None) and (cid != 0) and (cid != idaapi.BADADDR):

            new_name = ida_kernwin.ask_str(
                old_name, 0, "Enter new class name:")

            if new_name == None:
                self.cls_tree.blockSignals(False)
                return

            if ida_struct.set_struc_name(cid, new_name) != 0:
                item.setText(0, str(new_name))

                cls_list = self.__ooanalyzer.get_classes()
                for c in cls_list:
                    if c.ida_name == old_name:
                        c.ida_name = new_name

            else:
                ida_kernwin.warning(
                    "Cannot rename class to %s, the name already exists!" % new_name)
        else:
            ida_kernwin.warning("Cannot rename class before it is applied")

        return

    def edit_class_item(self, event):

        self.cls_tree.blockSignals(True)

        item = self.cls_tree.currentItem()

        if type(item) is PyOOAnalyzerMemberTreeItem:
            self.__edit_member_from_class_viewer(item)

        elif type(item) is PyOOAnalyzerMethodTreeItem:
            self.__edit_method_from_class_viewer(item)

        elif type(item) is PyOOAnalyzerStructTreeItem:
            self.__edit_class_from_class_viewer(item)

        self.cls_tree.blockSignals(False)

    def OnCreate(self, form):

        # Get parent widget

        self.parent = self.FormToPyQtWidget(form)

        # Create cls_tree control
        self.cls_tree = QTreeWidget()
        headerItem = QTreeWidgetItem()
        headerItem.setText(0, "Class")
        headerItem.setText(1, "State")

        self.cls_tree.setHeaderItem(headerItem)
        self.cls_tree.setWindowTitle("OOAnalzyer Results")
        self.cls_tree.setColumnWidth(0, 200)

        self.cls_tree.itemSelectionChanged.connect(
            lambda: self.navigate(self.cls_tree.currentItem()))

        # install the context menu
        self.cls_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.cls_tree.customContextMenuRequested.connect(self.open_menu)

        # Create layout
        layout = QVBoxLayout()
        layout.addWidget(self.cls_tree)

        self.populate_class_list()
        # Populate PluginForm
        self.parent.setLayout(layout)

        applied_cls = self.__ooanalyzer.get_applied_classes()
        for c in applied_cls:
            self.__mark_applied(c)

        return

    def open_menu(self, position):

        menu = QMenu()

        # can only apply classes
        applyAction = None
        gotoDefAction = None
        renameAction = None

        item = self.cls_tree.currentItem()
        if type(item) is PyOOAnalyzerStructTreeItem:
            cls = item.class_struct
            if cls.applied:
                gotoDefAction = menu.addAction("Open Definition")
                renameAction = menu.addAction("Rename")
            else:
                applyAction = menu.addAction("Apply")
        elif type(item) is PyOOAnalyzerMethodTreeItem:
            if item.method.cls.applied:
                renameAction = menu.addAction("Rename")
        elif type(item) is PyOOAnalyzerMemberTreeItem:
            if item.member.cls.applied:
                renameAction = menu.addAction("Rename")

        action = menu.exec_(QCursor.pos())

        if applyAction is not None and action == applyAction:
            self.apply_action()
        elif gotoDefAction is not None and action == gotoDefAction:
            self.goto_def_action()
        elif renameAction is not None and action == renameAction:
            self.rename_action()

        return

    def apply_class_item(self, item):
        '''
        Apply a class
        '''
        if type(item) is PyOOAnalyzerStructTreeItem:

            applied_classes = self.__ooanalyzer.get_applied_classes()

            if self.__ooanalyzer.apply_struct(item.class_struct):

                new_applied_classes = self.__ooanalyzer.get_applied_classes()

                # mark all the newly applied classes
                delta = [
                    x for x in new_applied_classes if x not in applied_classes]

                for c in delta:
                    self.__mark_applied(c)
        else:
            print("Not applying because not struct")

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
                    cur_item.setBackground(
                        0, QBrush(Qt.green, Qt.Dense7Pattern))
                    font = cur_item.font(0)
                    font.setBold(True)
                    cur_item.setFont(0, font)
                    cur_item.setText(1, "Applied")

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
            ida_kernwin.open_structs_window(item.class_struct.id)
        else:
            ida_kernwin.warning(
                "You must apply class '%s' before you can open its definition" % item.class_struct.ida_name)

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
               
        self.__node[OOA_JSON] = self.__ooanalyzer.get_json_data()
        self.__node[APPLIED_CLASS_NAMES] = [
            cls.ida_name for cls in self.__ooanalyzer.get_applied_classes()]

        return

    def __load_from_idb(self):
        '''
        Load previously applied JSON
        '''

        if OOA_JSON in self.__node and APPLIED_CLASS_NAMES in self.__node:
            return [self.__node[OOA_JSON], self.__node[APPLIED_CLASS_NAMES]]
        elif OOA_JSON in self.__node:
            return [self.__node[OOA_JSON], None]
        elif APPLIED_CLASS_NAMES in self.__node:
            return [None, self.__node[APPLIED_CLASS_NAMES]]

        return [None, None]

    def __load_from_json_file(self, json_file):
        '''
        Parse the JSON file
        '''
        if json_file != None:

            if self.__ooanalyzer.set_json_file(json_file):
                print("Opened JSON file %s" % json_file)
            else:
                ida_kernwin.warning("Could not open %s" % json_file)
                return None, 0, 0, 0

        if self.__ooanalyzer.is_parsed() == False:  # not parsed yet
            result, msg = self.__ooanalyzer.parse()
            print("Parsed %s %s" % (result, msg))
            if result == False:
                ida_kernwin.warning("Could not parse JSON: %s" % msg)
                return None, 0, 0, 0

        parse_results = self.__ooanalyzer.get_parse_results()
        if parse_results == None:
            return None, 0, 0, 0

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
""" % (self.__ooanalyzer.get_json_filename(), num_classes, num_usages, num_vcalls)

        return res_str, num_classes, num_vcalls, num_usages

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

        [json, applied_classes] = self.__load_from_idb()
        if json:
            print("OOAnalyzer class information found in IDB, opening Class Viewer")
          
            # mark previously applied classes
            self.__ooanalyzer = PyOOAnalyzer()
            self.__ooanalyzer.set_json_data(json)
            self.__ooanalyzer.parse()
            if applied_classes:

                # Find the intersection
                intersection = [
                    c for c in self.__ooanalyzer.get_classes() if c.ida_name in applied_classes]

                for c in intersection:
                    self.__ooanalyzer.apply_class(c)

        else:

            # load the class spec from a JSON file

            json_file = ida_kernwin.ask_file(
                0, "*.json", "Open JSON C++ specification file")
            if not json_file:
                return False

            self.__ooanalyzer = PyOOAnalyzer()

            # if everything applies OK, then show the form
            parse_results, nc, nvc, nu = self.__load_from_json_file(json_file)

            if parse_results != None:
                form_msg = """CERT OOAnalyzer v%.1f
%s
""" % (PLUGIN_VERSION, parse_results)

                do_apply = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, form_msg)

                if do_apply == ida_kernwin.ASKBTN_YES:  # yes
                    print("Applying all results")

                    self.__ooanalyzer.apply_all_structs()

                # apply virtual function calls for yes or no
                if do_apply == ida_kernwin.ASKBTN_YES or do_apply == ida_kernwin.ASKBTN_NO:
                    print("Applying virtual function calls")
                    self.__ooanalyzer.apply_vfcalls()
                    print("Applied virtual function calls")

                else:  # cancel
                    print("User cancelled.  Not applying anything")
                    return False

            else:
                # ida_kernwin.warning(
                #     "No C++ data structures found in '%s'" % json_file)
                return False

        return True

    def Show(self):

        if not self.__visible:
            setup_form = False
            try:
                setup_form = self.__setup_form
            except Exception as e:
                ida_kernwin.warning("An exception occurred: %s" % e)
            if self.__setup_form():

                if self.idbhook == None and self.idphook == None:
                    self.start_ida_hooks()

                self.__visible = True
                return idaapi.PluginForm.Show(self, "OOAnalyzer Class Viewer", options=idaapi.PluginForm.WOPN_PERSIST)
            else:
                return -1

    def is_visible(self):
        return self.__visible


class PyOOAnalyzerIDPHooks(ida_idp.IDP_Hooks):

    def __init__(self, objd, frm):

        ida_idp.IDP_Hooks.__init__(self)

        self.__ooanalyzer = objd
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
        if ignore_renamed:
            return ida_idp.IDP_Hooks.renamed(self, ea, new_name, local_name)

        # a function has been renamed
        if idc.get_func_name(ea) != "":
            cls_model = self.__ooanalyzer.get_classes()
            for c in cls_model:
                for m in c.methods:
                    if m.start_ea == ea:

                        self.__form.update_class_method(
                            c.id, m.method_name, new_name)
                        m.method_name = new_name

                        if m.is_virtual:

                            # rename function name in vftable structure
                            for off, vt in c.vftables.items():
                                for vfoff, vf in vt.virtual_functions.items():

                                    if vf.start_ea == m.start_ea:

                                        ignore_renamed = True
                                        idc.set_member_name(
                                            vt.id, 4*vfoff, new_name)

                                        ignore_renamed = False

                                        vf.method_name = new_name
                                        break

                        return ida_idp.IDP_Hooks.renamed(self, ea, new_name, local_name)

        return ida_idp.IDP_Hooks.renamed(self, ea, new_name, local_name)


class PyOOAnalyzerIDBHooks(idaapi.IDB_Hooks):

    def __init__(self, objd, frm):

        self.form = frm
        self.__ooanalyzer = objd

        idaapi.IDB_Hooks.__init__(self)

    def struc_member_renamed(self, *args):
        '''
        A structure member has been renamed
        '''
        global ignore_renamed
        if ignore_renamed:
            return 0

        struc = args[0]
        mbr = args[1]

        class_model = self.__ooanalyzer.get_classes()
        for c in class_model:
            if c.id == struc.id:

                changed_name = idc.get_member_name(c.id, int(mbr.soff))

                for off, m in c.members.items():
                    if off == mbr.soff:
                        if m:
                            self.form.update_class_member(
                                c.id, m.member_name, changed_name)
                            m.member_name = changed_name
                            return 0

        # Update virtual functions if they are changed
        for c in class_model:
            for off, vt in c.vftables.items():
                if struc.id == vt.id:

                    changed_name = idc.get_member_name(vt.id, int(mbr.soff))

                    for vfoff, vf in vt.virtual_functions.items():

                        # this has to be scaled
                        if (vfoff*4) == mbr.soff:
                            if vt:
                                self.form.update_class_method(
                                    c.id, vf.method_name, changed_name)
                                vf.method_name = changed_name

                                ignore_renamed = True
                                idc.set_name(
                                    vf.start_ea, changed_name, ida_name.SN_CHECK)
                                ignore_renamed = False

                                return 0
        return 0

    def struc_renamed(self, *args):
        '''
        A structure was renamed in the IDB
        '''
        renamed_struc = args[0]

        class_model = self.__ooanalyzer.get_classes()
        for c in class_model:
            if c.id == renamed_struc.id:

                new_name = ida_struct.get_struc_name(renamed_struc.id)
                if new_name != None:

                    self.form.update_class(c.ida_name, new_name)

                    c.ida_name = new_name
                    for off, m in c.members.items():
                        m.ida_name = new_name

                    for mtd in c.methods:
                        cmt = "%s::%s" % (c.ida_name, mtd.method_name)
                        if mtd.is_virtual == True:
                            cmt = "virtual %s" % cmt
                        if mtd.is_ctor == True:
                            cmt += " (constructor)"
                        if mtd.is_dtor == True:
                            cmt += " (destructor)"
                        idc.set_func_cmt(mtd.start_ea, cmt, 1)

                    for off, v in c.vftables.items():
                        v.cls.ida_name = new_name

                        new_vft_name = generate_vftable_name(
                            self.__ooanalyzer.get_classes(), v, c, off)

                        idc.set_name(v.start_ea, "%s_%x" % (
                            new_vft_name, v.start_ea), ida_name.SN_CHECK)
                        ida_struct.set_struc_name(v.id, new_vft_name)
                        ida_struct.set_struc_cmt(
                            v.id, v.cls.ida_name + " virtual function table", 1)

                    break

        return 0

# =============================================================================
# This is the entry point for the plugin


class PyOOAnalyzer_plugin(idaapi.plugin_t):
    '''
    Main plugin class
    '''

    flags = idaapi.PLUGIN_UNL

    comment = "IDA OOAnalyzer plugin"
    help = "Email jsg@cert.org"
    wanted_name = "OOAnalyzer"
    wanted_hotkey = "F3"

    def init(self):
        '''
        Create the Plugin
        '''

        return idaapi.PLUGIN_OK

    def run(self, arg):
        '''
        Run the plugin
        '''

        try:
            # is the Class Viewer already open?
            class_viewer = ida_kernwin.find_widget("OOAnalyzer Class Viewer")
            if class_viewer != None:
                ida_kernwin.warning(
                    "OOAnalyzer class information has already been imported")
                return

            global clsExpForm
            global ignore_renamed

            ignore_renamed = False
            clsExpForm = None

            print("\n\nOOAnalyzer Plugin version %s loaded" % PLUGIN_VERSION)

            if clsExpForm is None:
                clsExpForm = PyOOAnalyzerExpForm()
                clsExpForm.Show()

            idaapi.set_dock_pos('OOAnalyzer Class Viewer',
                                'Functions window', idaapi.DP_BOTTOM)
        except Exception as e:
            traceback.print_exc()
            print(e)

        return

    def term(self):
        print("OOAnalyzer Plugin version %s done importing" % PLUGIN_VERSION)
        return


def PLUGIN_ENTRY():
    try:
        return PyOOAnalyzer_plugin()
    except Exception as e:
        traceback.print_exc()
        print(e)
    return None

# Local Variables:
# mode: python
# fill-column: 95
# comment-column: 0
# python-indent-offset: 4
# End:
