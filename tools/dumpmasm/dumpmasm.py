#!/usr/bin/env python

# This script dumps data from IDA in approximately the same format as
# dumpmasm.  That format is:
#
#   "PART",address,category,function,bytes,mnemonic,operands
#
# Where address is the address of the "head", and function is the
# address of the function that the address is assigned to.  An address
# can be assigned to more than one function, in which case there will
# be multiple lines for the address.  Category is eitehr "INSN" or
# "DATA".  The IDA implementation adds some types for error signaling.
# Bytes is a hexadecimal encoding of the bytes of the instruction or
# data element.  The mnemonic is the instruction mnemonic or "db" for
# the data category.  Operands is the assembly representation of the
# operands in some arbitrary format.
#
# A newly added record type is:
#
#   "FLOW",source,destination,type
#
# This record is not currently supported by this script.  Each line
# represents control flow from one instruction to another, with source
# being the address of the source instruction.  Destination is the
# address of the destination instruction, or the value "UNKNOWN" if
# the flow is to an indeterminate location.  Implementations ahould be
# as complete as possible, reporting "UNKNOWN" when there are control
# flow edges that are not reported.  The type field is one of
# "FALLTHRU", "BRANCH", "CALL", "CALL_FALL", "NOT_TAKEN", and
# "RETURN".

# The script can be invoke like this:
#
#   ida -A -OIDAPython:dumpmasm.py input_file
#
# or this:
#
#   for f in *; do echo $f ; idaq_batch -A -OIDAPython:~/dumpmasm.py $f; done

import ida_idaapi
import ida_nalt
import ida_idp
import ida_ua
import ida_pro
import ida_bytes
import ida_auto
import ida_lines

import idautils

import binascii
import os

def build_a2fmap():
    a2fmap = {}

    print "Generating address to functon map..."
    min_ea = idaapi.cvar.inf.minEA
    max_ea = idaapi.cvar.inf.maxEA
    for fea in idautils.Functions(min_ea, max_ea):
        ida_auto.show_addr(fea)
        for (startea, endea) in idautils.Chunks(fea):
            for addr in range(startea, endea):
                if addr in a2fmap:
                    a2fmap[addr].append(fea)
                else:
                    a2fmap[addr] = [fea]
    print "Address to function map generation complete!"
    return a2fmap

def dump_heads(out):
    # out is a file like object, sys.stdout or an acual file object

    # There doesn't seem to a good way to determine what function a
    # particular address is in.  Almost everyone recommends iterating
    # of the functions, and then getting the bytes out of each, but
    # that's not really what we want because it skips non function
    # bytes and reports them in the wrong order. It appears that the
    # best we can do is to build a map in advance. :-(
    a2fmap = build_a2fmap()

    min_ea = idaapi.cvar.inf.minEA
    max_ea = idaapi.cvar.inf.maxEA
    ea = min_ea
    while ea != ida_idaapi.BADADDR:
        ida_auto.show_addr(ea)
        isize = ida_bytes.get_item_size(ea)
        ibytes = ida_bytes.get_bytes(ea, isize)
        ihexbytes = binascii.b2a_hex(ibytes).upper()
        iflags = ida_bytes.get_flags(ea)

        # Skip the PE header?
        if not ida_bytes.is_head(iflags):
            ea = ida_bytes.next_head(ea, max_ea)
            continue

        # Loop up this address in the address-to-function map.
        if ea in a2fmap:
            faddrs = a2fmap[ea]
        else:
            faddrs = [ea]

        tcode = "ERROR"
        imnem = "???"
        iops = "???"

        if ida_bytes.is_code(iflags):
            tcode = "INSN"
            imnem = "???"
            iops = "???"

            insn = idautils.DecodeInstruction(ea)
            if insn == None:
                imnem = "BAD"
                iops = ""
            elif not insn.is_canon_insn():
                imnem = "NCAN"
                iops = ""
            else:
                imnem = insn.get_canon_mnem()

                sops = []
                for n in range(8):
                    ostr = ida_ua.print_operand(ea, n)
                    if ostr is not None:
                        ostrnt = ida_lines.tag_remove(ostr)
                        if ostrnt != '':
                            sops.append(ostrnt)
                iops = ', '.join(sops)

        elif ida_bytes.is_data(iflags):
            tcode = "DATA"
            imnem = "db"
            iops = "???"
            if ida_bytes.is_align(iflags):
                tcode += "_ALIGN"
            #elif ida_bytes.is_struct(iflags):
            #    tcode += "_STRUCT"
            #elif ida_bytes.is_char(iflags):
            #    tcode += "_STR"
            # There are other types that IDA recognizes.
        elif ida_bytes.is_unknown(iflags):
            tcode = "UNK-%08X" % iflags
            imnem = "???"
            iops = "???"

        for faddr in sorted(faddrs):
            out.write('"PART",0x%08X,"%s",0x%08X,"%s","%s","%s"\n' % (
                ea, tcode, faddr, ihexbytes, imnem, iops))
        ea = ida_bytes.next_head(ea, max_ea)
    print "Analysis complete!"

outname = None
if True:
    fhash = idautils.GetInputFileMD5()
    if fhash is not None:
        fhash = fhash.lower()
        outname = "/tmp/%s_idadata.csv" % fhash

if outname == None:
    # Get the file name of the file being analyzed.
    fpath = ida_nalt.get_input_file_path()
    fname = os.path.basename(fpath)
    outname = "/tmp/%s_idadata.csv" % fname

print "The output filename is '%s'." % outname
outfile = open(outname, 'w')

ida_auto.auto_wait()
dump_heads(outfile)
outfile.close()

# Uncomment if you want IDA to exit after the script completes:
#ida_pro.qexit(0)
