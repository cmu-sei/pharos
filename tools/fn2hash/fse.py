#!/usr/bin/env python3
#
# Copyright 2017, Carngegie Mellon University
#
# fse.py - Function Set Extraction, a variant of the old uberflirt function
# set intersection script specifically for fn2hash csv data, as well as
# exploring new hash types and incorporating new statistical analysis and
# graphical visualizations over time...
#
# And if/when fn2hash gets database support this will be expanded to handle
# that as well.
#

import os
import sys
import logging
import operator
import re
import csv
import collections
import math

from optparse import OptionParser

###########################################################################
#
# some global vars, yes, evil, I know...
#
###########################################################################
__version__ = "0.1"

hashtypes = "EXACT,PIC,CPIC,MNEM,MCNT,MCAT,MCCNT".split(",")
#defaulthash = "CPIC" # CPIC may be slightly broken right now, so PIC for now
defaulthash = "PIC" # and actually...PIC may have some minor issues occasionally too???  Need to investigate...

file2fn = {}
fn2file = {}
blacklist = set()
numblacklisted = 0
fninfo = {}

maxinstwidth = 0
maxbyteswidth = 0
maxaddrwidth = 0
maxhashwidth = 0

###########################################################################
#
# set up some logging functions
#
###########################################################################

logging.basicConfig(level=logging.WARNING,
                    #filename="/tmp/fn2hash_fs_log.txt", # uncomment, overrides stream setting
                    format='%(asctime)s [%(levelname)s] %(message)s',
                    stream=sys.stderr)
logger = logging.getLogger('FSE')

def setQuiet():
    logger.setLevel(logging.ERROR)

def setVerbose():
    logger.setLevel(logging.INFO)

def setDebug():
    logger.setLevel(logging.DEBUG)

###########################################################################
#
# a Table class, to help print the data in various ways (and not clutter
# the rest of the code with stupid formatting crap, like the old stuff was)
#
###########################################################################

#ColDef = collections.namedtuple('coldef','name, width, align')
# really just using width right now:
ColDef = collections.namedtuple('coldef','width')

class Table:
    def __init__(self,sepchar='|',sepcount=1):
        # list of named tuples:
        self.cols = []
        # list of lists:
        self.headers = []
        # list of lists:
        self.rows = []

        self.sepchar = sepchar
        self.sepcount = sepcount

    def add_column(self, coldef):
        """adds ColDef named tuple (name, width, align)"""
        self.cols.append(coldef)

    def add_header_row(self, hdrs):
        """iterable of header text, can have multiple headers (for 'easy' printing of vertical text)"""
        if len(hdrs) != len(self.cols):
            logger.error("header data wrong length: %s"%(hdrs))
        else:
            self.headers.append(hdrs)

    def add_row(self, rowdat):
        """iterable of row data, better be same length as number of columns"""
        if len(rowdat) != len(self.cols):
            logger.error("row data wrong length: %s"%(rowdat))
        else:
            self.rows.append(rowdat)

    def fmt_data_for_col(self,dat,col):
        dat = dat if dat is not None else ' '
        cstr = "%*s"%(self.cols[col].width,str(dat))
        if self.sepcount and self.sepchar and (col+1) % self.sepcount == 0:
            cstr += self.sepchar
        return cstr

    def __str__(self):
        """converts table to string"""
        rcstr = ""
        if len(self.headers):
            for hdr in self.headers:
                for i in range(len(hdr)):
                    rcstr += self.fmt_data_for_col(hdr[i],i)
                rcstr += '\n'
            for i in range(len(self.cols)):
                rcstr += self.fmt_data_for_col('-'*self.cols[i].width,i)
            rcstr += '\n'
        # and now the rows:
        for row in self.rows:
            for i in range(len(row)):
                rcstr += self.fmt_data_for_col(row[i],i)
            rcstr += '\n'
        return rcstr


###########################################################################
#
# other utility functions
#
###########################################################################

def read_config(args):
    global hashtypes
    global defaulthash

    # setup the cmd line parameters (matches possible contents of config file):
    usage="Usage: %prog [options] <fn2hash csv data file(s)>"
    version="%prog version " + __version__
    epilog="%prog is used to compare functions amongst 2 or more files from fn2hash data file(s) provided"
    parser = OptionParser(usage=usage,version=version,epilog=epilog)
    parser.add_option("-v", "--verbose", help="verbose logging (info and above)", action="store_true", dest="verbose", default=False)
    parser.add_option("-d", "--debug", help="debug logging", action="store_true", dest="debug", default=False)
    parser.add_option("-q", "--quiet", help="quiet logging (errors & above)", action="store_true", dest="quiet", default=False)

    parser.add_option("-m", "--minlen", help="minimum length (bytes) of function to consider (default %default)", type="int", dest="minlen", default=1)
    parser.add_option("-i", "--instructions", help="minimum length (instructions) of function to consider (default %default)", type="int", dest="mininstructions", default=1)
    parser.add_option("-t", "--function-threshold", help="minimum number of files to appear in to show a function in the text matrix output (default %default)", type="int", dest="fn_threshold", default=0)
    # do we also need an upper threashold as well to filter out functions that appear in all files in the set?

    # no names in the csv yet, but maybe when we get to the db portion a
    # variant of this filtering will be needed (more likely to be on some
    # cleanware flag than a name though).
    #parser.add_option("-n", "--exclude-name", help="regexp values to filter out functions that have names that match, can specify multiple times (default: %default)", action="append", type="string", dest="exclude_names", default=[r'^_.*',r'^\?.*',r'^unknown_libname.*',r'^j_.*',r'^\$LN.*'])
    # for now, can specify csv files w/ funcs to skip:
    parser.add_option("-X", "--blacklist", help="specify a file filled with csv data to filter out functions that are in it from the rest of the processing (eg: cleanware csv data, note that you can use -X multiple times, but don't use wildcards to read in multiple blacklist files as that probably won't work)", type="string", dest="blacklist", action="append", default=[])

    parser.add_option("-T", "--hashtype", help="hash type to use for fn hash comparisons (" + ",".join(hashtypes) + "; default %default)", type="string", dest="hashtype", default=defaulthash)

    parser.add_option("-M", "--matrix", help="show text matrix of files and hashes (default)", action="store_true", dest="matrix", default=False)
    parser.add_option("-c", "--compact", help="compact the output a bit (when appropriate)", action="store_true", dest="compact", default=False)
    parser.add_option("-H", "--histogram", help="show histogram of # files per # hashes (NOT IMPLEMENTED YET)", action="store_true", dest="histogram", default=False)
    parser.add_option("-G", "--graph", help="show graph of files and hashes (requires NetworkX, matplotlib, scipy, and numpy, NOT IMPLEMENTED YET)", action="store_true", dest="graph", default=False)
    parser.add_option("-F", "--faces", help="show chernoff faces of fn2hash data ala our malfaces R module (requires scikit-learn, matplotlib, scipy, and numpy, NOT IMPLEMENTED YET)", action="store_true", dest="faces", default=False)

    global options
    global data_files
    (options, data_files) = parser.parse_args(args)

    if options.quiet:
        # set proper logging level (error messages only [overrides warnings on by default])
        setQuiet()
    if options.verbose:
        # set proper logging level (overrides quiet, info & above)
        setVerbose()
    if options.debug:
        # set proper logging level (debug implies & overrides verbose)
        setDebug()

    # suppose I could have 0 data files mean read from stdin, but not for now:
    if len(data_files) < 1:
        logger.error("must have at least 1 fn2hash data file!")
        sys.exit(1)

    if options.hashtype not in hashtypes:
        logger.error("specified hash '%s' not in known list of hashtypes: %s" % (options.hashtype,",".join(hashtypes)))
        sys.exit(2)

    if not options.matrix and not options.histogram and not options.graph and not options.faces:
        options.matrix = True

###########################################################################

# parse fn2hsh CSV data into global dictionaries
def parse_fn2hash_data(datafile,is_blacklist):
    # each of thesse is a dict keyed by the item after the 2 in the name and that returns a list of addresses found at...
    global file2fn
    global fn2file
    global blacklist
    global numblacklisted
    global fninfo
    global maxinstwidth
    global maxbyteswidth
    global maxaddrwidth
    global maxhashwidth

    # fn2hash CSV data layout:
    #   filemd5,fn_addr,num_basic_blocks,num_basic_blocks_in_cfg,num_instructions,num_bytes,
    #   exact_hash,pic_hash,composite_pic_hash,
    #   mnemonic_hash,mnemonic_count_hash,mnemonic_category_hash,mnemonic_category_counts_hash,
    #   mnemonic_count_string,mnemonic_category_count_string
    logger.debug("parsing %s"%datafile)
    with open(datafile) as df_in:
        rdr = csv.reader(df_in)
        for line in rdr:
            filemd5,fn_addr,num_basic_blocks,num_basic_blocks_in_cfg,num_instructions,num_bytes,exact_hash,pic_hash,composite_pic_hash,mnemonic_hash,mnemonic_count_hash,mnemonic_category_hash,mnemonic_category_counts_hash,mnemonic_count_string,mnemonic_category_count_string = line
            # which hash: EXACT,PIC,CPIC,MNEM,MCNT,MCAT,MCCNT
            if options.hashtype == "EXACT":
                fnhash = exact_hash
            elif options.hashtype == "PIC":
                fnhash = pic_hash
            elif options.hashtype == "CPIC":
                fnhash = composite_pic_hash
            elif options.hashtype == "MNEM":
                fnhash = mnemonic_hash
            elif options.hashtype == "MCNT":
                fnhash = mnemonic_count_hash
            elif options.hashtype == "MCAT":
                fnhash = mnemonic_category_hash
            elif options.hashtype == "MCCNT":
                fnhash = mnemonic_category_counts_hash

            if is_blacklist:
                blacklist.add(fnhash)
            else:
                nilen = len(num_instructions)
                nblen = len(num_bytes)
                num_instructions = int(num_instructions)
                num_bytes = int(num_bytes)
                logger.debug("file: %s, fn: %s, addr: %s, # inst %d, # bytes: %d"%(filemd5,fnhash,fn_addr,num_instructions,num_bytes))
                if num_bytes < options.minlen:
                    logger.info("skipping fn %s, too few bytes (%d)"%(fnhash,num_bytes))
                    continue
                if num_instructions < options.mininstructions:
                    logger.info("skipping fn %s, too few instructions (%d)"%(fnhash,num_instructions))
                    continue

                if fnhash not in blacklist:
                    maxinstwidth = max(maxinstwidth,nilen)
                    maxbyteswidth = max(maxbyteswidth,nblen)
                    maxaddrwidth = max(maxaddrwidth,len(fn_addr))
                    maxhashwidth = max(maxhashwidth,len(fnhash))
                    if filemd5 in file2fn:
                        if fnhash in file2fn[filemd5]:
                            file2fn[filemd5][fnhash].append(fn_addr)
                        else:
                            file2fn[filemd5][fnhash] = [fn_addr]
                    else:
                        file2fn[filemd5] = {fnhash: [fn_addr]}

                    if fnhash in fn2file:
                        if filemd5 in fn2file[fnhash]:
                            fn2file[fnhash][filemd5].append(fn_addr)
                        else:
                            fn2file[fnhash][filemd5] = [fn_addr]
                    else:
                        fn2file[fnhash] = {filemd5: [fn_addr]}
                else:
                    logger.info("skipping blacklisted fn %s"%fnhash)
                    numblacklisted += 1
                    continue

                if fnhash not in fninfo:
                    fninfo[fnhash] = {"insn": num_instructions, "bytes": num_bytes, "conflicting":False, "addrs": [fn_addr]}
                else:
                    if fninfo[fnhash]["insn"] != num_instructions:
                        logger.warning("mismatch in hash %s num insn (old %d, new %d) keeping max"%(fnhash,fninfo[fnhash]["insn"],num_instructions))
                        fninfo[fnhash]["insn"] = max(num_instructions,fninfo[fnhash]["insn"])
                        fninfo[fnhash]["conflicting"] = True
                    if fninfo[fnhash]["bytes"] != num_bytes:
                        logger.warning("mismatch in hash %s num bytes (old %d, new %d) keeping max"%(fnhash,fninfo[fnhash]["bytes"],num_bytes))
                        fninfo[fnhash]["bytes"] = max(num_bytes,fninfo[fnhash]["bytes"])
                        fninfo[fnhash]["conflicting"] = True
                    fninfo[fnhash]["addrs"].append(fn_addr)

###########################################################################
#
# code for different output modes
#
###########################################################################

def do_matrix():
    global data_files
    global options
    global fn2hash
    global file2hash
    global blacklist
    global fninfo
    global maxinstwidth
    global maxbyteswidth
    global maxaddrwidth
    global maxhashwidth

    if len(file2fn) > 100:
        logger.warning("# of file (%d) > 100, text matrix output will likely be sub optimal"%len(file2fn))
    if len(fn2file) > 100:
        logger.warning("# of funcs (%d) > 100, text matrix output will likely be sub optimal"%len(fn2file))

    num_fn_per_file = {}
    for f in file2fn.keys():
        num_fn_per_file[f] = len(file2fn[f])
    files_descending = []
    for pair in sorted(num_fn_per_file.items(), key=lambda item: item[1], reverse=True):
        # Skip files that have no functions.
        if pair[1] == 0:
            continue
        # Append the file hash to the correctly sorted list.
        files_descending.append(pair[0])
    files_dropped = len(file2fn) - len(files_descending)
    logger.info("(%d files dropped because no functions found)"%files_dropped)

    num_files_for_func = {}
    for fn in fn2file.keys():
        num_files_for_func[fn] = len(fn2file[fn])

    #funcs_descending = [fn[0] for fn in sorted(num_files_for_func.iteritems(),key=operator.itemgetter(1),reverse=True) if fn[1] >= options.fn_threshold]
    # okay, ordered by number of files it appears in is okay, but would be
    # nice to order showing clusters better, so let's try a different
    # sorting pass based on the files it appears in (sort by a variant of
    # the output line for the matrix).  I could probably combine this with
    # the output generation instead of repeating it, but this is just a
    # test for now, I'll fix for real later...
    vec_files_for_func = {}
    for fn in fn2file.keys():
        vec = ""
        cnt = 0
        for f in files_descending:
            if fn in file2fn[f]:
                vec += "1"
                cnt += 1
            else:
                vec += "0"
        vec_files_for_func[fn] = (vec,cnt)
    funcs_descending = [fn[0] for fn in sorted(vec_files_for_func.items(),key=lambda t: (t[1][0],t[1][1]),reverse=True) if fn[1][1] >= options.fn_threshold]
    funcs_dropped = len(num_files_for_func) - len(funcs_descending)
    logger.info("(%d functions dropped due to file threhsold)"%funcs_dropped)

    for i,f in enumerate(files_descending):
        print("F%02d: %s (%d funcs)"%(i,f,num_fn_per_file[f]))
    #for i,fn in enumerate(funcs_descending):
    #    print("P%04d: %s (%d files)"%(i,fn,num_files_for_func[fn]))

    print("\n############################################################")
    print("# %s function set intersection matrix"%options.hashtype)
    print("############################################################\n")

    # setup the table, need todefine the columns first:
    tbl = Table() if not options.compact else Table(None,0)
    num_files = len(files_descending)
    for cd in [ColDef(1)]*num_files:
        tbl.add_column(cd)
    tbl.add_column(ColDef(1)) # c(onflicting sizes)?
    # some calculated col widths need extra spacing if compact option used
    if options.compact:
        maxinstwidth += 1
        maxbyteswidth += 1
        maxaddrwidth += 1
        maxhashwidth += 1
    # and the addr might get a * prepended:
    maxaddrwidth += 1
    tbl.add_column(ColDef(maxinstwidth)) # i(nstructions)
    tbl.add_column(ColDef(maxbyteswidth)) # b(ytes)
    tbl.add_column(ColDef(maxaddrwidth)) # addr?
    tbl.add_column(ColDef(maxhashwidth)) # hash

    # okay, now the headers, and we're file numbers printing vertically, so it's tricky...
    tbl.add_header_row("F"*num_files + ' '*(len(tbl.cols)-num_files))
    # build up the remaining headers, the number of which is log10(num_files) rounded up:
    numhdrs = int(math.ceil(math.log(num_files,10)))
    #hdrs=[[]*numhdrs] # this doesn't work like expected...list comprehensions I guess (which does work):
    #hdrs=[[] for _ in range(numhdrs)]
    # actually, discovered later that this works:
    hdrs = [[]]*numhdrs
    # now, need to get each single digit for each row, this is the really tricky part:
    for j in range(numhdrs):
        hdrs[j]=[]
        for i in range(num_files):
            hdrs[j].append((i//(10**(numhdrs-j-1)))%10)
        if j+1 == numhdrs:
            hdrs[j] += ['c','i','b','addr',options.hashtype]
        else:
            hdrs[j] += [' ']*(len(tbl.cols)-num_files)
        tbl.add_header_row(hdrs[j])

    # and now the row data...
    yeschar = 'X'
    nochar = ' ' if not options.compact else '.'
    for i,fn in enumerate(funcs_descending):
        # probably should reuse vec_files_for_func instead of rebuilding this...
        row = []
        for f in files_descending:
            if fn in file2fn[f]:
                row.append(yeschar)
            else:
                row.append(nochar)

        # display # insn, bytes, "addr", and hash value at end of line
        row.append('*' if fninfo[fn]["conflicting"] else ' ')
        row.append(fninfo[fn]["insn"])
        row.append(fninfo[fn]["bytes"])
        # address aggregation, if all instances have same address, output
        # it, if "majority" have same address, output it w/ a deliniator,
        # and if mostly different output ???????
        num_addrs = len(fninfo[fn]["addrs"])
        addr_counter = collections.Counter(fninfo[fn]["addrs"])
        disp_addr_maybe = addr_counter.most_common()
        disp_addr = disp_addr_maybe[0][0]
        if disp_addr_maybe[0][1] == 1 and len(disp_addr_maybe) > 1:
            disp_addr = '?'*len(disp_addr)
        elif disp_addr_maybe[0][1] != num_addrs:
            disp_addr = '*'+disp_addr
        row.append(disp_addr)
        row.append(fn)

        tbl.add_row(row)
    print(tbl)



###########################################################################
#
# main driver code
#
###########################################################################

def main(args):
    global data_files
    global options
    global fn2hash
    global file2hash
    global blacklist
    global fninfo
    global maxinstwidth
    global maxbyteswidth
    global maxaddrwidth
    global maxhashwidth

    read_config(args)

    # deal w/ any blacklists
    if len(options.blacklist) > 0:
        for bf in options.blacklist:
            parse_fn2hash_data(bf,True)
        logger.info("blacklisted %d functions"%len(blacklist))

    # read in the CSV data:
    for df in data_files:
        parse_fn2hash_data(df,False)

    logger.info("%d files and %d functions found, skipped %d blacklisted functions"%(len(file2fn),len(fn2file),numblacklisted))

    if options.matrix:
        do_matrix()


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except BrokenPipeError:
        pass
