#!/usr/bin/python

import sys
import os
import subprocess
import argparse
import re
import shutil
import errno

def test_input_path(args):
    return os.path.join(args.git_dir, "tests" , args.testcase[0])

def test_ground_path(args):
    return os.path.join(args.git_dir, "tools", "ooanalyzer", "tests" , args.testcase[0])

def test_output_path(args):
    return os.path.join(args.build_dir, "tools", "ooanalyzer", "tests" , args.testcase[0])

def create_test_output_dir(args):
    test_output_dir = os.path.dirname(test_output_path(args))
    if os.path.isdir(test_output_dir):
        return

    try:
        os.makedirs(test_output_dir)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(test_output_dir):
            pass
        else:
            raise

def fixup_ugly_symbols(symbol):
    for (b, a) in fixups:
        symbol = symbol.replace(b, a, 99)
    return symbol

def report_error(args, context, msg):
    if args.interactive:
        print "%s" % msg
    else:
        print >>sys.stderr, "FAILED: %s %s %s" % (args.testcase[0], context, msg)

# ===========================================================================
# Build the symbol map.
# ===========================================================================
def build_symbol_map(symbols_file):
    addr2symbol = {}
    try:
        symbolHnd = open(symbols_file, 'r')
        lines = symbolHnd.readlines()
    except:
        print "Error opening " + symbols_file
        sys.exit(2)

    for l in lines:
        l = l.rstrip()
        if len(l) == 0: continue

        try:
            (addr, isthunk, idasymbol, symbol) = l.split(None, 3)
        except ValueError:
            print >>sys.stderr, "Bad line: %s" % l

        addr = int(addr, 16)
        if symbol != 'None':
            addr2symbol[addr] = "0x%08X %s" % (addr, fixup_ugly_symbols(symbol))
        else:
            addr2symbol[addr] = "0x%08X %s" % (addr, idasymbol)
        #print str(addr) + " : " + symbol + " => " + addr2symbol[addr]

    symbolHnd.close()
    return addr2symbol

# ===========================================================================
# Now do the substitutions.
# ===========================================================================
def postprocess_oo_output(output_file, named_file, addr2symbol):
    out = open(named_file, 'w')
    outputHnd = open(output_file, 'r')
    #print "creating " + named_file + " from " + output_file
    for l in outputHnd:

        #print "Examining: " + l

        # Hide variations in timing.
        if l.endswith('seconds elapsed.\n'):
            l = re.sub('complete, .* seconds elapsed.', 'complete.', l)
        # Hide variations in timing.
        if l.endswith('seconds.\n'):
            l = re.sub('complete, analyzed .* functions in .* seconds.', 'took X seconds.', l)
        # Hide version number changes.
        if l.startswith('OPTI[INFO ]: Object Digger version'):
            l = re.sub('version .*.$', 'version X.', l)
        # Hide different progress reporting in partitioner 2
        if l.startswith('PRT2[MARCH]: cfg'):
            # Just skip these lines entirely since there might be different numbers of them
            continue

        # Don't be picky about exactly where the Prolog files were exported to.
        pos = l.find('Prolog facts to ')
        if pos != -1:
            l = l[0:pos] + 'Prolog facts to ...\n'
        pos = l.find('Prolog results to ')
        if pos != -1:
            l = l[0:pos] + 'Prolog results to ...\n'

        # Apply regexp replacements
        for rx, n, r in regexp_replace:
            match = rx.search(l)
            if match and match.group(n):
                l = "".join((l[:match.start(n)], r, l[match.end(n):]))

        # Do we have a any variables?
        if l.find('=v') != -1 or l.find(' v') != -1:
            # If so normalize them.
            l = re.sub('v[0-9a-f]*\[', 'v?[', l)

        for addr in addr2symbol:
            sym = addr2symbol[addr]
            # Removed the decimal address supprt since we don't do that anymore, right Wes?

            if True:
                xaddr = "0x%08X" % addr
                if l.find(xaddr) != -1:
                    l = l[0:l.find(xaddr)] + sym + l[l.find(xaddr)+len(xaddr):]
            else:
                xaddr = "%x" % addr
                # Someone (Chuck?) wrote: That above works, but better w/ regexp to strip out
                # extra leading zeroes and 0x prefixes?  Cory says: Yes, except for the part
                # where it takes 16 seconds instead of 0.3 seconds. :-)
                l = re.sub("(0x)?0*%s"% (xaddr), sym, l)

        out.write(l)
    outputHnd.close()

    # Merge in the error output so that we see assertions, exceptions, etc.
    #errorHnd = open(error_file, 'r')
    #for l in errorHnd:
    #    if l.startswith('Partitioner: starting GRAPH'): continue
    #    if l.startswith('Disassembler[va 0x') and l.endswith('instructions\n'): continue
    #    out.write(l)
    #errorHnd.close()

    out.close()

def update_rules(args):
    os.chdir(args.build_dir)
    # This is pretty hackish, but if this script is run without
    # parallelization, then it does the right thing.  If it is run
    # parallel and the oorules are already up-to-date that's ok as
    # well.  And if they're not up-to-date, then this causes us to
    # just fail in a different way. :-)
    os.system('make oorules >/dev/null')

def run_ooanalyzer_test(args):
    create_test_output_dir(args)

    testname = args.testcase[0]

    update_rules(args)

    options = []
    options.append("--no-site-file")
    options.append("--no-user-file")
    options.append("--config=%s" % os.path.join(args.build_dir, "tests", "testconfig.yaml"))
    options.append("--verbose=4")
    options.append("--json=%s" % test_output_path(args) + ".json")
    prolog_fact_path = test_output_path(args) + ".facts"
    options.append("--prolog-facts=%s" % prolog_fact_path)
    prolog_results_path = test_output_path(args) + ".results"
    options.append("--prolog-results=%s" % prolog_results_path)

    tool_path = os.path.join(args.build_dir, "tools", "ooanalyzer", "ooanalyzer")

    cmd = [tool_path]
    cmd.extend(options)

    exe_path = test_input_path(args) + ".exe"
    cmd.append(exe_path)

    output_path = test_output_path(args) + ".output"
    cmd.append(">" + output_path)
    error_path = test_output_path(args) + ".error"
    cmd.append("2>" + error_path)

    cmd = ' '.join(cmd)
    if args.commands:
        print cmd

    if not args.review:
        rc = subprocess.call(cmd, shell=True)
        if rc != 0:
            if not args.quiet:
                report_error(args, "", "ooanalyzer execution rc=%d" % rc)
            sys.exit(1)

    symbol_path = test_input_path(args) + ".symbols"
    addr2symbol = build_symbol_map(symbol_path)
    named_path = test_output_path(args) + ".named"
    postprocess_oo_output(output_path, named_path, addr2symbol)

    gen_facts_path = test_output_path(args) + ".facts"
    sort_file(args, gen_facts_path)
    gen_results_path = test_output_path(args) + ".results"
    sort_file(args, gen_results_path)
    return compare_prolog_answers(args, gen_facts_path, gen_results_path)

def sort_file(args, filename):
    cmd = "sort %s >%s.new && mv %s.new %s" % (filename, filename, filename, filename)
    if args.commands:
        print cmd

    if not args.review:
        rc = subprocess.call(cmd, shell=True)
        if rc != 0:
            if not args.quiet:
                report_error(args, "", "ooanalyzer sorting %s rc=%d" % (filename, rc))
            sys.exit(1)

def run_prolog_test(args):
    create_test_output_dir(args)
    ground_facts_path = test_ground_path(args) + ".facts"
    gen_results_path = test_output_path(args) + ".results"
    xsb_spew_path = test_output_path(args) + ".prolog_error"

    testname = args.testcase[0]

    update_rules(args)
    rules_path = os.path.join(args.git_dir, "share", "prolog", "oorules")
    os.chdir(rules_path)

    xsb_path = args.xsb_path
    assertions = "[rulerun],assert(rTTIEnabled),run('%s')." % ground_facts_path
    redirection = ">%s 2>%s" % (gen_results_path, xsb_spew_path)
    prolog_cmd = xsb_path + ' --noprompt -e "' + assertions + '" ' + redirection

    if args.commands:
        print prolog_cmd

    failed = 0
    if not args.review:
        rc = subprocess.call(prolog_cmd, shell=True)
        if rc != 0:
            if not args.quiet:
                report_error(args, "", "xsb execution rc=%d" % rc)
            failed += 1

    sort_file(args, gen_results_path)

    if failed == 0:
        failed += compare_prolog_answers(args, ground_facts_path, gen_results_path)

    return failed

def compare_prolog_answers(args, gen_fact_path, gen_results_path):
    testname = args.testcase[0]

    ground_fact_path = test_ground_path(args) + ".facts"
    gen_fact_lines = set(open(gen_fact_path, 'U').readlines())
    ground_fact_lines = set(open(ground_fact_path, 'U').readlines())

    ground_results_path = test_ground_path(args) + ".results"
    gen_results_lines = set(open(gen_results_path, 'U').readlines())
    ground_results_lines = set(open(ground_results_path, 'U').readlines())

    if args.commands:
        cmd = "diff %s %s" % (ground_fact_path, gen_fact_path)
        print cmd
        cmd = "diff %s %s" % (ground_results_path, gen_results_path)
        print cmd

    extra_facts =  gen_fact_lines - ground_fact_lines
    missing_facts = ground_fact_lines - gen_fact_lines
    extra_results = gen_results_lines - ground_results_lines
    missing_results = ground_results_lines - gen_results_lines

    # We could do a better job of this, but for right now, this seems reasonable.
    new_gen_facts = set()
    for fact in gen_fact_lines:
        new_gen_facts.add(re.sub('sv_[0-9]+', 'sv_xxx', fact))
    new_ground_facts = set()
    for fact in ground_fact_lines:
        new_ground_facts.add(re.sub('sv_[0-9]+', 'sv_xxx', fact))

    # A common occurrence is for the sv_hashes to change.
    if len(extra_facts) == len(missing_facts) and len(missing_facts) != 0:
        new_extra_facts =  new_gen_facts - new_ground_facts
        new_missing_facts = new_ground_facts - new_gen_facts
        if len(new_extra_facts) == 0 and len(new_missing_facts) == 0:
            if not args.quiet:
                print >>sys.stderr, "WARNING: %s ooanalyzer-prolog facts symbolic values changed" % (testname)
            extra_facts = new_extra_facts
            missing_facts = new_missing_facts

    if args.discard and len(extra_facts)+len(missing_facts) != 0:
        new_extra_facts =  new_gen_facts - new_ground_facts
        new_missing_facts = new_ground_facts - new_gen_facts

        if not args.quiet:
            print >>sys.stderr, "WARNING: %s ooanalyzer-prolog facts symbolic values discarded" % (testname)
        extra_facts = new_extra_facts
        missing_facts = new_missing_facts

    if args.verbose:
        for fact in sorted(extra_facts):
            report_error(args, "ooanalyzer facts", "+%s+" % fact.rstrip())
        for fact in sorted(missing_facts):
            report_error(args, "ooanalyzer facts", "-%s-" % fact.rstrip())
        for result in sorted(extra_results):
            report_error(args, "ooanalyzer results", "+%s+" % result.rstrip())
        for result in sorted(missing_results):
            report_error(args, "ooanalyzer results", "-%s-" % result.rstrip())

    total_errors = len(extra_facts) + len(missing_facts) + len(extra_results) + len(missing_results)
    if total_errors > 0:
        if not args.quiet:
            fmt = "missing-facts=%d extra-facts=%d missing-results=%d extra-results=%d"
            msg = fmt % (len(missing_facts), len(extra_facts),
                         len(missing_results), len(extra_results))
            report_error(args, "ooanalyzer prolog", msg)
            return 1
        else:
            return 1
    return 0

def accept_prolog_test(args):
    gen_facts_path = test_output_path(args) + ".facts"
    gen_results_path = test_output_path(args) + ".results"
    ground_facts_path = test_ground_path(args) + ".facts"
    ground_results_path = test_ground_path(args) + ".results"

    if args.commands:
        print "cp %s %s" % (gen_facts_path, ground_facts_path)
        print "cp %s %s" % (gen_results_path, ground_results_path)

    if not args.review:
        shutil.copyfile(gen_facts_path, ground_facts_path)
        shutil.copyfile(gen_results_path, ground_results_path)

# ===========================================================================
# Globals for the OOanalyzer output fixup process
# ===========================================================================

# My goal here was to make the eyes bleed just a little bit less...
fixups = [
    # Just to save a little more space on the screen...
    ('public: ', ''),
    ('private: ', ''),
    # These are for when have std templates in the output...
    ('struct std::char_traits<char>', 'CHAR_TRAITS'),
    ('class std::allocator<char>', 'CHAR_ALLOC'),

    ('basic_streambuf<char, CHAR_TRAITS>', 'basic_char_streambuf'),
    ('basic_istream<char, CHAR_TRAITS>', 'basic_char_istream'),
    ('istreambuf_iterator<char, CHAR_TRAITS>', 'istreambuf_char_iter'),
    ('basic_ostream<char, CHAR_TRAITS>', 'basic_char_ostream'),
    ('ostreambuf_iterator<char, CHAR_TRAITS>', 'ostreambuf_char_iter'),
    ('basic_ios<char, CHAR_TRAITS>', 'basic_char_ios'),

    ('basic_string<char, CHAR_TRAITS, CHAR_ALLOC>', 'basic_char_string'),
    ('basic_stringbuf<char, CHAR_TRAITS, CHAR_ALLOC>', 'basic_char_stringbuf'),
    ('_String_iterator<char, CHAR_TRAITS, CHAR_ALLOC>', '_string_iter'),
    ('_String_const_iterator<char, CHAR_TRAITS, CHAR_ALLOC>', '_string_const_iter'),
    ('_String_val<char, CHAR_ALLOC>', '_string_val'),

    ('pair<class std::basic_char_string const, class std::basic_char_string>', 'string_pair'),
    ('less<class std::basic_char_string>', 'less<str>'),
    ('class std::allocator<struct std::string_pair>', 'STR_PAIR_ALLOC'),

    ('_Tmap_traits<class std::basic_char_string, class std::basic_char_string, struct std::less<str>, STR_PAIR_ALLOC, 0', '_Tmap_traits<str, str>'),

    ('map<class std::basic_char_string, class std::basic_char_string, struct std::less<str>, STR_PAIR_ALLOC>', 'map<str, str>'),

    ('_Tree_val<class std::_Tmap_traits<str, str>>', '_Tree_val<str, str>'),
    ('_Tree_const_iterator<class std::_Tree_val<str, str>>>', '_Tree_const_iter<str, str>'),
    ('_Tree_nod<class std::_Tmap_traits<str, str>>', '_Tree_nod<str, str>'),
    ('_Tree_unchecked_const_iterator<class std::_Tree_val<str, str> >', '_Tree_unch_iter<str, str>'),

    ('_Pair_base<class std::basic_char_string, class std::basic_char_string>', '_Pair_base<str, str>'),
    ]

regexp_replace = [
    ("complete(, .*seconds elapsed).", 1, ""),
    ("took (.*) seconds.", 1, "X"),
    ("Analyzing executable: (.*/)?tests", 1, ""),
    ("Loaded API database: (.*/)?", 1, ""),
    ("to JSON file:? '?(.*/)?tests", 1, "")
]
regexp_replace = [(re.compile(rx), n, r) for (rx, n, r) in regexp_replace]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run an OOAnalyzer test.')
    parser.add_argument('testcase', metavar='testcase', type=str,
                        nargs='+',
                        help='The testcase to run')
    parser.add_argument("-p", "--prolog",
                        action="store_true", default=False,
                        help="only run the prolog part of the test")
    parser.add_argument("-v", "--verbose",
                        action="store_true", default=False,
                        help="report verbose details of test")
    parser.add_argument("-q", "--quiet",
                        action="store_true", default=False,
                        help="suppress messages about failures")
    parser.add_argument("-a", "--accept",
                        action="store_true", default=False,
                        help="accept the changes in test results")
    parser.add_argument("-r", "--review",
                        action="store_true", default=False,
                        help="review changes but don't rerun the commands")
    parser.add_argument("-c", "--commands",
                        action="store_true", default=False,
                        help="print commands associated with test")
    parser.add_argument("-i", "--interactive",
                        action="store_true", default=False,
                        help="report differences without testcase prefixes")
    parser.add_argument("-d", "--discard",
                        action="store_true", default=False,
                        help="discard differences in symbolic value hashes")
    parser.add_argument("-b", "--build-dir",
                        type=str, default=os.getcwd(),
                        help="set the cmake build directory")
    parser.add_argument("-g", "--git-dir",
                        type=str, default="",
                        help="set the git root checkout directory")
    parser.add_argument("-x", "--xsb-path",
                        type=str, default="/usr/local/xsb-3.7.0/bin/xsb",
                        help="The location of the xsb runtime")
    args = parser.parse_args()

    ground_facts_path = test_ground_path(args) + ".facts"
    if not os.path.exists(ground_facts_path):
        print >>sys.stderr, "FAILED: Invalid test case '%s'" % (args.testcase[0])
        sys.exit(1)

    if args.git_dir == "":
        args.git_dir = os.path.dirname(args.build_dir)

    if args.accept:
        while len(args.testcase) > 0:
            accept_prolog_test(args)
            args.testcase.pop(0)
        sys.exit(0)

    failures = 0
    while len(args.testcase) > 0:
        if args.prolog:
            failures += run_prolog_test(args)
        else:
            failures += run_ooanalyzer_test(args)

        args.testcase.pop(0)

    sys.exit(failures)

