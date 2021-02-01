#!/usr/bin/env python
import os

import sys
import os
import subprocess
import argparse
import shutil
import errno

def test_input_path(args):
    return os.path.join(args.git_dir, "tests" , args.testcase[0])

def test_ground_path(args):
    return os.path.join(args.git_dir, "tools", "dumpmasm", "tests" , args.testcase[0])

def test_output_path(args):
    return os.path.join(args.build_dir, "tools", "dumpmasm", "tests" , args.testcase[0])

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

def report_error(args, context, msg):
    if args.interactive:
        print "%s" % msg
    else:
        print >>sys.stderr, "FAILED: %s %s %s" % (args.testcase[0], context, msg)

def run_test(args):
    create_test_output_dir(args)

    testname = args.testcase[0]

    options = ["--format=csv"]
    options.append("--no-site-file")
    options.append("--no-user-file")
    options.append("--config=%s" % os.path.join(args.build_dir, "tests", "testconfig.yaml"))

    tool_path = os.path.join(args.build_dir, "tools", "dumpmasm", "dumpmasm")

    cmd = [tool_path]
    cmd.extend(options)
    cmd.append(test_input_path(args) + ".exe")
    output_path = test_output_path(args) + ".part2"
    cmd.extend(["|", "grep", '-e', 'PART', '-e', 'FLOW', "|", "sort -k2 -t,", ">", output_path])

    cmd = ' '.join(cmd)
    if args.commands:
        print cmd

    if not args.review:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        rc = subprocess.Popen(cmd, shell=True, env=env).wait()
        if rc != 0:
            if not args.quiet:
                report_error(args, "", "dumpmasm execution rc=%d" % rc)
            sys.exit(1)

    previous_path = test_ground_path(args) + ".part2prev"
    diff_path = test_output_path(args) + ".part2diff"
    diff_cmd = "diff %s %s" % (previous_path, output_path)
    if not args.verbose:
        diff_cmd = diff_cmd + " >%s" % diff_path

    if args.commands:
        print diff_cmd

    rc = subprocess.call(diff_cmd, shell=True)
    if rc != 0:
        if not args.quiet:
            report_error(args, "", "dumpmasm diff rc=%d" % rc)
        return 1

    return 0

def accept_test(args):
    gen_path = test_output_path(args) + "part2diff"
    ground_path = test_ground_path(args) + "part2prev"

    if args.commands:
        print "cp %s %s" % (gen_path, ground_path)

    if not args.review:
        shutil.copyfile(gen_path, ground_path)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a partitioner test.")
    parser.add_argument('testcase', metavar='testcase', type=str,
                        nargs='+',
                        help='The testcase to run')
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
    parser.add_argument("-b", "--build-dir",
                        type=str, default=os.getcwd(),
                        help="set the cmake build directory")
    parser.add_argument("-g", "--git-dir",
                        type=str, default="",
                        help="set the git root checkout directory")
    args = parser.parse_args()

    if args.git_dir == "":
        args.git_dir = os.path.dirname(args.build_dir)

    if args.accept:
        while len(args.testcase) > 0:
            accept_test(args)
            args.testcase.pop(0)
        sys.exit(0)


    failures = 0
    while len(args.testcase) > 0:
        failures += run_test(args)
        args.testcase.pop(0)

    sys.exit(failures)
