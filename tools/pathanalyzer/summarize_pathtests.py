#!/usr/bin/env python3

# cmake -DPATHTEST_CROSS32BIT=on -DPATHTEST_CXX_FLAGS=-O0 -DPATHTEST_TIMEOUT_SECS=300 ..
# make -j32
# ctest -j32 -R ^path > 00.txt
# ../tools/pathanalyzer/summarize_pathtests.py <O0.txt O0 >O0.csv
# cmake -DPATHTEST_CXX_FLAGS=-O1 .. && make -j32
# ctest -j32 -R ^path > O1.txt
# ../tools/pathanalyzer/summarize_pathtests.py <O1.txt O1 >O1.csv
# cmake -DPATHTEST_CXX_FLAGS=-O2 .. && make -j32
# ctest -j32 -R ^path > O2.txt
# ../tools/pathanalyzer/summarize_pathtests.py <O2.txt O2 >O2.csv
# sort O0.csv O1.csv O2.csv > pathtests.csv
# ./tools/pathanalyzer/summarize_pathtests.py --stage2 <pathtests.csv >pathtable.csv
# (Import pathtable.csv into second sheet in pathtests.ods)

import sys

class TestResult(object):

    def __init__(self, name, method, config, archbits, goal, status, time):
        self.name = name
        self.method = method
        self.config = config
        self.archbits = archbits
        self.goal = goal
        self.status = status
        self.time = time

    def __str__(self):
        return "%s,%s,%s,%s,%s,%s,%s" % (
            self.name, self.method, self.config, self.archbits, self.goal, self.status, self.time)

def read_ctest_output(config):
    tests = []
    for line in sys.stdin:
        line = line.strip().rstrip()
        if line == '':
            continue
        if line.startswith("Test project"):
            continue
        if line.startswith("Start"):
            continue
        if line.find('tests passed') != -1:
            break

        # The Exception line needs to be handled specially because there's a space after it.
        # 46/936 Test  #464: pathanalyzer_spacer_xxx_goal_64 ......***Exception: SegFault234.71 sec
        # Actually I guess CTest is just horribly inconsistent:
        # 6/8 Test #424: pathanalyzer_spacer_xxx_nongoal_64 ...Child aborted***Exception:  33.08 sec

        # The 'S' in front of Aborted is just because I'm not sure I want the _spreadsheet_ to
        # have separate categories for SegFault and aborted, since thgey're both supposed to be
        # very rare.
        line = line.replace('Child aborted', ' SAborted')
        line = line.replace('***Exception:', '  ')
        line = line.replace('SegFault', 'SegFault ')
        # This substitution create a space betwen the dots and the "Failed" keyword.
        # 1/780 Test #319: pathanalyzer_wp_xxx_goal_64 ............***Failed    1.32 sec
        line = line.replace('***', '   ')

        try:
            (_num, _test, _onum, name, _dots, status, time, _sec) = line.split()
        except ValueError:
            print("Invalid line: '%s'" % line, file=sys.stderr)
            continue

        # The time is a float
        time = float(time)

        if name.startswith('pathanalyzer_'):
            name = name[13:]
        else:
            raise ValueError("Invalid name test name '%s'" % name)

        if name.endswith('_32'):
            archbits = 32
            name = name[:-3]
        elif name.endswith('_64'):
            archbits = 64
            name = name[:-3]
        else:
            raise ValueError("Invalid name architecture '%s'" % name)


        if name.endswith('_goal'):
            goal = 'goal'
            name = name[:-5]
        elif name.endswith('_nongoal'):
            goal = 'nongoal'
            name = name[:-8]
        else:
            goal = 'old'
            # Should do this, but we're still transitioning.
            #raise ValueError("Invalid name architecture '%s'" % name)

        if name.startswith('spacer_'):
            method = 'sp'
            name = name[7:]
        elif name.startswith('fs_'):
            method = 'fs'
            name = name[3:]
        elif name.startswith('wp_'):
            method = 'wp'
            name = name[3:]
        elif name.startswith('sea_'):
            method = 'sea'
            name = name[4:]
        else:
            raise ValueError("Invalid name method '%s'" % name)

        test = TestResult(name, method, config, archbits, goal, status, time)
        tests.append(test)
    return tests

def make_results_table():
    tests = {}
    for line in sys.stdin:
        line = line.rstrip()
        (name, method, config, archbits, goal, status, time) = line.split(',')
        time = float(time)
        test = TestResult(name, method, config, archbits, goal, status, time)

        if name not in tests:
            tests[name] = {}
        if method not in tests[name]:
            tests[name][method] = {}
        if config not in tests[name][method]:
            tests[name][method][config] = {}
        if archbits not in tests[name][method][config]:
            tests[name][method][config][archbits] = {}

        tests[name][method][config][archbits][goal] = test

    line = "name"
    name = list(tests.keys())[0]
    for method in sorted(tests[name]):
        for config in sorted(tests[name][method]):
            for archbits in sorted(tests[name][method][config]):
                for goal in [ 'g', 'ng' ]:
                    for field in [ 's', 't' ]:
                        column_label = '%s_%s_%s_%s_%s' % (method, config, archbits, goal, field)
                        line += ',%s' % column_label
    print(line)

    for name in tests:
        line = name
        for method in sorted(tests[name]):
            for config in sorted(tests[name][method]):
                for archbits in sorted(tests[name][method][config]):
                    values = []
                    for goal in sorted(tests[name][method][config][archbits]):
                        test = tests[name][method][config][archbits][goal]
                        values.append(test.status[0])
                        values.append('%d' % test.time)
                    line += ",%s" % (','.join(values))
        print(line)

if __name__ == '__main__':
    # Hacky options parsing. ;-(
    if sys.argv[1] == '--stage2':
        make_results_table()
        sys.exit()
    else:
        tests = read_ctest_output(sys.argv[1])
        for test in tests:
            tstr = str(test)
            # More _super_ hacky options parsing...
            if len(sys.argv) > 2 and sys.argv[2] == '--time':
                tstr = ','.join(tstr.split(',')[:6])
            print(tstr)
