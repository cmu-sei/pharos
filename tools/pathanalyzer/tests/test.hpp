// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef __TEST_HPP
#define __TEST_HPP

#include <stdlib.h>
#include <time.h>

#define INT_RAND (rand())
#define SMALL_POSITIVE_RAND (rand() & 0xFFFF)
#define BOOL_RAND ((bool)rand())
#define CHAR_RAND ((char)rand())
#define FRESH_SYMBOLIC (random())

// This will probably need some #ifdefs around it to support multiple
// compilers in the future, but that's ok.  The NOINLINE marker should
// only be used to prevent a test from having multiple path_start(),
// path_goal() or path_nongoal() calls in a single test.
#define NOINLINE __attribute__((noinline))

extern time_t global_time;

// Never inline the path markers, because if they get inlined, we
// won't find the symbols, which defeats the whole point of using
// these calls to parameterize our tests.

void NOINLINE path_start();

void NOINLINE path_goal();

void NOINLINE path_nongoal();

// APIs here

void example_constrain_arg (int, int);
int example_constrain_ret (int);
int example_counter (void);

// This is a dummy import that we will treat as an assert statement in the sense of GCL.
extern "C" void __assert_symbolic_dummy_import (bool);

#define assert_symbolic_name __assert_symbolic_dummy_import
#define assert_symbolic_name_str #assert_symbolic_name

#define assert_symbolic(bool) assert_symbolic_name (bool);

#endif
