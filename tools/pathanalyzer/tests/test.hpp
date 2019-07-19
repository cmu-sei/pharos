// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdlib.h>
#include <time.h>

#define INT_RAND (rand())
#define BOOL_RAND ((bool)rand())
#define CHAR_RAND ((char)rand())

// This will probably need some #ifdefs around it to support multiple
// compilers in the future, but that's ok.  The NOINLINE marker should
// only be used to prevent a test from having multiple path_start(),
// path_goal() or path_nongoal() calls in a single test.
#define NOINLINE __attribute__((noinline))

time_t global_time;

void path_start() {
  time(&global_time);
}

void path_goal() {
  time(&global_time);
}

void path_nongoal() {
  time(&global_time);
}
