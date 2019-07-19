// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void __attribute__ ((noinline)) writeThroughPointer (volatile int *x, int y) {
  *x = y;
}

int main () {
  volatile int t;
  path_start ();
  writeThroughPointer (&t, 42);
  if (t != 42) {
    path_nongoal ();
  }
  return 0;
}
