// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void writeThroughPointer (volatile int *x, int y) {
  *x = y;
}

int main () {
  path_start ();
  volatile int t = 1;
  writeThroughPointer (&t, 42);
  if (t == 42) {
    path_goal ();
  }
  else {
    path_nongoal ();
  }
  return 0;
}
