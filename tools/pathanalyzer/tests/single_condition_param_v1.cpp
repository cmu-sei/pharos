// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

// Static so that if it gets inlined, the non-inlined copy is removed.
static void func(int n) {
  path_start();
  volatile int x = n; // volatile to prevent optimization of nongoal
  if (n == 2) {
    path_goal();
    if (x == 3) {
      path_nongoal();
    }
  }
}
int main() {
  func(INT_RAND);
}
