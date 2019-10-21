// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  path_goal();
  // Minimal way to produce an impossible condition?
  volatile int x = 3;
  volatile int y = x;
  if (x != y) {
    path_nongoal();
  }
}
