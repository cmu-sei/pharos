// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  volatile bool maybe;
  maybe = false;
  while (!maybe) {
    path_goal();
  }
  // Not reached.
  path_nongoal();
  return 0;
}
