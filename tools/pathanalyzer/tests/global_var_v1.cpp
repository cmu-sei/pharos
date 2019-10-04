// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

volatile int x;

int main() {
  path_start();
  x = INT_RAND;
  if (x == 4) {
    path_goal();
    if (x != 4) {
      path_nongoal();
    }
  }
}
