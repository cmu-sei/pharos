// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n = INT_RAND;
  if (n == 2) {
    n++;
  }
  path_goal();
  volatile int g = 3;
  if (g == 2) {
    path_nongoal();
  }
}
