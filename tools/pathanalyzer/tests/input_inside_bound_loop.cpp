// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int sum = 0;

  while (sum < 100) {
    sum += INT_RAND;
  }

  path_goal ();

  volatile int t = sum; // volatile to prevent optimization of nongoal
  if (t == 0) {
    path_nongoal();
  }

  return sum;
}
