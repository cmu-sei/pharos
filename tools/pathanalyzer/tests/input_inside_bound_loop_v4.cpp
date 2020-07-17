// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int sum = 51;

  while (sum < 100) {
    int x = INT_RAND;
    if (x < 0 || x > 10) break;
    sum += x;
  }

  path_goal ();

  volatile int t = sum; // volatile to prevent optimization of nongoal
  if (t < 50) {
    path_nongoal();
  }

  return sum;
}
