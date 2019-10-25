// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void func(int n, int k, int j) {
  path_start();
  int x=0;

  if (n == 0) {
    x++;
  }
  if (k == 0) {
    x++;
  }
  if (j == 0) {
    x++;
  }
  if (x == 3) {
    path_goal();
  }
  // Not enough increments to reach 5.
  volatile int t = x; // volatile to prevent optimization of nongoal
  if (t == 5) {
    path_nongoal();
  }
}

int main() {
  func(INT_RAND, INT_RAND, INT_RAND);
}
