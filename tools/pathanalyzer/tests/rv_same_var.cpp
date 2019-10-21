// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  return n + 1;
}
int main() {
  path_start();
  int n = SMALL_POSITIVE_RAND;
  n = func(n + 3);
  volatile int t = n; // volatile to prevent optimization of nongoal
  if (func(n + 4) < t) {
    path_nongoal();
  }
  if (n == 5) {
    path_goal();
  }
}
