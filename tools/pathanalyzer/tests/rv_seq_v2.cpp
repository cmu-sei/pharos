// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  return n + 1;
}
int main() {
  path_start();
  int n = INT_RAND;
  int n2 = func(n + 3);
  if (n2 == 5) {
    path_goal();
  }
  volatile int t = n2; // volatile to prevent optimization of nongoal
  if (n == t) {
    path_nongoal();
  }
}
