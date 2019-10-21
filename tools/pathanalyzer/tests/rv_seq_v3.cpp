// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  return n+1;
}
int main() {
  path_start();
  int n = INT_RAND;
  volatile int x = n; // volatile to prevent optimization of nongoal
  n = func(n);
  if (n==37) { // n must start as 36
    path_goal();
  }
  if (x == n) {
    path_nongoal();
  }
}
