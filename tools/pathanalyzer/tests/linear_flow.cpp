// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n = 0;
  n++;
  path_goal();
  volatile int t = n; // volatile to prevent optimization of nongoal
  if (t == 0) {
    path_nongoal();
  }
  return n;
}
