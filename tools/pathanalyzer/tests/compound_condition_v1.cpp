// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n=INT_RAND;
  if (n > 2 && n < 10) {
    path_goal();
  }
  volatile int x = n; // volatile to prevent optimization of nongoal
  if (x == 2 && x == 10) {
    path_nongoal();
  }
}
