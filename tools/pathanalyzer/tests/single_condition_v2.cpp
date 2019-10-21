// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n=INT_RAND;
  if (n == 2) {
    path_goal();
    n++;
    volatile int x = n; // volatile to prevent optimization of nongoal
    if (x == 2) {
      path_nongoal();
    }
  }
}
