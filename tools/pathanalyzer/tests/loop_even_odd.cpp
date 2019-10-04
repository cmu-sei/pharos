// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  volatile int n = INT_RAND;
  int x = INT_RAND;
  x = x & 0xf;
  for (int i = 0; i < x+1; i++) {
    n *= 2;
  }
  if (n != 0 && (n % 2) == 0) {
    path_goal();
  }
  if (n != 0 && (n % 2) == 1) {
    path_nongoal();
  }
}
