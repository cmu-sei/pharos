// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n=INT_RAND, k=INT_RAND, j=INT_RAND;
  int x=0;

  if ( n == 0 ) {
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
  // Not enough increments to reach 4.
  volatile int t = x; // volatile to prevent optimization of nongoal
  if (t == 4) {
    path_nongoal();
  }
}
