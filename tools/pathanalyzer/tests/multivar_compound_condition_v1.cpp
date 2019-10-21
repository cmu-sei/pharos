// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int goal=0;
  int n=INT_RAND;
  int x=INT_RAND;

  if (n > 2 && x <= 10) {
    goal = 1;
  }
  else if (n >= 11 && x < 20) {
    path_goal();
  }
  else {
    goal = 3;
  }

  volatile int t = goal; // volatile to prevent optimization of nongoal
  if (t == 2) {
    path_nongoal();
  }

  return goal;
}
