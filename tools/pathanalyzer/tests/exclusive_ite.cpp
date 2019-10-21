// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int goal = 0;
  int n=INT_RAND;

  if (n >= 100) {
    goal = 100;
  }
  else if (n > 75) {
    goal = 75;
  }
  else if (n > 50) {
    path_goal();
  }
  else if (n > 25) {
    goal = 25;
  }
  else if (n > 10) {
    goal = 10;
  }
  else {
    goal = 1;
  }

  // Not one of the possible values of goal.
  volatile int t = goal; // volatile to prevent optimization of nongoal
  if (t == 3) {
    path_nongoal();
  }

  return goal;
}
