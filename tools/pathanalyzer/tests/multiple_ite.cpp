// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int goal = 0;
  int n = INT_RAND;
  int x = INT_RAND;

  if (n == 1 ) {
    goal = 1;
  }
  else if (n == 2) {
    goal = 2;
  }
  else {
    goal = 3;
  }

  if (x > 2) {
    goal = 4;
  }
  else if (x >3 && x<7) {
    goal = 5;
  }
  else {
    goal = 6;
  }
  if (goal != 0) {
    path_goal();
  }

  volatile int t = goal; // volatile to prevent optimization of nongoal
  if (t == 0) {
    path_nongoal();
  }
}
