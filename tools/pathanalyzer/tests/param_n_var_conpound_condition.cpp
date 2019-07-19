// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  path_start();
  int goal=0;
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

  return goal;
}
int main() {
  func(INT_RAND);
}
