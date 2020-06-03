// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void func(int i, int j, int k) {
  path_start();
  int x=0,y=0;

  if (i==3 && j==4 && k==5) {
    y = 1;
  }
  else {
    if (i==6 && j==7 && k==8) {
      y = 2;
    }
  }

  if (y == 2) {
    x = 42;
  }
  else {
    x = 43;
  }

  if (x == 42) {
    path_goal();
  }
  volatile int t = x; // volatile to prevent optimization of nongoal
  if (t == 44) {
    path_nongoal();
  }
  return;
}

int main(void) {
  func(INT_RAND, INT_RAND, INT_RAND);
  return 0;
}

