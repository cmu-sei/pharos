// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  path_start();
  int goal = 0;
  volatile int x = n; // volatile to prevent optimization of nongoal

  if (n >= 1) {
    goal = 1;
    if (n >= 10) {
      goal = 10;
      if (n >= 50) {
        goal = 50;
        if (n >= 75) {
          goal = 75;
          if (n > 100) {
            goal = 100;
          }
          else {
            path_goal();
          }
        }
        else {
          goal = -75;
        }
      }
      else {
        goal = -50;
        if (x == 55) {
          path_nongoal();
        }
      }

    }
    else {
      goal = -10;
    }
  }

  return goal;
}
int main() {
  func(INT_RAND);
}
