// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int goal=0;
  int n=INT_RAND;

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
            goal = -100;
          }
        }
        else {
          goal =  -75;
        }
      }
      else {
        path_goal();
      }
    }
    else {
      goal = -10;
    }
  }

  return goal;
}
