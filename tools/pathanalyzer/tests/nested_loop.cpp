// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n = INT_RAND;
  volatile int x = n; // volatile to prevent optimization of nongoal
  for (int i = 0; i < n; i++) {
    for (int j = i; j < n; j++) {
      path_goal();
      if (i > x) {
        path_nongoal();
      }
    }
  }
}
