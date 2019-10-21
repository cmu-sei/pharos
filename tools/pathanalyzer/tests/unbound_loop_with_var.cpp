// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n = INT_RAND;
  int i = 0;
  while (i < n) {
    if (n == 5) {
      path_goal();
    }
    ++i;
    if (i > n) {
      path_nongoal();
    }
  }
}
