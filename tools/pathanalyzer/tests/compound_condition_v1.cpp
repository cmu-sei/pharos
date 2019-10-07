// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n=INT_RAND;
  if (n > 2 && n < 10) {
    path_goal();
  }
  if (n == 2 && n == 10) {
    path_nongoal();
  }
}
