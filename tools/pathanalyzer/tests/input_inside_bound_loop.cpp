// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  int sum;
  path_start();
  sum = 0;

  while (sum < 100) {
    sum += INT_RAND;
  }

  path_goal ();

  return sum;
}
