// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n = INT_RAND;
  for (int i = 0; i < 9; i++) {
    n *= 2;
  }
  if (n != 0 && (n % 2) == 0) {
    path_goal();
  }
}
