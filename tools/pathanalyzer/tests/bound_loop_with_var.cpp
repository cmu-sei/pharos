// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  int n;
  path_start();
  n = (INT_RAND % 10) - 2;

  while (n < 10) {
    if (n == 9) {
      path_goal();
    }
    n++;
  }
}
