// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void func(volatile int n) {
  path_start();
  if (n > 2 && n < 10) {
    path_goal();
  }
  if (n == 3 && n == 4) {
    path_nongoal();
  }
}
int main() {
  func(INT_RAND);
}
