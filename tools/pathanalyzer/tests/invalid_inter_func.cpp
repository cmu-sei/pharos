// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void func(volatile int n) {
  if (n == 2 && n == 10) {
    path_nongoal();
  }
}
int main() {
  path_start();
  func(INT_RAND);
}
