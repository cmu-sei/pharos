// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

NOINLINE void func(int n) {
  path_start();
  if (n == 2) {
    n++;
  }
  path_goal();
}
int main() {
  func(INT_RAND);
}
