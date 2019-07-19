// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

NOINLINE void func2() {
  path_nongoal();
}
void func1(volatile int n) {
  if (n == 0) {
    func2();
  }
}
int main() {
  int n = INT_RAND;
  path_start();
  // this simply makes the tree node smaller
  if (n == 1) {
    func1(n);
  }
}
