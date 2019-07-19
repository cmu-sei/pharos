// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

NOINLINE void func2() {
  path_goal();
}
void func1(int n) {
  if (n == 1) {
    func2();
  }
}
int main() {
  int n;

  path_start ();

  n = INT_RAND;

  if (n == 1) {
    func1(n);
  }
}
