// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

// This function becomes inlined
NOINLINE int func1(int n) {
  path_goal();
  return n;
}
void func0(int n) {
  func1(n);
  func1(n+0x42);
}
int main() {
  path_start();
  func0(INT_RAND);
}
