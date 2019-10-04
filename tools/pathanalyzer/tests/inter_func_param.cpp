// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void func1(volatile int n, int x) {
  if (n > 2 && x == 1) {
    path_goal();
  }
  if (n == 2 && n == 10) {
    path_nongoal();
  }
}
void func0(int x) {
  int n=INT_RAND;
  if (n==4 && x < 10) {
    func1(n, x);
  }
}
int main() {
  path_start();
  func0(INT_RAND);
}
