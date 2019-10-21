// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func1(int x) {
  if (x > 2 && x < 100) {
    path_goal();
  }
  if (x > 100) {
    path_nongoal();
  }
  return 0;
}
void func0() {
  int n=INT_RAND;
  if (n==4) {
    func1(n);
  }
}
int main() {
  path_start();
  func0();
}
