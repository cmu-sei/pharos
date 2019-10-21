// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func1(int x) {
  if (x == 4) {
    path_goal();
  }
  if (x == 200) {
    path_nongoal();
  }
  return 0;
}
void func0() {
  int n=INT_RAND;
  if (n > 2 && n < 100) {
    func1(n);
  }
}
int main() {
  path_start();
  func0();
}
