// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

volatile int x;

void func() {
  if (x == 11) {
    x = 7;
  }
}
void func2() {
  x = INT_RAND;
}
int main() {
  path_start();
  x = 13;
  func();
  if (x == 7) {
    func2();
  }
  path_goal();
  if (x == 4) {
    path_nongoal();
  }
}
