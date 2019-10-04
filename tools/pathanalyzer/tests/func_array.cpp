// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

volatile int x = 2;

void func1() {
  x = 3;
}
void func2() {
  x = 4;
}
void func3() {
  x = 5;
}
void func4() {
  x = 6;
}
int main() {
  void(*funcs[])() = { func1, func2, func3, func4 };
  path_start();
  int max = INT_RAND % 4;
  for (int i = 0; i < max; i++) {
    (*funcs[i])();
  }
  if (x == 5) {
    path_goal();
  }
  if (x == 7) {
    path_nongoal();
  }
}
