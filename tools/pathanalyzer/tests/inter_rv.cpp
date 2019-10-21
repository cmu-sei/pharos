// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int add(int n) {
  return n+1;
}
int far_add(int n) {
  return add(n);
}
int func1() {
  int n = SMALL_POSITIVE_RAND; // 3
  n = far_add(n); // n = 3+1 = 4
  return n;
}
int main() {
  int n;
  path_start();
  n = func1();
  n += func1();
  if (n == 5) {
    path_goal();
  }
  volatile int t = n; // volatile to prevent optimization of nongoal
  if (t == 0) {
    path_nongoal();
  }
}
