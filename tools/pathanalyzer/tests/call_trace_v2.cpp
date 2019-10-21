// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func2(int n) {
  return n+2;
}
int func1(int n) {
  return func2(n)+1;
}
int func0(int n) {
  return func1(n);
}
int main() {
  int n = INT_RAND; // 2
  path_start();
  if (n >= 0 && n < 10) {
    n = func0(n); // n = (0+3) +1 +1 = 3
    volatile int x = n; // volatile to prevent optimization of nongoal
    if (n == 5) {
      path_goal();
    }
    if (x == 2) {
      path_nongoal();
    }
  }
}

