// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func3(int n) {
  return n - n;
}
int func2(int n) {
  return n + n;
}
int  func1(int n) {
  if (n) return func2(n + 1);
  else return func3(n);
}
int main() {
  path_start();
  int n = SMALL_POSITIVE_RAND;
  if (n < 5) {
    n = func1(n); // 6 = (n+1)+(n+1) = 2n+2 = 2 to begin with
  }
  else {
    n = func1(n + 1);
  }
  if (n == 6) {
    path_goal();
  }
  volatile int x = n; // volatile to prevent optimization of nongoal
  if (x == 1) {
    path_nongoal();
  }
}
