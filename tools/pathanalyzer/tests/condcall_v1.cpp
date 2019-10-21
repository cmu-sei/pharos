// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  if (n) return n + 2;
  else return n + 1;
}
int main() {
  int n = SMALL_POSITIVE_RAND;
  path_start();
  if (n < 5) {
    n = func(n);
  }
  else {
    n = func(n - 1);
  }
  if (n == 5) {
    path_goal();
  }
  volatile int x = n; // volatile to prevent optimization of nongoal
  if (x == 2) {
    path_nongoal();
  }
}
