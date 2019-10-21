// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  return n+1;
}
int main() {
  path_start();
  int n = INT_RAND; // n = 3
  volatile int x = n; // volatile to prevent optimization of nongoal
  n = func(n); // n = 4
  n = func(n); // n = 5
  if (n == 5) {
    path_goal();
  }
  if (x == n) {
    path_nongoal();
  }
}
