// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  return n+n;
}
int main() {
  path_start();
  int n = INT_RAND;
  int x = func(n);

  if (x == 20) {
    path_goal();
  }
  if (x != 0 && x == n) {
    path_nongoal();
  }
}
