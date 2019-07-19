// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  return n+n;
}
int main() {
  int n = INT_RAND;
  path_start();
  int x = func(n);

  if (x==20) {
    path_goal();
  }
}
