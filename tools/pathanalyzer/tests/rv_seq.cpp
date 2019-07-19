// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  return n+1;
}
int main() {
  int n = INT_RAND;
  path_start();
  n = func(n);

  if (n==37) { // n must start as 36
    path_goal();
  }
}
