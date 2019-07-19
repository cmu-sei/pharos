// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int n) {
  return n+1;
}
int main() {
  int n = INT_RAND;
  path_start();
  int n2 = func(n+3);
  if (n2 == 5) {
    path_goal();
  }
}
