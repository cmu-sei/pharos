// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int add(int n) {
  return n+1;
}
int main() {
  int n = INT_RAND; // n = 1
  path_start();
  n = add(n); // n = 1+1 = 2
  n = add(n+2); // 5 = 2+2+1
  if (n == 5) {
    path_goal();
  }
}
