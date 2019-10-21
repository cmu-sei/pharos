// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func2(int n) {
  if (n&1) return n+2; // odd
  return n+1;
}
int func1(int n) {
  return func2(n);
}
int main() {
  int n = INT_RAND; // n = 1
  path_start();
  if (n >= 0 && n < 10) {
    n = func1(n); // n = 3
    n = func1(n); //n = 5
    if (n == 5) {
      path_goal();
    }
    // Compiler optimization didn't figure this one out...
    if (n == 2) {
      path_nongoal();
    }
  }
}
