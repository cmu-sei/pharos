// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func2(int n) { //1
  if (n%2 == 0) return n+2;
  return n+3; // ret 4
}
int func1(int n) {
  return func2(n)+1; // ret 5
}
int func0(int n) {
  return func1(n); // 1
}
int main() {
  int n = INT_RAND; // choose n = 1
  path_start();
  if (n >= 0 && n < 10) { // n is positive
    n = func0(n); // n = (1+3)+1 = 5
    volatile int x = n; // volatile to prevent optimization of nongoal
    if (n == 5) {
      path_goal();
    }
    if (x == 2) { // n = n +3 or +4
      path_nongoal();
    }
  }
}
