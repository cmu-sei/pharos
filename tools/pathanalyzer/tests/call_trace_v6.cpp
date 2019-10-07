// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int add(int n) {
  return n+1;
}
int far_add(int n) {
  return add(n);
}
void func() {
  int n = INT_RAND; // 3
  n = far_add(n); // n = 3+1 = 4
  n = far_add(n); // n = 4+1 = 5
  if (n == 5) {
    path_goal();
  }
}
int main() {
  path_start();
  func();
}
