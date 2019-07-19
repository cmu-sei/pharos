// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void func1(int n, int x) {
  if (n > 2 && x == 1) {
    path_goal();
  }
}
void func0(int x) {
  int n=INT_RAND;
  if (n==4 && x < 10) {
    func1(n, x);
  }
}
int main() {
  path_start();
  func0(INT_RAND);
}
