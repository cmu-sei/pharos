// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func3(int n) {
  return n-n;
}
int func2(int n) {
  return n+n;
}
int  func1(int n) {
  if (n) return func2(n+1);
  else return func3(n);
}
int main() {
  int n = INT_RAND;
  path_start();
  if (n<5) {
    n = func1(n); // 6 = (n+1)+(n+1) = 2n+2 = 2 to begin with
  }
  else {
    n = func1(n-1);
  }
  if (n == 6) {
    path_goal();
  }
}
