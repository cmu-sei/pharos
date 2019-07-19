// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void func2(int n) {
  if (n==5) {
    // This is only reachable when the n==5 condition is true
    path_goal();
  }
}
void func1(int n) {
  if (n==5) {
    func2(n); // Only valid option
  }
  else if (n>5) {
    func2(n);
  }
  else {
    func2(n+0x42); // not valid because the arg!=5
  }
}
int main() {
  path_start();
  func1(INT_RAND);
}
