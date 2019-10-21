// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void func1(int n) {
  if (n==6) {
    // This is only reachable when the n==6 condition is true
    path_goal();
  }
  // Not possible, because 4 becomes 5.
  if (n==4) {
    path_nongoal();
  }
}
void func0(int n) {
  if (n==5) {
    func1(n);
  }
  else if (n==4) {
    func1(n+1);
  }
  else {
    // Only valid option
    func1(n);
  }
}
int main() {
  path_start();
  func0(INT_RAND);
}
