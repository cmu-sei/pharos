// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int count) {
  if (count==0) {
    path_goal();
    return 0;
  }
  return count+func(count-1);
}

int main() {
  path_start();
  int n = INT_RAND;
  int sum = func(n);
  if (sum < n) {
    path_nongoal();
  }
  return sum;
}
