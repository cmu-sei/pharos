// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func(int count) {
  if (count==0) {
    return 0;
  }
  return count+func(count-1);
}

int main() {
  path_start();
  int n = SMALL_POSITIVE_RAND;
  int sum = func(n);
  path_goal();
  if (sum < n) {
    path_nongoal();
  }
  return sum;
}
