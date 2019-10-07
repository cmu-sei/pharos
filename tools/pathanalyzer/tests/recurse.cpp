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
  int sum = func(INT_RAND);
  path_goal();
  return sum;
}
