// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  volatile int n=INT_RAND;
  volatile int x=INT_RAND;

  if ( n == x ) {
    x += 1;
    if ((n+1) == x) {
      path_goal();
    }
    if (n == (x+2)) {
      path_nongoal();
    }
  }
}
