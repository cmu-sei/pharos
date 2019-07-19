// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  volatile int n=INT_RAND;
  if (n == 2 && n == -2) {
    path_nongoal();
  }
}
