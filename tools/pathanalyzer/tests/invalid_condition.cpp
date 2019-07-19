// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  volatile int n = 3;
  if (n == 2) {
    path_nongoal();
  }
}
