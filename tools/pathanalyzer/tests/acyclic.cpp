// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  volatile bool maybe;
  path_start ();

  maybe = 0;

  for (int i = 0; i >= 0; i++) {
  }

  path_goal ();

  return 0;
}
