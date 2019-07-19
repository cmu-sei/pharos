// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  volatile bool maybe;
  path_start ();

  maybe = 0;

  while (!maybe) {

  }

  path_nongoal ();

  return 0;
}
