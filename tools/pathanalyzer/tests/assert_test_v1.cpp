// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  volatile int x = rand ();
  example_constrain_arg (x, 42);
  if (x == 42)
    path_goal();
  else
    path_nongoal();
}
