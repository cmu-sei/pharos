// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  example_counter ();
  example_counter ();
  volatile int x = example_counter ();
  if (x == 45)
    path_goal();
  else
    path_nongoal();
}
