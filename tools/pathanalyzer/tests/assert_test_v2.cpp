// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  volatile int x = example_constrain_ret (43);
  if (x == 43)
    path_goal();
  else
    path_nongoal();
}
