// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdexcept>
#include "test.hpp"

int func(int p) {
  if (p % 2 == 0) {
    return 5;
  }
  else {
    throw std::runtime_error("exception thrown!");
  }
}

int main() {
  path_start();

  volatile int x = 3;
  volatile int r = 7;

  try {
    r = func(x);
  }
  catch (std::runtime_error &e) {
    r = 4;
  }

  // R can be even is the exception is thrown.
  if (r % 2 == 0) {
    path_goal();
  }
  // But it's never one.
  else if (r == 1) {
    path_nongoal();
  }
}
