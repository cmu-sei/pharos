// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func3(int, int z) {
  if (z > 0) {
    return z;
  }
  else {
    return 0;
  }
}

int func2(int x, int, const char* c) {
  volatile int z = 2;
  if (c[0] == 'T') {
    return func3(x, z);
  }
  else {
    return func3(x, z+1) + 1;
  }
}

bool func1(int x, int y, int) {
  const char *c = "Testing";
  if (func2(x, y, c) > 1) {
    return true;
  }
  else {
    return false;
  }
}

int main() {
  path_start();

  volatile int x = 3;
  volatile int y = 4;
  volatile int z = 5;

  if (func1(x, y, z)) {
    path_goal();
  }
  else {
    path_nongoal();
  }
}
