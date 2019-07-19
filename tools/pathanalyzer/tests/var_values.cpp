// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {

  int x, y, z;
  bool b;
  char c;

  path_start();

  x = INT_RAND;
  y = INT_RAND;
  z = INT_RAND;
  b = BOOL_RAND;
  c = CHAR_RAND;

  if (x==2 && y==(x+8) && b==false && z>7 && c==12) {
    path_goal();
  }
}
