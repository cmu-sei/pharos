// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int x = INT_RAND;
  int y = INT_RAND;
  int z = INT_RAND;
  bool b = BOOL_RAND;
  char c = CHAR_RAND;

  if ( (x > 2 && y < 10) || (b == false && z == 7) || (b || c == 'c')) {
    path_goal();
    if (y == 11 && z == 8 && (b == false) && c == 'd') {
      path_nongoal();
    }
  }
}
