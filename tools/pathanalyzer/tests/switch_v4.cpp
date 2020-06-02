// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();

  char c = CHAR_RAND;
  // Even though this value is even, it's always overwritten with an odd value.
  volatile int x = 4;

  switch (c) {
   case 'a':
   case 'b':
   case 'c':
    x = 5;
    break;
   case 'g':
   case 'h':
    x = 42;
    // fallthru
   case 'l':
   case 'm':
   case 'n':
    x = x + 3;
    break;
   case 'x':
    x = 7;
    break;
   case 'y':
    x = 9;
    break;
   case 'z':
    x = 11;
    break;
   default:
    x = 13;
    break;
  }

  // All answers are odd.
  if (x % 2 == 1) {
    path_goal();
  }
  // But no answers are even.
  else {
    path_nongoal();
  }
}
