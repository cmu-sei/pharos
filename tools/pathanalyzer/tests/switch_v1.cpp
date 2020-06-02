// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();

  char c = CHAR_RAND;
  volatile int x = 1;

  switch (c) {
   case 'a':
   case 'b':
   case 'c':
    x = 5;
    break;
   case 'g':
   case 'h':
    x = 3;
    // fallthru
   case 'l':
   case 'm':
   case 'n':
    x = x + 2;
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

  // Choose 'y' as our random character.
  if (x == 9) {
    path_goal();
  }
  // But no answers are even.
  else if (x == 4) {
    path_nongoal();
  }
}
