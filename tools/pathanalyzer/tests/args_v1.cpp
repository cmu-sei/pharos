// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main(int argc, char *argv[]) {
  path_start();

  volatile int ac = argc;

  char x = CHAR_RAND;
  if (argc == 2 && argv[1][0] == x) {
    path_goal();
  }
  else if (ac == 2 && argv[1][0] == x) {
    path_nongoal();
  }
}
