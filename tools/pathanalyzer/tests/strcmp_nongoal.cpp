// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main () {
  char str[5];
  path_start ();

  str[4] = 0;

  if (__builtin_strcmp (str, "Hello world!") == 0) {
    path_nongoal ();
  }
  return 0;
}
