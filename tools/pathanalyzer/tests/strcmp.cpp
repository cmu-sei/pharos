// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main () {
  path_start ();
  char str[20];

  if (__builtin_strcmp (str, "Hello world!") == 0) {
    path_goal ();
  }

  str[4] = 0;

  if (__builtin_strcmp (str, "Hello world!") == 0) {
    path_nongoal ();
  }
  return 0;
}
