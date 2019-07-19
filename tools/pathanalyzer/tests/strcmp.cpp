// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main () {
  char str[20];
  path_start ();

  if (__builtin_strcmp (str, "Hello world!") == 0) {
    path_goal ();
  }
  return 0;
}
