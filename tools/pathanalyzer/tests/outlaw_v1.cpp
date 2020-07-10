// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

#define SUCCESS 1

int func2(size_t size) {
  size_t bytes_left = size;
  size_t rx_bytes_local = 0;

  // Fails in WP because of loop unrolling?
  while(bytes_left) {
    rx_bytes_local = 1;
    bytes_left -= rx_bytes_local;
  }

  return 3;
}

size_t func(size_t size) {
  if (func2(size) == 3) {
    return SUCCESS;
  }
  else {
    return 7;
  }
}

int main() {
  path_start();

  size_t ret = SUCCESS;
  volatile size_t s = 4;

  ret = func(s);



  path_goal();
  if (s == 5) {
    path_nongoal();
  }


  return ret;
}
