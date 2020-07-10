// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int global_thing = 0;

int func2(const char* xml) {
  if (*xml == 'x') {
    global_thing = 1;
    return 2;
  }
  else if (*xml == '!') {
    return -1;
  }
  return 1;
}

void func(const char *xml, unsigned int qty) {
  unsigned int count = 0;
  int ret;

  while (*xml != 0) {
    if (count >= qty) {
      path_goal();
      break;
    }

    // This code has no effect on the reachability because while it changes where xml is
    // pointing, it doesn't affect count or qty.  It could short circuit the loop, preventing
    // us from reaching the nongoal(), but isn't that kind of the point?  Can we figure that
    // out?
    ret = func2(xml);
    if (0 > ret) { return; }
    xml += ret;

    count++;
    if (count > qty) {
      path_nongoal();
    }
  }

}

int main() {
  path_start();

  const char *xml = "Testing";
  unsigned int q = SMALL_POSITIVE_RAND;
  func(xml, q);
}
