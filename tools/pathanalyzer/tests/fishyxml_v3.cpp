// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int global_thing = 0;

int func2(char* buf) {
  if (*buf == 'x') {
    *buf = 'y';
  }
  return 1;
}

void func(char *xml, unsigned int qty) {
  unsigned int count = 0;
  int ret;

  while (*xml != 0) {
    if (count >= qty) {
      path_goal();
      break;
    }

    // This code has no effect on the reachability because while it changes the values that xml
    // points to, it doesn't affect count or qty.  It could short circuit the loop, preventing
    // us from reaching the nongoal(), but isn't that kind of the point?  Compared to version
    // one of this test, version three does update stack memory.  Can we figure that out?
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

  char xml[20];
  unsigned int q = SMALL_POSITIVE_RAND;
  func(xml, q);
}
