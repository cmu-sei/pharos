// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int global_thing = 0;

void func2(const char* xml) {
  if (*xml == 'x') {
    global_thing = 1;
  }
}

void func(const char *xml, unsigned int qty) {
  unsigned int count = 0;

  while (*xml != 0) {
    if (count >= qty) {
      path_goal();
      break;
    }

    // This code has no effect on the reachability at all because it does nothing but set a
    // global variable, yet SPACER has more trouble with this test than the previous one.  Why?
    func2(xml);
    xml ++;

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
