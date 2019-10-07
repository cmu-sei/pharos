// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

class Cls {
 private:
  volatile int member = 3;
 public:
  Cls() {
    member = 4;
  }

  int get_member() {
    return member;
  }
};

int main() {
  path_start();
  Cls* c = new Cls();
  if (c->get_member() == 4) {
    path_goal();
  }
  else {
    path_nongoal();
  }
}
