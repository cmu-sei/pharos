// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

void func(int x, int y, int z, bool b, char c) {
  volatile int t = z; // volatile to prevent optimization of nongoal
  if (x==2 && y==(x+8) && b==false && z>7 && c==12) {
    path_goal();
    if (t < x) {
      path_nongoal();
    }
  }
}
int main() {
  path_start();
  int x = INT_RAND;
  int y = INT_RAND;
  int z = INT_RAND;
  bool b = BOOL_RAND;
  char c = CHAR_RAND;
  func(x, y, z, b, c);
}
