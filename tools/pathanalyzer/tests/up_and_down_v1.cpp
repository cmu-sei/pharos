// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int func1(int arg) {
  if (arg == 3) {
    return 11;
  }
  else {
    return 13;
  }
}

int func2(int arg) {
  if (arg == 9) {
    return func1(3);
  }
  else {
    return func1(4);
  }
}

int func3(int arg) {
  if (arg == 6) {
    return func2(7);
  }
  else {
    return func2(9);
  }
}

int func4(int arg) {
  if (arg != 2) {
    return 12;
  }
  else {
    return 8;
  }
}

int func5(int arg) {
  if (arg == 11) {
    return func4(2);
  }
  else {
    return func4(5);
  }
}

int main() {
  path_start();
  int x = INT_RAND;
  int y = func5(func3(x));
  if (y == 8) {
    path_goal();
  }
  volatile int t = y; // volatile to prevent optimization of nongoal
  if (t == 33) {
    path_nongoal();
  }
}
