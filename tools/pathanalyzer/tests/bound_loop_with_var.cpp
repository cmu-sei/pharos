// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"
//#include "stdio.h"

int main() {
  path_start();
  //srand(time(NULL));
  int x = INT_RAND;
  int n = (x % 10) - 2;
  //printf("initial n=%d\n",n);
  while (n < 10) {
    //printf("loop n=%d\n",n);
    if (n == 9) {
      path_goal();
    }
    n++;
    volatile int t = n; // volatile to prevent optimization of nongoal
    if (t == 13) {
      path_nongoal();
    }
  }
}
