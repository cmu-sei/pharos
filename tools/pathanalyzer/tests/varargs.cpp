// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdarg.h>
#include "test.hpp"
#ifdef DEBUG
#include <stdio.h>
#endif

int func(int count, ...) {
  va_list argp;
  va_start(argp, count);

  int sum = 0;
  for (int n = 0; n < count; n++) {
    int t = va_arg(argp, int);
    // All summations are of _even_ values.
    int x = t & 0xFFFE;
    sum += x;
#ifdef DEBUG
    printf("Summing %d %d %d\n", t, x, sum);
#endif
  }

  va_end(argp);
  return sum;
}

int main() {
  path_start();
  int a = SMALL_POSITIVE_RAND;
  int b = SMALL_POSITIVE_RAND;
  int c = SMALL_POSITIVE_RAND;
  int d = SMALL_POSITIVE_RAND;
  int e = SMALL_POSITIVE_RAND;

  int sum = func(5, a, b, c, d, e);
#ifdef DEBUG
  printf("%d+%d+%d+%d+%d=%d (%d)\n", a, b, c, d, e, sum, sum % 2);
#endif

  // A sum of even values must be even.
  if (sum % 2 == 0) {
    path_goal();
  }
  // And not odd.
  else {
    path_nongoal();
  }
}
