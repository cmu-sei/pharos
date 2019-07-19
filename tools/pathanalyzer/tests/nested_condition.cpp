// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n=INT_RAND;

  if (n >= 1) {
    if (n >= 10) {
      if (n >= 50) {
        if (n >= 75) {
          if (n > 100) {
            path_goal();
          }
        }
      }
    }
  }
}
