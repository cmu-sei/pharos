// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();
  int n=INT_RAND;
  for (int i=0; i < n; i++) {
    for (int j=i; i < n; j++) {
      path_goal();
    }
  }
}
