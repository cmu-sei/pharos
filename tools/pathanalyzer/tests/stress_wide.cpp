// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  volatile int v0 = 0;
  volatile int v1 = 0;
  volatile int v2 = 0;
  volatile int v3 = 0;
  volatile int v4 = 0;
  volatile int v5 = 0;
  volatile int v6 = 0;

  path_start();
  int input = INT_RAND;

  if ((input & 1) == 0) {
    if ((input >> 0) & 1) {
      v0 = input;
    } else {
      v0 = input;
    }
  }
  else {
    if ((input >> 0) & 1) {
      // All FFs not copied!
      v0 = 0;
    } else {
      v0 = input;
    }
  }
  if ((input & 1) == 0) {
    if ((input >> 0) & 1) {
      v1 = input;
    } else {
      v1 = input;
    }
  }
  else {
    if ((input >> 0) & 1) {
      v1 = input;
    } else {
      v1 = input;
    }
  }
  if ((input & 1) == 0) {
    if ((input >> 0) & 1) {
      v2 = input;
    } else {
      v2 = input;
    }
  }
  else {
    if ((input >> 0) & 1) {
      v2 = input;
    } else {
      v2 = input;
    }
  }
  if ((input & 1) == 0) {
    if ((input >> 0) & 1) {
      v3 = input;
    } else {
      v3 = input;
    }
  }
  else {
    if ((input >> 0) & 1) {
      v3 = input;
    } else {
      v3 = input;
    }
  }
  if ((input & 1) == 0) {
    if ((input >> 0) & 1) {
      v4 = input;
    } else {
      v4 = input;
    }
  }
  else {
    if ((input >> 0) & 1) {
      v4 = input;
    } else {
      v4 = input;
    }
  }
  if ((input & 1) == 0) {
    if ((input >> 0) & 1) {
      v5 = input;
    } else {
      v5 = input;
    }
  }
  else {
    if ((input >> 0) & 1) {
      v5 = input;
    } else {
      v5 = input;
    }
  }
  if ((input & 1) == 0) {
    if ((input >> 0) & 1) {
      v6 = input;
    } else {
      v6 = input;
    }
  }
  else {
    if ((input >> 0) & 1) {
      v6 = input;
    } else {
      v6 = input;
    }
  }

  if (v0 == 0x2a &&
      v1 == 0x2a &&
      v2 == 0x2a &&
      v3 == 0x2a &&
      v4 == 0x2a &&
      v5 == 0x2a &&
      v6 == 0x2a) {
    path_goal();
  }
  if (v0 == 0xff &&
      v1 == 0xff &&
      v2 == 0xff &&
      v3 == 0xff &&
      v4 == 0xff &&
      v5 == 0xff &&
      v6 == 0xff) {
    path_nongoal();
  }
}
