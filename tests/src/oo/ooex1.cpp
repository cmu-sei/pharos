// Copyright 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include "oohelper.hpp"

/*
 * show object composition
 */

class Composite  {
private:
  int x;
  char y;
public:

  Composite() {
    PRINT_CONSTRUCTOR_NAME(Composite);
    x = 1;
    y = 'a';
  }

  DEFINE_PRINT_DESTRUCTOR(Composite);
  DEFINE_PRINT_OPERATOR_DELETE(Composite);

  void func1() {
    x = 2;
    y = 'b';
  }

  void func2() {
    x = 3;
    y = 'c';
  }

  int func3() {
    return x + y;
  }
};


class Derived {

private:
  int x;
  Composite c, *c2;

public:

  Derived() {
    PRINT_CONSTRUCTOR_NAME(Derived);
    if (rand() % 10)
      c2 = new Composite();
    x = c.func3();
  }

  ~Derived() {
    PRINT_DESTRUCTOR_NAME(Derived);
    if (c2) {
      delete c2;
    }
  }

  DEFINE_PRINT_OPERATOR_DELETE(Derived);

  int func4() {
    if (c2 != 0)
      return c2->func3();
    return c.func3();
  }

  int func5(Composite c3, int y) {
    return y + c3.func3() + x;
  }
};

int main() {

    Derived *b = new Derived();
    b->func4();

    Composite c;
    int j = c.func3() + b->func5(c,5);
    delete b;
}

