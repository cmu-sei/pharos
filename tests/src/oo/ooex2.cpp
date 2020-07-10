// Copyright 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include "oohelper.hpp"

/*
 * show single inheritance
 */

class Base  {
private:
  int x;
  char y;
public:
  int z;

  Base() {
    PRINT_CONSTRUCTOR_NAME(Base);
    x = 1;
    y = 'a';
    z = -1;
  }

  DEFINE_PRINT_DESTRUCTOR(Base);
  DEFINE_PRINT_OPERATOR_DELETE(Base);

  void func1() {
    x = 2;
    y = 'b';
    z = -2;
  }

  void func2() {
    x = 3;
    y = 'c';
    z = -3;
  }

  int func3() {
    return x + y;
  }
};


class Derived : public Base {

private:
  int x;

public:

  Derived() {
    PRINT_CONSTRUCTOR_NAME(Derived);
    if (rand() % 10)
      x = func3();
    else
      x = z;
  }

  DEFINE_PRINT_DESTRUCTOR(Derived);
  DEFINE_PRINT_OPERATOR_DELETE(Derived);

  int func4() {
    return x + 1;
  }
};

int main() {


    Derived *b = new Derived();
    int j = b->func4();
    delete b;
    return j;

}




