// Copyright 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include "oohelper.hpp"

/*
 * show multiple inheritance
 */

class Base  {
private:
  int x;
  char y;
  int z;
public:


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
    return x +y;
  }
};


class Base2  {
private:
  int x;
  char y;
  int z;
public:

  Base2() {
    PRINT_CONSTRUCTOR_NAME(Base2);
    x = -100;
    y = 'A';
    z = -100;
  }

  DEFINE_PRINT_DESTRUCTOR(Base2);
  DEFINE_PRINT_OPERATOR_DELETE(Base2);

  void func1() {
    x = 200;
    y = 'B';
    z = -200;
  }

  void func2() {
    x = 300;
    y = 'C';
    z = -300;
  }

  int func3() {
    return x - y;
  }
};

class Derived : public Base, public Base2 {

private:
  int x;
public:

  Derived() {
    PRINT_CONSTRUCTOR_NAME(Derived);
    if (rand() % 10)
      x = Base::func3();
    else
      x = Base2::func3();;
  }

  DEFINE_PRINT_DESTRUCTOR(Derived);
  DEFINE_PRINT_OPERATOR_DELETE(Derived);

  int func4() {
    return x + 1;
  }
};

int main() {


    Base *b = new Derived();
    int j = b->func3();
    delete b;
    return j;

}




