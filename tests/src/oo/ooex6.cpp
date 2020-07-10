#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include "oohelper.hpp"


/*
 * show virtual destructor
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

  virtual int func1() {
    x = 2;
    y = 'b';
    z = -2;
    return y;
  }

  virtual int func2() {
    x = 3;
    y = 'c';
    z = -3;
    return x;
  }

  virtual int func3()=0;
};


class Derived : public Base {

private:
  int x;
public:

  Derived() {
    PRINT_CONSTRUCTOR_NAME(Derived);
    if (rand() % 10)
      x = func1();
    else
      x =func2();;
  }
  virtual ~Derived() {
    PRINT_DESTRUCTOR_NAME(Derived);
    x = 0;
  }
  DEFINE_PRINT_OPERATOR_DELETE(Derived);

  int func3() {
    return x + 1;
  }
};

int main() {

    Base *b = new Derived();
    int j = b->func3();
    delete b;
    return j;

}
