// Copyright 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdlib.h>
#include "oohelper.hpp"

/*
 * This basic class variable and method access
 */
class ClassA {
private:
  int c,d;
  short g;
public:
        int a;

  ClassA() {
    PRINT_CONSTRUCTOR_NAME(ClassA);
    c = d = 42;
    g = 24;
  }
  DEFINE_PRINT_DESTRUCTOR(ClassA);
  DEFINE_PRINT_OPERATOR_DELETE(ClassA);
  int func1() { return (int)rand(); }
  int func2() { return c + d; }


};

int main() {

    ClassA *a = new ClassA();
    a->a = 4;
    a->a += a->func1() + a->func2();
    delete a;
    a = NULL;

    ClassA b;
    b.a = 10;
    b.a -= b.func1() - b.func2();

    return 0;

}
