// Copyright 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <iostream>
#include "oohelper.hpp"

class Cls1 {
public:
  int x;
  char y;

  DEFINE_PRINT_CONSTRUCTOR(Cls1);
  DEFINE_PRINT_DESTRUCTOR(Cls1);
  DEFINE_PRINT_OPERATOR_DELETE(Cls1);
  virtual void func1() {
    std::cout << "Cls1::func1()" << std::endl;
  }
  void func2() {
    std::cout << "Cls1::func2()" << std::endl;
  }
};


struct Str1 {
  int x,y;
  char s[50];
};

class Cls2 {
public:
  struct Str1 s;
  int z;

  DEFINE_PRINT_CONSTRUCTOR(Cls2);
  DEFINE_PRINT_DESTRUCTOR(Cls2);
  DEFINE_PRINT_OPERATOR_DELETE(Cls2);
  virtual void func3() {
    std::cout << "Cls2::func3()" << std::endl;
  }
  virtual void func4() {
    std::cout << "Cls2::func4()" << std::endl;
  }
};

class Cls3 : public Cls1, public Cls2 {

public:
  int i;
  Cls3() {
    PRINT_CONSTRUCTOR_NAME(Cls3);
    i = 42;
  }
  DEFINE_PRINT_DESTRUCTOR(Cls3);
  DEFINE_PRINT_OPERATOR_DELETE(Cls3);
  virtual void func1() {
    std::cout << "Cls3::func1()" << std::endl;
  }
  virtual void func3() {
    std::cout << "Cls3::func3()" << std::endl;
  }
};

int main() {
  Cls3 *e = new Cls3();
  Cls1 *f = new Cls3();
  Cls1 *c1 = new Cls1();

  c1->func2();

  e->func1();
  e->func3();
  e->func4();


  f->func1();

  delete e;
  delete f;
  delete c1;
}
