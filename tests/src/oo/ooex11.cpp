// Copyright 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include "oohelper.hpp"

class Inner1 {
private:
  int x;
  int y;
  int z;

public:
  Inner1() {
    PRINT_CONSTRUCTOR_NAME(Inner1);
    x = 0x34;
    y = 0x35;
    z = 0x36;
  }

  DEFINE_PRINT_DESTRUCTOR(Inner1);
  DEFINE_PRINT_OPERATOR_DELETE(Inner1);

  virtual void func11() {
    x = 0x38;
  }
  virtual void func12() {
    y = 0x39;
  }
};

class Inner2 {
private:
  int a;
  int b;
  int c;
  int d;

public:

  Inner2() {
    PRINT_CONSTRUCTOR_NAME(Inner2);
    a = 0x46;
    b = 0x47;
    c = 0x48;
    d = 0x49;
  }

  DEFINE_PRINT_DESTRUCTOR(Inner2);
  DEFINE_PRINT_OPERATOR_DELETE(Inner2);

  virtual void func21() {
    b = 0x44;
  }
  virtual void func22() {
    c = 0x43;
  }
};


class DInner1: public Inner1 {
public:
  DEFINE_PRINT_CONSTRUCTOR(DInner1);
  DEFINE_PRINT_DESTRUCTOR(DInner1);
  DEFINE_PRINT_OPERATOR_DELETE(DInner1);
};
class DInner2: public Inner2 {
public:
  DEFINE_PRINT_CONSTRUCTOR(DInner2);
  DEFINE_PRINT_DESTRUCTOR(DInner2);
  DEFINE_PRINT_OPERATOR_DELETE(DInner2);
};


class DAInner1: public DInner1 {
public:
  DEFINE_PRINT_CONSTRUCTOR(DAInner1);
  DEFINE_PRINT_DESTRUCTOR(DAInner1);
  DEFINE_PRINT_OPERATOR_DELETE(DAInner1);
};
class DAInner2: public DInner2 {
public:
  DEFINE_PRINT_CONSTRUCTOR(DAInner2);
  DEFINE_PRINT_DESTRUCTOR(DAInner2);
  DEFINE_PRINT_OPERATOR_DELETE(DAInner2);
};


class Root {
public:
  DAInner1 dai1;
  DAInner2 dai2;
  int r;

  Root() {
    r = 0x17;
  }
};

int main() {
  Root r;
  r.dai1.func11();
  r.dai1.func12();
  r.dai2.func21();
  r.dai2.func22();
  return 0;
}
