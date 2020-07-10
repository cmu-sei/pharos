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

class Group: public Inner1, public Inner2 {
public:
  int g;

  Group() {
    PRINT_CONSTRUCTOR_NAME(Group);
    g = 0x22;
  }

  DEFINE_PRINT_DESTRUCTOR(Group);
  DEFINE_PRINT_OPERATOR_DELETE(Group);
};

class Root: public Group {
public:
  int r;

  Root() {
    PRINT_CONSTRUCTOR_NAME(Root);
    r = 0x17;
  }

  DEFINE_PRINT_DESTRUCTOR(Root);
  DEFINE_PRINT_OPERATOR_DELETE(Root);
};

int main() {
  Root r;
  r.func11();
  r.func12();
  r.func21();
  r.func22();
  return 0;
}


