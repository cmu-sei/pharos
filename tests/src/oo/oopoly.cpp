// Copyright 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include "oohelper.hpp"
#include <iostream>

class Shape {
public:
  DEFINE_PRINT_CONSTRUCTOR(Shape);
  DEFINE_PRINT_DESTRUCTOR(Shape);
  DEFINE_PRINT_OPERATOR_DELETE(Shape);
  virtual void draw()=0;
};

class Rectangle : public Shape {
public:
  DEFINE_PRINT_CONSTRUCTOR(Rectangle);
  DEFINE_PRINT_DESTRUCTOR(Rectangle);
  DEFINE_PRINT_OPERATOR_DELETE(Rectangle);
  virtual void draw() {
    std::cout << "Drawing Rectangle" << std::endl;
  }
};

class Circle : public Shape {
public:
  DEFINE_PRINT_CONSTRUCTOR(Circle);
  DEFINE_PRINT_DESTRUCTOR(Circle);
  DEFINE_PRINT_OPERATOR_DELETE(Circle);
  virtual void draw() {
    std::cout << "Drawing Circle" << std::endl;
  }
};

class Triangle : public Shape {
public:
  DEFINE_PRINT_CONSTRUCTOR(Triangle);
  DEFINE_PRINT_DESTRUCTOR(Triangle);
  DEFINE_PRINT_OPERATOR_DELETE(Triangle);
  virtual void draw() {
    std::cout << "Drawing Triangle" << std::endl;
  }
};

int main() {
  Shape *s[3];
  s[0] = new Rectangle();
  s[1] = new Circle();
  s[2] = new Triangle();

  for (int i=0; i<3; i++) {
    s[i]->draw();
  }

  for (int i=0; i<3; i++) {
    delete s[i];
  }
}
