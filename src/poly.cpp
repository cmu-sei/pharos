#include <iostream>

class Shape { 
public:
  virtual void draw()=0;
};

class Rectangle : public Shape { 
public:
  virtual void draw() {
    std::cout << "Drawing Rectangle" << std::endl;
  }
};

class Circle : public Shape { 
public:
  virtual void draw() {
    std::cout << "Drawing Circle" << std::endl;
  }
};

class Triangle : public Shape { 
public:
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
}
