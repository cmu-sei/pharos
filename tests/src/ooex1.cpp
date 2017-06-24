#include <stdio.h>
#include <math.h>
#include <stdlib.h>



/*
 * show object composition 
 */

class Composite  {
private:
  int x;
  char y;
public:

  Composite() { 
    x = 1; 
    y = 'a'; 
  }

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
    if (rand() % 10)
      c2 = new Composite();
    x = c.func3();
  }  
  
  int func4() {
    if (c2 != 0)
      return c2->func3();
    return c.func3();
  }
  
  int func5(Composite c3, int y) { 
    return y + c3.func3() + x;
  }
};

void main() {

    Derived *b = new Derived();
    b->func4();      

    Composite c;
    int j = c.func3() + b->func5(c,5);
    delete b;
 
}
    
    
    

