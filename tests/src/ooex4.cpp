#include <stdio.h>
#include <math.h>
#include <stdlib.h>



/*
 * show virtual functions 
 */

class Base  {
private:
  int x;
  char y;
  int z;
public:
  

  Base() { 
    x = 1; 
    y = 'a'; 
    z = -1;
  }

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
    if (rand() % 10)
      x = func1();
    else 
      x =func2();;
  }  
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
    
    
    

