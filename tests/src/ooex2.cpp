#include <stdio.h>
#include <math.h>
#include <stdlib.h>



/*
 * show single inheritance 
 */

class Base  {
private:
  int x;
  char y;
public:
  int z;

  Base() { 
    x = 1; 
    y = 'a'; 
    z = -1;
  }

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
    return x + y;
  }
};


class Derived : public Base {

private:
  int x;
  
public:
  
  Derived() {  
    if (rand() % 10)
      x = func3();
    else 
      x = z;
  }  
  int func4() {
    return x + 1;
  }
};

int main() {
  

    Derived *b = new Derived();
    int j = b->func4();      
    delete b;
    return j;
 
}
    
    
    

