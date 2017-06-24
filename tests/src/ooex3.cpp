#include <stdio.h>
#include <math.h>
#include <stdlib.h>



/*
 * show multiple inheritance 
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
    return x +y;
  }
};


class Base2  {
private:
  int x;
  char y;
  int z;
public:

  Base2() { 
    x = -100; 
    y = 'A'; 
    z = -100;
  }

  void func1() {  
    x = 200; 
    y = 'B'; 
    z = -200;
  } 

  void func2() { 
    x = 300;
    y = 'C';
    z = -300;
  }
  
  int func3() {
    return x - y;
  }
};

class Derived : public Base, public Base2 {

private:
  int x;
public:
  
  Derived() {  
    if (rand() % 10)
      x = Base::func3();
    else 
      x = Base2::func3();;
  }  
  int func4() {
    return x + 1;
  }
};

int main() {
  

    Base *b = new Derived();
    int j = b->func3();   
    delete b;
    return j;
 
}
    
    
    

