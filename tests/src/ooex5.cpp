#include <stdio.h>
#include <math.h>
#include <stdlib.h>

/*
 * show multiple inheritance with virtual functions
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
    return 1;
  } 

  virtual int func2() { 
    x = 3;
    y = 'c';
    z = -3;
    return 2;
  }
  
  virtual int func3()=0;
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

  virtual int func1() {  
    x = 200; 
    y = 'B'; 
    z = -200;
    return 1;
  } 

  virtual int func2() { 
    x = 300;
    y = 'C';
    z = -300;
    return 2;
  }
  
  virtual int func4()=0;
  
};

class Derived : public Base, public Base2 {

private:
  int x;
public:
  
  Derived() {  
    if (rand() % 10)
      x = Base::func2();
    else 
      x = Base2::func1();;
  }  

  virtual int func4() {
    return x - 1;
  }
  virtual int func3() {
    return x + 1;
  }

};

int main() {
  
    Base *b = new Derived();
    
    int j = b->func3() + ((Base2*)b)->func4();     
    delete b;

    return j + rand();;
 
}
    
    
    

