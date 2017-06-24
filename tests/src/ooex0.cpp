#include <stdlib.h>
#include <stdio.h>

/*
 * This basic class variable and method access
 */
class ClassA { 
private:
  int c,d;
  short g;
public:
	int a;
    
  ClassA() { 
    c = d = 42;
    g = 24;
  }
  ~ClassA() { printf("ClassA::DTOR"); }
  int func1() { return (int)rand(); }
  int func2() { return c + d; }
    
 
};

int main() {
  
    ClassA *a = new ClassA();
    a->a = 4;
    a->a += a->func1() + a->func2();
    delete a;
    a = NULL;
    
    ClassA b;
    b.a = 10;
    b.a -= b.func1() - b.func2();
    
    return 0;
  
}
