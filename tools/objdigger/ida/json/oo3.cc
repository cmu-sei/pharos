#include <iostream>

class Cls0 { 
public:
  virtual void func1() { 
    std::cout << "Cls0::func1()" << std::endl;
  }
};

class Cls1 : public Cls0 { 
public:
  int x;
  char y;
  virtual void func1() { 
    std::cout << "Cls1::func1()" << std::endl;
  }
  void func2() { 
    std::cout << "Cls1::func2()" << std::endl;
  }
};


struct Str1 { 
  int x,y;
  char s[50];
};

class Cls2 { 
public:
  struct Str1 s;
  int z;

  virtual void func3() { 
    std::cout << "Cls2::func3()" << std::endl;
  }
  virtual void func4() { 
    std::cout << "Cls2::func4()" << std::endl;
  }
};

class Cls3 : public Cls1, public Cls2 { 

public:
  int i;
  Cls3() { 
    i = 42;
  }
  virtual void func1() { 
    std::cout << "Cls3::func1()" << std::endl;
  }
  virtual void func3() { 
    std::cout << "Cls3::func3()" << std::endl;
  }
};

int main() { 
  Cls3 *e = new Cls3();
  Cls1 *f = new Cls3();
  Cls1 *c1 = new Cls1();

  c1->func2();

  e->func1();
  e->func3();
  e->func4();


  f->func1();

  delete e;
  delete f;
  delete c1;
}
