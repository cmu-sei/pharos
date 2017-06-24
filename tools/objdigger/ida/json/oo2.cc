#include <iostream>

class Cls0 { 
public:
  virtual void func1() { 
    std::cout << "Cls0::func1()" << std::endl;
  }
};

class Cls1 : public Cls0 { 
public:
  virtual void func1() { 
    std::cout << "Cls1::func1()" << std::endl;
  }
};

class Cls2 : public Cls1 { 
public:
  virtual void func1() { 
    std::cout << "Cls2::func1()" << std::endl;
  }
};

class Cls3 : public Cls2 { 
public:
  virtual void func1() { 
    std::cout << "Cls3::func1()" << std::endl;
  }
};


int main() { 
  Cls3 * cls3 = new Cls3();

  cls3->func1();

}
