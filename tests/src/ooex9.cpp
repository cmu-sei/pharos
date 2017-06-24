

/*


Combining virtual inheritance with virtual functions 

class A size(8):
        +---
 0      | {vfptr}
 4      | a
        +---

A::$vftable@:
        | &A_meta
        |  0
 0      | &A::get_a

A::get_a this adjustor: 0


class B size(20):
        +---
 0      | {vfptr}
 4      | {vbptr}
 8      | b
        +---
        +--- (virtual base A)
12      | {vfptr}
16      | a
        +---

B::$vftable@B@:
        | &B_meta
        |  0
 0      | &B::get_b

B::$vbtable@:
 0      | -4
 1      | 8 (Bd(B+4)A)

B::$vftable@A@:
        | -12
 0      | &A::get_a

B::get_b this adjustor: 0

vbi:       class  offset o.vbptr  o.vbte fVtorDisp
               A      12       4       4 0


class C size(20):
        +---
 0      | {vfptr}
 4      | {vbptr}
 8      | c
        +---
        +--- (virtual base A)
12      | {vfptr}
16      | a
        +---

C::$vftable@C@:
        | &C_meta
        |  0
 0      | &C::get_c

C::$vbtable@:
 0      | -4
 1      | 8 (Cd(C+4)A)

C::$vftable@A@:
        | -12
 0      | &A::get_a

C::get_c this adjustor: 0

vbi:       class  offset o.vbptr  o.vbte fVtorDisp
               A      12       4       4 0


class D size(36):
        +---
        | +--- (base class B)
 0      | | {vfptr}
 4      | | {vbptr}
 8      | | b
        | +---
        | +--- (base class C)
12      | | {vfptr}
16      | | {vbptr}
20      | | c
        | +---
24      | d
        +---
        +--- (virtual base A)
28      | {vfptr}
32      | a
        +---

D::$vftable@B@:
        | &D_meta
        |  0
 0      | &B::get_b
 1      | &D::get_d

D::$vftable@C@:
        | -12
 0      | &C::get_c

D::$vbtable@B@:
 0      | -4
 1      | 24 (Dd(B+4)A)

D::$vbtable@C@:
 0      | -4
 1      | 12 (Dd(C+4)A)

D::$vftable@A@:
        | -28
 0      | &A::get_a

D::get_d this adjustor: 0

vbi:       class  offset o.vbptr  o.vbte fVtorDisp
               A      28       4       4 0



*/


class A { 
public: 
  A() { 
    a = 0xa;
  }
  virtual int get_a() { 
    return a;
  }
  int a;
};

class B : public virtual A { 
public:
  B() {
    b = 0xB;
  }
  virtual int get_b() { 
    return b;
  }
  int b;
};

class C : public virtual A {
public:
  C() {
    c = 0xC;
  }
  virtual int get_c() { 
    return c;
  }
  int c;
};

class D : public B, public C {
public:
  D() {
    d = 0xD;
  }
  virtual int get_d() { 
    return d;
  }
  int d;
};

int main () { 

  D *d = new D();
  d->a = 41;
  d->b = 42;
  d->c = 43;
  d->b = 44;

  d->get_a();
  d->get_b();
  d->get_c();
  d->get_d();
  
  
}


