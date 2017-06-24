

/*
Consider this arrangement:

class A { public: void Foo() {} };
class B : public A {};
class C : public A {};
class D : public B, public C {};


with this arrangement of classes you get a diamond:

  A
 / \
B   C
 \ /
  D

So, when you instantiate D you will get two instances of A (one for B
and one for C).

Using virtual inheritance eliminats this problem:

class A size(4):
        +---
 0      | a
        +---



class B size(12):
        +---
 0      | {vbptr}
 4      | b
        +---
        +--- (virtual base A)
 8      | a
        +---

B::$vbtable@:
 0      | 0
 1      | 8 (Bd(B+0)A)


vbi:       class  offset o.vbptr  o.vbte fVtorDisp
               A       8       0       4 0


class C size(12):
        +---
 0      | {vbptr}
 4      | c
        +---
        +--- (virtual base A)
 8      | a
        +---

C::$vbtable@:
 0      | 0
 1      | 8 (Cd(C+0)A)


vbi:       class  offset o.vbptr  o.vbte fVtorDisp
               A       8       0       4 0


class D size(24):
        +---
        | +--- (base class B)
 0      | | {vbptr}
 4      | | b
        | +---
        | +--- (base class C)
 8      | | {vbptr}
12      | | c
        | +---
16      | d
        +---
        +--- (virtual base A)
20      | a
        +---

D::$vbtable@B@:
 0      | 0
 1      | 20 (Dd(B+0)A)

D::$vbtable@C@:
 0      | 0
 1      | 12 (Dd(C+0)A)


vbi:       class  offset o.vbptr  o.vbte fVtorDisp
               A      20       0       4 0


Note that B and C don't contain A even though they derive from
A. Rather, B and C contain 'virtual base class tables'. These tables
enssentially bind a parent to a child class at runtime. 

*/


class A { 
public: 
  A() { 
    a = 0xa;
    b = 0xb;
    c = 'c';
  }
  int a;
  short b;
  char c;
};

class B : public virtual A { 
public:
  B() {
    b = 0xB;
  }
  int b;
};

class C : public virtual A {
public:
  C() {
    c = 0xC;
  }
  int c;
};

class D : public B, public C {
public:
  D() {
    d = 0xD;
  }
  int d;
};

int main () { 

  D *d = new D();
  d->a = 41;
  d->b = 42;
  d->c = 43;
  d->d = 44;

  B *b;
  b->a = 40;
  b->A::b = -0xb;

}


