// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

// The goal of this test is just to trigger the different variants of
// operator new and delete.

#include <string>
#include "oohelper.hpp"

struct dummy {
  int x;
  int y;
  std::string hello;
  DEFINE_PRINT_CONSTRUCTOR(dummy);
  DEFINE_PRINT_DESTRUCTOR(dummy);
  DEFINE_PRINT_OPERATOR_DELETE(dummy);
};

#if ((defined(_MSVC_LANG) && _MSVC_LANG >= 201703L) || __cplusplus >= 201703L)
#define ALIGNME alignas(32)
#else
#define ALIGNME /**/
#endif

class ALIGNME Vec3d {
    double x, y, z;
};

void g() {
  // void* operator new  ( std::size_t count );
  dummy *d = new dummy;
  // void* operator new[]( std::size_t count );
  dummy *da = new dummy[42];
  // void* operator new  ( std::size_t count, std::align_val_t al );
  Vec3d *v = new Vec3d;
  // void* operator new[]( std::size_t count, std::align_val_t al );
  Vec3d *va = new Vec3d[10];

  // Microsoft debug heap
#ifdef _DEBUG
  // void* operator new(unsigned int, std::_DebugHeapTag_t const &, near char *, int)
  dummy *dd = new (_CLIENT_BLOCK, __FILE__, __LINE__) dummy;
  // void* operator new[](unsigned int, std::_DebugHeapTag_t const &, near char *, int)
  dummy *dda = new (_CLIENT_BLOCK, __FILE__, __LINE__) dummy[42];
#endif

  // void* operator new  ( std::size_t count, const std::nothrow_t& tag );
  dummy *dnt = new (std::nothrow) dummy;
  // void* operator new[]( std::size_t count, const std::nothrow_t&
  // tag );
  dummy *dant = new (std::nothrow) dummy[42];
  // void* operator new  ( std::size_t count,
  //                      std::align_val_t al, const std::nothrow_t& );
  Vec3d *vnt = new (std::nothrow) Vec3d;
  // void* operator new[]( std::size_t count,
  //                    std::align_val_t al, const std::nothrow_t& );
  Vec3d *vant = new (std::nothrow) Vec3d[10];

  // void* operator new  ( std::size_t count, void* ptr );
  d = new (d) dummy;
  // void* operator new[]( std::size_t count, void* ptr );
  da = new (da) dummy[42];

  delete d;
  delete[] da;

#ifdef _DEBUG
  delete dd;
  delete[] dda;
#endif

  if (dnt)
    delete dnt;
  if (dant)
    delete[] dant;
  if (vnt)
    delete vnt;
  if (vant)
    delete[] vant;

  delete v;
  delete[] va;

}

int main() {
  g();
}
