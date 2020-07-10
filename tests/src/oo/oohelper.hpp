#define _NOTHING /* */

#ifdef _CONSTRUCTOR_PRINT
#include <stdio.h>
#define PRINT_CONSTRUCTOR_NAME(CLASS) printf(#CLASS "::" #CLASS "()\n");
#define DEFINE_PRINT_CONSTRUCTOR(CLASS) CLASS() {                \
    PRINT_CONSTRUCTOR_NAME(CLASS);                               \
  }                                                              \

#else
#define PRINT_CONSTRUCTOR_NAME(CLASS) _NOTHING
#define DEFINE_PRINT_CONSTRUCTOR(CLASS) _NOTHING
#endif

// XXX: Should destructors be virtual?

#ifdef _DESTRUCTOR_PRINT
#include <stdio.h>
#define PRINT_DESTRUCTOR_NAME(CLASS) printf(#CLASS "::~" #CLASS "()\n");
#define DEFINE_PRINT_DESTRUCTOR(CLASS) virtual ~CLASS() {               \
    PRINT_DESTRUCTOR_NAME(CLASS);                                       \
  }                                                                     \

#else
#define PRINT_DESTRUCTOR_NAME(CLASS) _NOTHING
#define DEFINE_PRINT_DESTRUCTOR(CLASS) _NOTHING
#endif

#ifdef _OPERATOR_DELETE_PRINT
#include <stdio.h>
#define PRINT_OPERATOR_DELETE_NAME(CLASS) printf(#CLASS "::operator delete()\n");
#define DEFINE_PRINT_OPERATOR_DELETE(CLASS) void operator delete(void *p) { \
    PRINT_OPERATOR_DELETE_NAME(CLASS);                                  \
    ::operator delete (p);                                              \
  }                                                                     \

#else
#define PRINT_OPERATOR_DELETE_NAME(CLASS) _NOTHING
#define DEFINE_PRINT_OPERATOR_DELETE(CLASS) _NOTHING
#endif
