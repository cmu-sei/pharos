#include "test.hpp"
#include <cstdint>

void example_constrain_arg(int x, int y) {
  assert_symbolic (x == y);
}

int example_constrain_ret(int y) {
  // If we don't force this to a fresh symbolic value, it could be in a register that was
  // pre-initialized, which causes Spacer to fail.
  volatile int x = FRESH_SYMBOLIC;
  assert_symbolic (x == y);
  return x;
}

int __ctr;

int example_counter() {
  return ++__ctr;
}

// Initial implementation
extern "C" void* _Znwm (int) {
  volatile uintptr_t ptr = FRESH_SYMBOLIC;
  assert_symbolic (ptr < 0xafff0000L && ptr >= 0xa0000000L);
  return (void*) ptr;
}

time_t global_time;

// Never inline the path markers, because if they get inlined, we
// won't find the symbols, which defeats the whole point of using
// these calls to parameterize our tests.

void NOINLINE path_start() {
  time(&global_time);
  // Initialize state
  __ctr = 42;
}

void NOINLINE path_goal() {
  time(&global_time);
}

void NOINLINE path_nongoal() {
  time(&global_time);
}
