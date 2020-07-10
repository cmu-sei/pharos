#include <cassert>

extern "C" void __assert_symbolic_dummy_import (bool) {
  assert (false);
}
