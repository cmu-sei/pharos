// Copyright 2016-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <libpharos/prologimpl.hpp>
#include <libpharos/enums.hpp>

#include "prolog_test.hh"

// Used for testing conversion of random pointers
struct Foo {};
struct Bar {};

// Used for testing conversion of enums
enum test_enum { TEST_A, TEST_B };

template <>
const char *pharos::EnumStrings<test_enum>::data[] = {"test_a", "test_b"};


// Used for testing user-defined conversion functions
struct IntCarrier {
  int x;
};

using pharos::prolog::impl::pl_term;

void c2p(const IntCarrier & ic, pl_term pt) {
  std::string val = "ic_" + std::to_string(ic.x);
  pharos::prolog::c2p(val, pt);
}

void p2c(IntCarrier & ic, pl_term pt) {
  std::string val;
  pharos::prolog::p2c(val, pt);
  val = val.substr(3);
  ic.x = std::stoi(val);
}

bool add_three(pharos::prolog::impl::Args args)
{
  auto arg0 = args.as<int>(0);
  auto arg1 = args.as<int>(1);
  assert(!arg0.is_var());
  assert(arg1.is_var());
  arg1 = arg0 + 3;
  return true;
}

// Test proper

int main()
{
  using namespace pharos::prolog::detail;

  std::string loc;
  // Get the session
  const char *prolog_root = getenv("PROLOG_ROOT");
  if (prolog_root) {
    loc = prolog_root;
  } else {
    loc = PROLOG_INSTALL_LOCATION;
  }
  auto session = Session::get_session(loc);
  session->set_debug_log(std::cout);

  session->register_predicate("add_three", 2, add_three, "pharos");
  auto add_five = [](Args args){ args.as<int>(1) = args.as<int>(0) + 5; return true; };
  session->register_predicate("add_five", 2, add_five, "pharos");

  // Load the rules
  session->add_fact("file_search_path", "pharos", "/tmp/nonexistant");
  try {
    session->consult("pharos", "prolog_test.P");
    assert(false);
  } catch (pharos::prolog::FileNotFound const &e) {
    std::cout << "Bad file test succeeded: " << e.what() << std::endl;
  }
  session->consult("prolog_test.P");
  std::cout << "Loaded prolog_test.P" << std::endl;

  // Assert the facts
  session->add_fact(functor("match", "a", "b"));
  session->add_fact(functor("match", "a", "c"));
  session->add_fact("match", "b", "c");
  session->add_fact("match", "b", "d");
  session->add_fact("match", "c", "a");
  session->add_fact("match", "d", "a");
  session->add_fact("match", "d", "b");
  session->add_fact("match", "d", "b");
  session->add_fact("match", "a test", "a test");
  session->add_fact("match", "'blah'", "'blah'");
  session->add_fact("match", "'blah'", "'blah'");

  auto fact = make_fact("match", "e", "e");
  std::cout << "Printed fact: " << fact << std::endl;
  session->add_fact(fact);

  // Query and iterate over the results
  std::string x, y;
  std::cout << "Test query" << std::endl;
  auto query = session->query("fullmatch", var(x), var(y));
  for (; !query->done(); query->next()) {
    std::cout << x << ", " << y << std::endl;
  }

  std::cout << "Test any() and debug_print" << std::endl;
  query = session->query("fullmatch", any(), any());
  for (; !query->done(); query->next()) {
    query->debug_print(std::cout);
  }

  // std::cout << "Test print_predicate" << std::endl;
  // session->print_predicate(std::cout, "fullmatch", 2);

  // Test callback
  int result = 0;
  query = session->query("test_foreign", 1, var(result));
  assert(!query->done());
  assert(result == 4);
  query->debug_print(std::cout);
  query->next();
  assert(query->done());
  query = session->query("test_foreign_two", 1, var(result));
  assert(!query->done());
  assert(result == 6);
  query->debug_print(std::cout);
  query->next();
  assert(query->done());

  // Test pointer-based facts
  auto f = Foo();
  auto b = Bar();
  const Foo *fp;
  const Bar *bp;

  session->add_fact("f2b", &f, &b);
  query = session->query("f2b", var(fp), var(bp));
  assert(!query->done());
  assert(fp == &f);
  assert(bp == &b);
  query->next();
  assert(query->done());

  Functor<const Foo *, const Bar *> tt;
  session->add_fact("testt", functor("f2b", &f, &b));
  query = session->query("testt", var(tt));
  assert(!query->done());
  assert(std::get<0>(tt) == "f2b");
  assert(std::get<1>(tt) == &f);
  assert(std::get<2>(tt) == &b);
  query->next();
  assert(query->done());

  std::vector<int> iv;
  auto fivesix = list(5, 6);
  auto sublist = list(7);
  sublist.push_back("eight", 9, list(10, "11", 12, "thirteen"));
  std::cout << "List print: " << make_fact("sublist", sublist) << std::endl;
  query = session->query("numbers", list(1, 2, "three", fivesix, sublist), var(iv));
  assert(!query->done());
  query->debug_print(std::cout);
  for (auto i : iv) {
    std::cout << i << std::endl;
  }
  query->next();
  assert(query->done());

  // Test enum-based facts
  session->add_fact("foo", TEST_B);
  test_enum te = TEST_A;
  query = session->query("foo", var(te));
  assert(!query->done());
  query->debug_print(std::cout);
  assert(te == TEST_B);
  query->next();
  assert(query->done());

  // test user-defined conversions
  IntCarrier ic{2};

  session->add_fact("bar", ic);
  ic.x = 0;
  query = session->query("bar", var(ic));
  assert(!query->done());
  query->debug_print(std::cout);
  assert(ic.x == 2);
  query->next();
  assert(query->done());

  // // Test restarting a session
  query.reset();
  session.reset();

  session = Session::get_session(loc);

  session->add_fact("match", "b", "c");

  return 0;
}
