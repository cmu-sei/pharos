// Copyright 2016-2021 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#ifndef Pharos_PROLOG_IMPL_HPP
#define Pharos_PROLOG_IMPL_HPP

// Example Usage:
//  #include <cassert>
//  #include <iostream>
//  #include "prolog.hpp"
//
//  static constexpr auto location = "/path/to/SWIPL_ROOT";
//
//  struct Foo {};
//  struct Bar {};
//
//  int main()
//  {
//    using namespace prolog;
//
//    // Get the session
//    auto session = Session::get_session(location);
//
//    // Load the rules
//    session->consult("test");
//
//    // Assert the facts
//    session->add_fact(functor("match", "a", "b"));
//    session->add_fact(functor("match", "a", "c"));
//    session->add_fact("match", "b", "c");
//    session->add_fact("match", "b", "d");
//    session->add_fact("match", "c", "a");
//    session->add_fact("match", "d", "a");
//    session->add_fact("match", "d", "b");
//    session->add_fact("match", "d", "b");
//
//    // Query and iterate over the results
//    std::string x, y;
//    auto query = session->query("fullmatch", var(x), var(y));
//    for (; !query->done(); query->next()) {
//      std::cout << x << ", " << y << std::endl;
//    }
//
//    // Query and iterate over the results (with unbound any())
//    query = session->query("fullmatch", var(x), any());
//    for (; !query->done(); query->next()) {
//      std::cout << x << std::endl;
//    }
//
//    // Test pointer-based facts
//    auto f = Foo();
//    auto b = Bar();
//    const Foo *fp;
//    const Bar *bp;
//
//    session->add_fact("f2b", &f, &b);
//    query = session->query("f2b", var(fp), var(bp));
//    assert(!query->done());
//    assert(fp == &f);
//    assert(bp == &b);
//    query->next();
//    assert(query->done());
//
//    return 0;
//  }

#include <string>
#include <memory>
#include <mutex>
#include <cstddef>
#include <functional>
#include <vector>
#include <set>
#include <ostream>
#include <utility>
#include <type_traits>
#include <sstream>

#include "enums.hpp"
#include "prologbase.hpp"
#include "swiimpl.hpp"

namespace pharos {
namespace prolog {

using impl::pl_term;
using impl::pl_int;
using impl::list;
using impl::List;

class FileNotFound : public Error {
  static std::string build_msg(std::string const & filename);
 public:
  FileNotFound(std::string const & filename) : Error(build_msg(filename)) {}
};

class SessionError : public Error {
 public:
  using Error::Error;
};

class InitError : public Error {
 public:
  InitError();
};

namespace detail {

using Query = std::shared_ptr<impl::Query>;

template <typename T>
class Arg {
  pl_term pt;
  Arg(pl_term p) : pt(p) {}
  friend class Args;
 public:
  bool is_var() const {
    return impl::is_var(pt);
  }
  operator T() const {
    T val;
    p2c(val, pt);
    return val;
  }
  Arg & operator=(const T & val) {
    impl::unify(val, pt);
    return *this;
  }
};

class Args {
  pl_term args_;
  std::size_t arity_;
  Args(pl_term args, std::size_t arity) : args_{args}, arity_{arity} {}
  friend class Session;

  void check_arity(std::size_t arg) const {
    if (arg > arity_) {
      throw prolog::Error{"Argument too large for arity"};
    }
  }
 public:
  template <typename T>
  void get_value(std::size_t arg, T & value) const {
    check_arity(arg);
    p2c(value, args_ + arg);
  }

  template <typename T>
  auto as(std::size_t arg) const {
    check_arity(arg);
    return Arg<T>{args_ + arg};
  }

  std::string to_string(std::size_t arg) const {
    check_arity(arg);
    std::ostringstream os;
    impl::term_to_stream(os, args_ + arg);
    return os.str();
  }

  std::size_t arity() const { return arity_; }
};

class Session : public std::enable_shared_from_this<Session>
{
 private:
  std::recursive_mutex mutex;
  using lock_guard = std::lock_guard<decltype(mutex)>;

  static std::shared_ptr<Session> current_session;

  std::vector<std::function<bool(Args)>> registry;
  std::set<int> registry_arity;

  std::ostream * log = nullptr;

  using predspec_t = std::tuple<std::string, int>;
  std::set<predspec_t> saved_state;

 public:
  // Session::get_session can only be called if a session is not already being used.  Otherwise
  // a SessionError will be thrown
  static std::shared_ptr<Session> &
  get_session(std::string const & location);

  template <typename... T>
  Query query(T &&... args) {
    return real_query(make_term(std::forward<T>(args)...));
  }

  template <typename... T>
  bool command(T &&... args) {
    return !query(std::forward<T>(args)...)->done();
  }

  template <typename T>
  bool add_fact(Fact<T> const & f) {
    return add_fact(f.val);
  }

  template <typename A, typename... T>
  std::enable_if_t<!is_a_fact<std::remove_reference_t<A>>::value, bool>
  add_fact(A && a, T &&... args) {
    auto cmd = functor(
      "call", functor(":", prolog_default_module,
                      functor("assert_uniquely",
                              make_term(std::forward<A>(a), std::forward<T>(args)...))));
    return command(cmd);
  }

  void consult(std::string const & filename) {
    return consult(functor("consult", filename));
  }

  void consult(std::string const & location, std::string const & filename) {
    return consult(functor("consult", functor(location, filename)));
  }

  std::size_t print_predicate(
    std::ostream & stream, std::string const & predicate, std::size_t arity);

  bool register_predicate(
    const std::string & predname,
    std::size_t arity,
    std::function<bool(Args)>,
    const std::string & modname = "user");

  std::ostream * get_debug_log() const {
    return log;
  }
  std::ostream * set_debug_log(std::ostream * s) {
    auto ret = log;
    log = s;
    return ret;
  }
  std::ostream * set_debug_log(std::ostream & s) {
    return set_debug_log(&s);
  }

  template <typename T>
  std::ostream & print_term(std::ostream & s, T && term) {
    return impl::print_term(s, std::forward<T>(term));
  }

 private:
  Session(std::string const & location);

  static constexpr auto wrapper_name = "registry_wrapper";
  static foreign_t predicate_wrapper(pl_term, std::size_t, void *);

  template <typename... T>
  Query real_query(BaseFunctor<T...> const & p) {
    constexpr auto result = "Prolog query result: ";
    if (log && *log) {
      *log << "Prolog query: " << make_fact(p) << std::endl;
    }
    try {
      auto rv = impl::Query::instance(p);
      if (log && *log) {
        *log << result << std::boolalpha << !rv->done() << std::endl;
      }
      return rv;
    } catch (Error const & e) {
      if (log && *log) {
        *log << result << "error: " << e.what() << std::endl;
      }
      throw;
    }
  }

  template <typename... T>
  std::string get_filename(T &&... args) {
    std::string result;
    auto term = make_term(std::forward<T>(args)...);
    if (command("absolute_file_name", term, var(result))) {
      return result;
    }
    return term_to_string(term);
  }

  template <typename T>
  std::string term_to_string(T && t) {
    std::ostringstream os;
    os << make_fact(std::forward<T>(t));
    return os.str();
  }

  template <typename T>
  void consult(CFunctor<T> && loc) {
    bool success = false;
    try {
      success = command(loc);
    } catch (Error const &) {
      success = false;
    }
    if (!success) {
      throw FileNotFound(get_filename(std::get<1>(loc)));
    }
  }

  void save_state();
  void revert_state();
};

template <typename T>
std::ostream & operator<<(std::ostream & stream, Fact<T> const & f) {
  return impl::print_term(stream, f.val);
}

using impl::list;

} // namespace detail
} // namespace prolog
} // namespace pharos


#endif  // Pharos_PROLOG_IMPL_HPP

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
