// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#ifndef Pharos_PROLOG_IMPL_HPP
#define Pharos_PROLOG_IMPL_HPP

#include <cassert>
#include <cctype>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>
#include <iostream>

#include "xsb.hpp"
#include "enums.hpp"

// Example Usage:
//  #include <cassert>
//  #include <iostream>
//  #include "prolog.hpp"
//
//  static constexpr auto location = "/path/to/XSB_ROOT";
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

namespace pharos {
namespace prolog {

static constexpr auto prolog_default_module = "pharos";

// Base exception for all prolog errors
class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Type mismatch error
class TypeMismatch : public Error {
  using xsb_term = impl::xsb::xsb_term;
  static constexpr auto errmsg = "Type from prolog was not of expected type";
  static std::string build_msg(xsb_term pt, const std::string & expected);
 public:
  TypeMismatch(xsb_term pt, const std::string & expected) : Error(build_msg(pt, expected)) {}
};

class FileNotFound : public Error {
  static std::string build_msg(const std::string & filename);
 public:
  FileNotFound(const std::string & filename) : Error(build_msg(filename)) {}
};

namespace impl {

struct IsAFunctor {};

// Functor type
template <typename... Types>
struct BaseFunctor : public IsAFunctor, public std::tuple<Types...> {
  using std::tuple<Types...>::tuple;
};

// Functor type based on std::string
template <typename... Types>
struct Functor : public BaseFunctor<std::string, Types...> {
  using BaseFunctor<std::string, Types...>::BaseFunctor;
};

// Functor type based on const char *
template <typename... Types>
struct CFunctor : public BaseFunctor<const char *, Types...> {
  using BaseFunctor<const char *, Types...>::BaseFunctor;
};

// Creates a Functor
template <typename... Types>
constexpr Functor<Types...>
functor(const std::string & name, Types && ... args)
{
  return Functor<Types...>(name, std::forward<Types>(args)...);
}

// Creates a Functor (move semantics for name)
template <typename... Types>
constexpr Functor<Types...>
functor(std::string && name, Types && ... args)
{
  return Functor<Types...>(std::move(name), std::forward<Types>(args)...);
}

// Creates a CFunctor
template <typename... Types>
inline constexpr CFunctor<Types...>
functor(const char * name, Types && ... args)
{
  return CFunctor<Types...>(name, std::forward<Types>(args)...);
}

// Represents a variable binding
template <typename T>
struct Var {
  Var(T & v) : var(v) {}
  T & var;
  using type = T;
};

// Function to create a variable binding
template <typename T>
inline Var<T> var(T & v) {
  return Var<T>(v);
}

// The type of the "Don't care" variable  (underscore, in prolog)
struct Any {
  using type = Any;
  void set(...) const {}
};

inline Any any() {
  return Any();
}

// Used to make functor(_, _, _, _, ...) queries
struct AnyN {
  std::size_t val;
  struct tag {};
};

template <typename P>
struct BaseFunctor<P, AnyN> : AnyN::tag, IsAFunctor, std::tuple<P, AnyN> {
  using std::tuple<P, AnyN>::tuple;
};
template <typename T>
using is_anyn_functor = std::is_base_of<AnyN::tag, T>;

// XSB-specific code
inline
namespace xsb {

// XSB error, created whenever status::ERROR is returned
class XSBError : public Error {
 public:
  XSBError();
 protected:
  using prolog::Error::Error;
};

// XSB initialization error
class InitError : public XSBError {
 public:
  InitError();
};

class SessionError : public XSBError {
 public:
  using XSBError::XSBError;
};

// Overflow error.  Should never happen, probably.
class OverflowError : public XSBError {
 public:
  OverflowError() : XSBError("Prolog answer too long for internal buffers") {}
};

class List;

// Code that creates type-based integer sequences.  Used for tuple iteration.
namespace detail {
template <std::size_t ... I>
struct Index {
  using next = Index<I..., sizeof...(I)>;
};

template <std::size_t N>
struct MakeSeq_ {
  using type = typename MakeSeq_<N - 1>::type::next;
};
template<>
struct MakeSeq_<0> {
  using type = Index<>;
};
template <std::size_t N>
using MakeSeq = typename MakeSeq_<N>::type;

template <typename T, typename F>
class capture_impl
{
 private:
  T val;
  F fn;
 public:
  capture_impl(T && x, F && f )
    : val{std::forward<T>(x)}, fn{std::forward<F>(f)}
  {}
  template <typename... Args>
  auto operator()(Args &&... args) -> decltype(fn(val, std::forward<Args>(args)...)) {
    return fn(val, std::forward<Args>(args)...);
  }
  template <typename... Args>
  auto operator()(Args &&... args) const -> decltype(fn(val, std::forward<Args>(args)...)) {
    return fn(val, std::forward<Args>(args)...);
  }
};
template <typename T, typename F>
capture_impl<T, F> capture(T && x, F && f ) {
  return capture_impl<T, F>(std::forward<T>(x), std::forward<F>(f));
}

} // namespace detail


template <typename T>
static void c2p(const Var<T> &, xsb_term) {}

inline void c2p(xsb_int arg, xsb_term pt) {
  if (!impl::c2p_int(arg, pt)) {
    throw XSBError();
  }
}
inline void p2c(xsb_int & arg, xsb_term pt) {
  if (!impl::is_int(pt)) {
    throw TypeMismatch(pt, "integer");
  }
  arg = impl::p2c_int(pt);
}

inline void c2p(const char * arg, xsb_term pt) {
  if (!impl::c2p_string(arg, pt)) {
    throw XSBError();
  }
}
inline void p2c(const char * & arg, xsb_term pt){
  if (!impl::is_string(pt)) {
    throw TypeMismatch(pt, "string");
  }
  arg = impl::p2c_string(pt);
}

inline void c2p(const std::string & s, xsb_term pt) {
  c2p(s.c_str(), pt);
}
inline void p2c(std::string & arg, xsb_term pt) {
  const char *val;
  p2c(val, pt);
  arg = val;
}

inline void c2p(const Any &, xsb_term) {}
inline void p2c(Any &, xsb_term) {}

// Forward declarations
template <typename T>
void p2c(Var<T> & arg, xsb_term pt);

template <typename T>
typename std::enable_if<std::is_enum<T>::value>::type
p2c(T & arg, xsb_term pt);

template <typename T>
typename std::enable_if<std::is_enum<T>::value>::type
c2p(T arg, xsb_term pt);

template <typename T>
typename std::enable_if<!std::is_enum<T>::value &&
                        std::is_convertible<T, xsb_int>::value>::type
p2c(T & arg, xsb_term pt);

template <typename... T>
void c2p(const BaseFunctor<T...> & arg, xsb_term pt);

template <typename... T>
void p2c(Functor<T...> & arg, xsb_term pt);

template <typename T>
void c2p(const T * arg, xsb_term pt);

template <typename T>
void p2c(T * & arg, xsb_term pt);

template <typename T>
void p2c(const std::vector<T> & arg, xsb_term pt);

template <typename T>
void c2p(const std::vector<T> & arg, xsb_term pt);

// Implementations
template <typename T>
void p2c(std::vector<T> & arg, xsb_term pt) {
  arg.clear();
  while (impl::is_list(pt)) {
    T val;
    p2c(val, impl::p2p_car(pt));
    arg.push_back(std::move(val));
    pt = impl::p2p_cdr(pt);
  }
  if (!impl::is_nil(pt)) {
    throw TypeMismatch(pt, "nil");
  }
}

template <typename T>
void c2p(const std::vector<T> & arg, xsb_term pt) {
  for (auto & val : arg) {
    impl::c2p_list(pt);
    c2p(val, impl::p2p_car(pt));
    pt = impl::p2p_cdr(pt);
  }
  impl::c2p_nil(pt);
}

template <typename T>
void p2c(Var<T> & arg, xsb_term pt) {
  p2c(arg.var, pt);
}

// Conversion for types that autoconvert to prolog-int (like long, short, etc.)
template <typename T>
typename std::enable_if<!std::is_enum<T>::value &&
                        std::is_convertible<T, xsb_int>::value>::type
p2c(T & arg, xsb_term pt) {
  xsb_int val;
  p2c(val, pt);
  arg = val;
}

// Enums
template <typename T>
typename std::enable_if<std::is_enum<T>::value>::type
p2c(T & arg, xsb_term pt) {
  std::string val;
  p2c(val, pt);
  arg = Str2Enum<T>(val);
}
template <typename T>
typename std::enable_if<std::is_enum<T>::value>::type
c2p(T arg, xsb_term pt) {
  c2p(Enum2Str(arg), pt);
}

template <typename T>
void c2p(const BaseFunctor<T, AnyN> & arg, xsb_term pt) {
  impl::c2p_functor(std::get<0>(arg), std::get<1>(arg).val, pt);
}

template <typename... T>
void c2p(const BaseFunctor<T...> & arg, xsb_term pt) {
  impl::c2p_functor(std::get<0>(arg), sizeof...(T) - 1, pt);
  c2p(arg, pt, detail::MakeSeq<sizeof...(T) - 1>());
}
template <typename... T>
void c2p(const BaseFunctor<T...> &, xsb_term, detail::Index<>) {
  // Do nothing (ends recursion)
}
template <typename... T, std::size_t i, std::size_t... Next>
void c2p(const BaseFunctor<T...> & arg, xsb_term pt, detail::Index<i, Next...>) {
  c2p(std::get<i + 1>(arg), impl::p2p_arg(pt, i + 1));
  c2p(arg, pt, detail::Index<Next...>());
}

template <typename... T>
void p2c(Functor<T...> & arg, xsb_term pt) {
  if (impl::is_functor(pt) && impl::p2c_arity(pt) == sizeof...(T)) {
    std::get<0>(arg) = impl::p2c_functor(pt);
    p2c(arg, pt, detail::MakeSeq<sizeof...(T)>());
  } else {
    std::ostringstream os;
    os << "functor/" << sizeof...(T);
    throw TypeMismatch(pt, os.str());
  }
}
template <typename... T>
void p2c(Functor<T...> &, xsb_term, detail::Index<>) {
  // Do nothing (ends recursion)
}
template <typename... T, std::size_t i, std::size_t... Next>
void p2c(Functor<T...> & arg, xsb_term pt, detail::Index<i, Next...>) {
  p2c(std::get<i + 1>(arg), impl::p2p_arg(pt, i + 1));
  p2c(arg, pt, detail::Index<Next...>());
}

template <typename T>
void c2p(const T * arg, xsb_term pt) {
  static_assert(sizeof(T*) <= sizeof(xsb_int), "Cannot store pointer as int");
    c2p(functor("__ptr", reinterpret_cast<xsb_int>(arg)), pt);
}
template <typename T>
void p2c(T * & arg, xsb_term pt) {
  if (impl::is_functor(pt) && impl::p2c_arity(pt) == 1
      && std::strcmp("__ptr", impl::p2c_functor(pt)) == 0)
  {
    auto a = impl::p2p_arg(pt, 1);
    if (impl::is_int(a)) {
      xsb_int val;
      p2c(val, a);
      arg = reinterpret_cast<T *>(val);
      return;
    }
  }
  throw TypeMismatch(pt, "__ptr/1");
}

template <typename Stream>
Stream & output_atom(Stream & stream, const char * atom) {
  const char *c;
  if (std::islower(atom[0])) {
    for (c = atom + 1; std::isalnum(*c) || *c == '_'; ++c);
    if (*c == '\0') {
      stream << atom;
      return stream;
    }
  }
  stream << '\'';
  while ((c = std::strchr(atom, '\''))) {
    stream << std::string(atom, c) << "''";
    atom = c + 1;
  }
  stream << atom << '\'';
  return stream;
}

template <typename Stream>
Stream & term_to_stream(Stream & stream, xsb_term pt) {
  struct restore_flags_t {
    Stream & stream;
    decltype(stream.flags()) flags;
    ~restore_flags_t() {
      stream.flags(flags);
    }
  } restore_flags = {stream, stream.flags()};
  if (impl::is_int(pt)) {
    int64_t sint = int64_t(impl::p2c_int(pt));
    if (sint < 0) {
      stream << '-';
      sint = -sint;
    }
    stream << std::hex << std::showbase << sint;
    return stream;
  }
  if (impl::is_string(pt)) {
    return output_atom(stream, impl::p2c_string(pt));
  }
  if (impl::is_functor(pt)) {
    output_atom(stream, impl::p2c_functor(pt));
    stream << '(';
    auto nargs = impl::p2c_arity(pt);
    for (decltype(nargs) i = 1; i <= nargs; ++i) {
      if (i != 1) {
        stream << ", ";
      }
      term_to_stream(stream, impl::p2p_arg(pt, i));
    }
    stream << ')';
    return stream;
  }
  if (impl::is_list(pt)) {
    bool nil;
    stream << '[';
    do {
      term_to_stream(stream, impl::p2p_car(pt));
      pt = impl::p2p_cdr(pt);
      if (!(nil = impl::is_nil(pt))) {
        stream << ", ";
      }
    } while (!nil);
    stream << ']';
    return stream;
  }
  if (impl::is_nil(pt)) {
    stream << "[]";
    return stream;
  }
  if (impl::is_var(pt)) {
    stream << "_Var(" << pt << ')';
    return stream;
  }
  stream << "<unknown>";
  return stream;
}

template <typename T>
class Arg {
  xsb_term pt;
 public:
  Arg(int arg) : pt(impl::reg_term(arg + 1)) {}
  bool is_var() const {
    return impl::is_var(pt);
  }
  operator T() const {
    T val;
    p2c(val, pt);
    return val;
  }
  Arg & operator=(const T & val) {
    c2p(val, pt);
    return *this;
  }
};

template <>
class Arg<void> {
  xsb_term pt;
 public:
  Arg(int arg) : pt(impl::reg_term(arg + 1)) {}
  bool is_var() const {
    return impl::is_var(pt);
  }
  operator std::string() const {
    std::ostringstream os;
    term_to_stream(os, pt);
    return os.str();
  }
};

template <typename T>
Arg<T> arg(int a) {
  return Arg<T>(a);
}

class List {
 public:
  template <typename... T>
  List(T &&... args) {
    push_back(std::forward<T>(args)...);
  }

  template <typename T>
  void push_back(const T & item) {
    list.emplace_back([item](xsb_term pt){ c2p(item, pt); });
  }

  template <typename T>
  void push_back(T && item) {
    list.emplace_back(detail::capture(std::move(item),
                                      [](T & v, xsb_term pt){ c2p(v, pt); }));
  }

  template <typename T, typename S, typename... Rest>
  void push_back(T && arg, S && arg2, Rest &&... args) {
    push_back(std::forward<T>(arg));
    push_back(std::forward<S>(arg2), std::forward<Rest>(args)...);
  }

  void push_back() {}

 private:
  friend void c2p(const List &, xsb_term);

  using setters_t = std::vector<std::function<void(xsb_term)>>;
  setters_t list;
};

template<typename... T>
List list(T &&... args) {
  return List(std::forward<T>(args)...);
}

inline void c2p(const List & lst, xsb_term pt) {
  for (auto & setter : lst.list) {
    impl::c2p_list(pt);
    setter(impl::p2p_car(pt));
    pt = impl::p2p_cdr(pt);
  }
  impl::c2p_nil(pt);
}

namespace detail {
template <typename T>
class SpecificQuery;
}

class Session;

// Queries can be iterated over to fill bound variables with the result of a query
class Query {
 public:
  // Return true if there are no more bindings
  bool done() const {
    return finished;
  }

  // Return true if there are no more bindings
  explicit operator bool() const {
    return !done();
  }

  // Bind the next query result.  Returns false if no next query result exists.
  bool next();

  // Terminates the query (generally not necessary to do manually)
  void terminate() {
    if (!done()) {
      impl::xsb_close_query();
      finished = true;
    }
  }

  // Return the arity of the query result.
  int arity() const {
    if (!done()) {
      auto pt = impl::reg_term(1);
      if (impl::is_string(pt)) {
        return 0;
      }
      assert(impl::is_functor(pt));
      return impl::p2c_arity(pt);
    }
    return 0;
  }

  template <typename Stream>
  Stream & debug_print(Stream & stream) {
    if (!done()) {
      term_to_stream(stream, impl::reg_term(1));
      stream << ".\n";
    }
    return stream;
  }

  virtual ~Query() {
    terminate();
  }

  // No copying allowed
  Query(const Query &) = delete;
  Query & operator=(const Query &) = delete;

  // Move semantics allowed
  Query(Query &&) = default;
  Query & operator=(Query &&) = default;


 protected:
  std::shared_ptr<Session> session;
  void call_query();

 private:
  template <typename T>
  friend class detail::SpecificQuery;

  Query(std::shared_ptr<Session> & s) : session(s) {};

  virtual void apply_setters() = 0;

  bool finished = false;
}; // class Query

namespace detail {

template <typename T>
constexpr typename std::enable_if<!std::is_base_of<IsAFunctor, T>::value, std::tuple<>>::type
extract_vars(const T &) {
  return std::tuple<>();
}

template <typename T>
constexpr std::tuple<Var<T>>
extract_vars(const Var<T> & v) {
  return std::make_tuple(v);
}

constexpr std::tuple<Any>
extract_vars(const Any & v) {
  return std::make_tuple(v);
}

template <typename... T>
constexpr auto
extract_vars(const BaseFunctor<T...> & v) ->
  decltype(extract_vars(v, detail::MakeSeq<sizeof...(T) - 1>()))
{
  return extract_vars(v, detail::MakeSeq<sizeof...(T) - 1>());
}

template <typename... T>
constexpr std::tuple<>
extract_vars(const BaseFunctor<T...> &, detail::Index<>) {
  return std::tuple<>();
}

template <typename... T, std::size_t i, std::size_t... Next>
constexpr auto
extract_vars(const BaseFunctor<T...> & v, detail::Index<i, Next...>) ->
  decltype(std::tuple_cat(extract_vars(std::get<i + 1>(v)),
                          extract_vars(v, detail::Index<Next...>())))
{
  return std::tuple_cat(extract_vars(std::get<i + 1>(v)),
                        extract_vars(v, detail::Index<Next...>()));
}


// Queries can be iterated over to fill bound variables with the result of a query
template <typename T>
class SpecificQuery : public Query {
 public:
  SpecificQuery(std::shared_ptr<Session> s, const T & t) : Query(s), vars(extract_vars(t)) {
    call_query();
  }

 private:
  using vars_t = decltype(extract_vars(std::declval<T>()));

  void apply_setters() override {
    auto vals = impl::reg_term(2);
    assert(impl::is_string(vals) ||
           (impl::is_functor(vals)
            && (is_anyn_functor<T>::value
                || (impl::p2c_arity(vals) == std::tuple_size<vars_t>::value))));
    _apply_setters(vals, detail::MakeSeq<std::tuple_size<vars_t>::value>());
  }

  void _apply_setters(xsb_term, detail::Index<>) {
    // Do nothing (end recursion)
  }

  template <std::size_t i, std::size_t... Next>
  void _apply_setters(xsb_term pt, detail::Index<i, Next...>) {
    p2c(std::get<i>(vars), impl::p2p_arg(pt, i + 1));
    _apply_setters(pt, detail::Index<Next...>());
  }

  vars_t vars;
}; // class SpecificQuery
} // namespace detail

// A session represents an entire XSB prolog session
class Session : public std::enable_shared_from_this<Session> {
 public:

  // Session::get_session can only be called once.  It will return a single unique XSB session.
  static std::shared_ptr<Session> &
  get_session(const std::string & location);

  ~Session();

  // Execute a command
  template <typename... T>
  bool command(T &&... t) {
    lock_guard lock(mutex);
    close_query();
    build_term(std::forward<T>(t)...);
    return run_command();
  }


  template <typename T>
  typename std::enable_if<std::is_same<std::string,
                                       typename std::decay<T>::type>::value, bool>::type
  command(T && cmd) {
    lock_guard lock(mutex);
    close_query();
    if (!cmd.empty() && cmd.back() == '.') {
      return run_command(cmd.c_str());
    } else {
      build_term(std::forward<T>(cmd));
      return run_command();
    }
  }

  template <typename T>
  typename std::enable_if<std::is_same<char *,
                                       typename std::decay<T>::type>::value
                          || std::is_same<const char *,
                                          typename std::decay<T>::type>::value, bool>::type
  command(T && cmd) {
    return command(std::string(cmd));
  }

  // Assert a fact
  template <typename... T>
  bool add_fact(T &&... t) {
    return command("assert", make_term(std::forward<T>(t)...));
  }

  // Interrogate with a query
  template <typename... T>
  std::shared_ptr<Query> query(T &&... t) {
    lock_guard lock(mutex);
    close_query();
    auto tm = make_term(std::forward<T>(t)...);
    build_term(tm);
    auto rv = std::shared_ptr<Query>(
      new detail::SpecificQuery<decltype(tm)>(shared_from_this(), std::move(tm)));
    current_query = rv;
    return rv;
  }

  template <typename Stream>
  std::size_t print_predicate(
    Stream & stream, const std::string & predicate, std::size_t arity)
  {
    std::size_t n = 0;
    auto q = query(predicate, AnyN{arity});
    for (; !q->done(); q->next()) {
      ++n;
      q->debug_print(stream);
    }
    return n;
  }

  // Load a file
  void consult(const std::string & name) {
    if (!command("consult", name)) {
      throw FileNotFound(name);
    }
  }

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

  bool register_predicate(const std::string & predname, int arity, int (*cfun)(),
                          const std::string & modname = "usermod");
  bool register_cxx_predicate(const std::string & predname, int arity,
                              std::function<int()> func,
                              const std::string & modname = "usermod");

 private:
  std::recursive_mutex mutex;
  using lock_guard = std::lock_guard<decltype(mutex)>;
  std::ostream * log = nullptr;

  Session(const std::string & location);

  bool run_command(const char *command = nullptr);

  static constexpr auto wrapper_name = "registry_wrapper";
  std::vector<std::function<int()>> registry;
  std::set<int> registry_arity;
  static int predicate_wrapper();

  void close_query();

  template <typename T>
  static auto make_term(T && x) -> decltype(std::forward<T>(x)) {
    return std::forward<T>(x);
  }
  template <typename... T>
  static Functor<T...> make_term(const std::string & s, T &&... t) {
    return functor(s, std::forward<T>(t)...);
  }
  template <typename... T>
  static Functor<T...> make_term(std::string && s, T &&... t) {
    return functor(std::move(s), std::forward<T>(t)...);
  }
  template <typename... T>
  static CFunctor<T...> make_term(const char * s, T &&... t) {
    return functor(s, std::forward<T>(t)...);
  }

  template <typename... T>
  void build_term(T &&... t) {
    const auto & x = make_term(std::forward<T>(t)...);
    c2p(x, impl::reg_term(1));
  }

  void save_state();
  void revert_state();

  using predspec_t = std::tuple<std::string, int>;
  std::set<predspec_t> saved_state;
  std::set<std::string> saved_modules;

  std::weak_ptr<Query> current_query;

  static std::shared_ptr<Session> current_session;
}; // class Session


} // namespace xsb
} // namespace impl
} // namespace prolog
} // namespace pharos


#endif  // Pharos_PROLOG_IMPL_HPP

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
