// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

// This file contains anything that must call out to the SWIPL library.

#ifndef Pharos_SWIPL_IMPL_HPP
#define Pharos_SWIPL_IMPL_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>
#include <tuple>
#include <utility>
#include <sstream>
#include <exception>
#include <memory>
#include <ostream>
#include <mutex>
#include <stack>

#include "enums.hpp"
#include "prologbase.hpp"
#include <SWI-Prolog.h>

#define MAYBE_UNUSED(x) ((void)(x))

namespace pharos {
namespace prolog {
namespace impl {

using pl_term = term_t;
using pl_int = std::int64_t;

}

// Type mismatch error
class TypeMismatch : public Error {
  static std::string build_msg(impl::pl_term pt, std::string const & expected);
 public:
  TypeMismatch(impl::pl_term pt, std::string const & expected)
    : Error(build_msg(pt, expected)) {}
};

template <class T, typename Enable = void>
struct Convert;

namespace impl {

using namespace detail;

inline bool is_var(term_t t) {
  return PL_is_variable(t);
}

inline bool is_float(term_t t) {
  return PL_is_float(t);
}

inline bool is_functor(term_t t) {
  return PL_is_compound(t);
}

inline bool is_int(term_t t) {
  return PL_is_integer(t);
}

inline bool is_list(term_t t) {
  return PL_is_pair(t);
}

inline bool is_nil(term_t t) {
  return PL_is_list(t) && !PL_is_pair(t);
}

inline bool is_string(term_t t) {
  return PL_is_atom(t) || PL_is_string(t);
}

inline pl_int get_arity(term_t t) {
  size_t arity;
  auto rv = PL_get_name_arity(t, nullptr, &arity);
  assert(rv);
  MAYBE_UNUSED(rv);
  return arity;
}

std::string term_type(pl_term pt);

inline int prolog_init(int argc, char **argv)
{
  return PL_initialise(argc, argv);
}

class Error : public prolog::Error
{
  static std::string build_msg(qid_t qid);
 public:
  Error(qid_t qid = 0) : prolog::Error{build_msg(qid)} {}
};

// RAII class for foreign frames
class Frame {
  fid_t fid;
 public:
  Frame() : fid(PL_open_foreign_frame()) {}
  ~Frame() { PL_close_foreign_frame(fid); }
};

/// Customization point for c2p and p2c
///
/// In the prolog namespace the only c2p and p2c visible are function objects which delegate to
/// do_c2p, do_p2c calls.  These do_ calls are prioritized such that a constructed
/// prolog::Convert<T> specialization's c2p or p2c will be tried first, ADL-based function
/// lookup for c2p and p2c will happen second, and implementations using prolog::impl::Convert
/// will be tried last.

template <std::size_t I>
struct priority_tag : priority_tag<I-1> {};
template <>
struct priority_tag<0> {};

template <class T, typename Enable = void>
struct Convert;

template <typename... Ts> struct make_void { using type = void; };
template <typename... Ts> using void_t = typename make_void<Ts...>::type;

template <class T>
auto do_c2p(T const & obj, pl_term pt, priority_tag<0>)
  -> void_t<decltype(c2p(obj, pt))>
{
  c2p(obj, pt);
}

template <class T>
auto do_p2c(T & obj, pl_term pt, priority_tag<0>)
  -> void_t<decltype(p2c(obj, pt))>
{
  p2c(obj, pt);
}

template <class T>
auto do_c2p(T const & obj, pl_term pt, priority_tag<1>)
  -> void_t<decltype(::pharos::prolog::impl::Convert<T>::c2p(obj, pt))>
{
  ::pharos::prolog::impl::Convert<T>::c2p(obj, pt);
}

template <class T>
auto do_p2c(T & obj, pl_term pt, priority_tag<1>)
  -> void_t<decltype(::pharos::prolog::impl::Convert<T>::p2c(obj, pt))>
{
  ::pharos::prolog::impl::Convert<T>::p2c(obj, pt);
}

template <class T>
auto do_c2p(T const & obj, pl_term pt, priority_tag<2>)
  -> void_t<decltype(::pharos::prolog::Convert<T>::c2p(obj, pt))>
{
  ::pharos::prolog::Convert<T>::c2p(obj, pt);
}

template <class T>
auto do_p2c(T & obj, pl_term pt, priority_tag<2>)
  -> void_t<decltype(::pharos::prolog::Convert<T>::p2c(obj, pt))>
{
  ::pharos::prolog::Convert<T>::p2c(obj, pt);
}

struct _c2p_fn {
  template <typename T>
  void operator()(T const & obj, pl_term pt) const
    noexcept(noexcept(::pharos::prolog::impl::do_c2p(obj, pt, priority_tag<2>{})))
  {
    ::pharos::prolog::impl::do_c2p(obj, pt, priority_tag<2>{});
  }
};

struct _p2c_fn {
  template <typename T>
  void operator()(T & obj, pl_term pt) const
    noexcept(noexcept(::pharos::prolog::impl::do_p2c(obj, pt, priority_tag<2>{})))
  {
    ::pharos::prolog::impl::do_p2c(obj, pt, priority_tag<2>{});
  }
};
} // namespace impl


template <class T>
constexpr T _static_const{};

namespace {
constexpr auto const & c2p = _static_const<impl::_c2p_fn>;
constexpr auto const & p2c = _static_const<impl::_p2c_fn>;
}

namespace impl {

/// Base type conversion
///
/// c2p(x, pt) sets the Prolog term pt to the C++ variable x
/// p2c(x, pt) sets the C++ reference x to the Prolog term pt

inline void wrap_error(int success) {
  if (!success) {
    throw Error{};
  }
}

// Int
template <>
struct Convert<pl_int> {
  static void c2p(pl_int arg, pl_term pt) {
    wrap_error(PL_put_int64(pt, arg));
  }
  static void p2c(pl_int & arg, pl_term pt) {
    if (!PL_is_integer(pt)) {
      throw TypeMismatch(pt, "integer");
    }
    wrap_error(PL_get_int64(pt, &arg));
  }
};

// char const *
template <>
struct Convert<char const *> {
  static void c2p(char const * arg, pl_term pt) {
    wrap_error(PL_put_atom_chars(pt, arg));
  }
  static void p2c(char const * & arg, pl_term pt) {
    switch (PL_term_type(pt)) {
     case PL_ATOM:
      wrap_error(PL_get_atom_chars(pt, const_cast<char **>(&arg)));
      return;
     case PL_STRING:
      wrap_error(PL_get_string_chars(pt, const_cast<char **>(&arg), nullptr));
      return;
     default:
      throw TypeMismatch(pt, "atom");
    }
  }
};

template <std::size_t s>
struct Convert<char[s]> : Convert<char const *> {};

// std::string
template <>
struct Convert<std::string> {
  static void c2p(std::string const & s, pl_term pt) {
    wrap_error(PL_put_atom_nchars(pt, s.size(), s.data()));
  }
  static void p2c(std::string & arg, pl_term pt) {
    std::size_t size;
    char *str;
    switch (PL_term_type(pt)) {
     case PL_ATOM:
      wrap_error(PL_get_atom_nchars(pt, &size, &str));
      break;
     case PL_STRING:
      wrap_error(PL_get_string_chars(pt, &str, &size));
      break;
     default:
      throw TypeMismatch(pt, "atom");
    }
    arg = {str, size};
  }
};

// Any
template <>
struct Convert<Any> {
  static void c2p(Any const &, pl_term) {}
  static void p2c(Any &, pl_term) {}
};


// std::vector<>
template <typename T>
struct Convert<std::vector<T>> {
  static void p2c(std::vector<T> & arg, pl_term pt) {
    Frame fid{};
    arg.clear();
    auto head = PL_new_term_ref();
    auto list = PL_copy_term_ref(pt);
    while (PL_get_list(list, head, list)) {
      T val;
      prolog::p2c(val, head);
      arg.push_back(std::move(val));
    }
    if (!PL_get_nil(list)) {
      throw TypeMismatch(list, "nil");
    }
  }
  static void c2p(std::vector<T> const & arg, pl_term pt) {
    Frame fid{};
    auto a = PL_new_term_ref();
    PL_put_nil(pt);
    for (auto i = arg.crbegin(); i != arg.crend(); ++i) {
      prolog::c2p(*i, a);
      wrap_error(PL_cons_list(pt, a, pt));
    }
  }
};

// AnyN
template <typename T>
struct Convert<BaseFunctor<T, AnyN>> {
  static void c2p(BaseFunctor<T, AnyN> const & arg, pl_term pt) {
    auto func = PL_new_functor(PL_new_atom(detail::chars_from_functor(arg)),
                               std::get<1>(arg).val);
    wrap_error(PL_put_functor(pt, func));
  }
};

// Var<>
template <typename T>
struct Convert<Var<T>> {
  static void c2p(Var<T> const &, pl_term) {}
  static void p2c(Var<T> & arg, pl_term pt) {
    prolog::p2c(arg.var, pt);
  }
};

// Functors
template <typename... T>
struct Convert<BaseFunctor<T...>> {
  static void c2p(BaseFunctor<T...> const &, pl_term, std::index_sequence<>) {
    // Do nothing (ends recursion)
  }

  template <std::size_t i, std::size_t... Next>
  static void c2p(BaseFunctor<T...> const & arg, pl_term args, std::index_sequence<i, Next...>)
  {
    prolog::c2p(std::get<i + 1>(arg), args + i);
    c2p(arg, args, std::index_sequence<Next...>{});
  }

  static void c2p(BaseFunctor<T...> const & arg, pl_term pt) {
    Frame fid{};
    auto args = PL_new_term_refs(sizeof...(T) - 1);
    c2p(arg, args, std::make_index_sequence<sizeof...(T) - 1>{});
    auto func = PL_new_functor(PL_new_atom(detail::chars_from_functor(arg)),
                               sizeof...(T) - 1);
    wrap_error(PL_cons_functor_v(pt, func, args));
  }
};

template <typename... T>
struct Convert<Functor<T...>> {
  static void c2p(Functor<T...> const & arg, pl_term pt) {
    Convert<BaseFunctor<std::string, T...>>::c2p(arg, pt);
  }

  static void p2c(Functor<T...> &, pl_term, std::index_sequence<>) {
    // Do nothing (ends recursion)
  }
  template <std::size_t i, std::size_t... Next>
  static void p2c(Functor<T...> & arg, pl_term pt, std::index_sequence<i, Next...>) {
    {
      Frame fid{};
      pl_term t = PL_new_term_ref();
      _PL_get_arg(i + 1, pt, t);
      prolog::p2c(std::get<i + 1>(arg), t);
    }
    p2c(arg, pt, std::index_sequence<Next...>{});
  }

  static void p2c(Functor<T...> & arg, pl_term pt) {
    atom_t name;
    std::size_t arity;
    if (PL_get_compound_name_arity(pt, &name, &arity)
        && arity == sizeof...(T))
    {
      std::get<0>(arg) = PL_atom_chars(name);
      p2c(arg, pt, std::index_sequence_for<T...>{});
    } else {
      std::ostringstream os;
      os << "functor/" << sizeof...(T);
      throw TypeMismatch(pt, os.str());
    }
  }
};

template <typename... T>
struct Convert<CFunctor<T...>> : Convert<BaseFunctor<const char *, T...>> {};

// Pointers
template <typename T>
struct Convert<T *> {
  static void c2p(T * arg, pl_term pt) {
    static auto ptrfunc = PL_new_functor(PL_new_atom("__ptr"), 1);
    Frame fid{};
    pl_term t = PL_new_term_refs(1);
    void * val = const_cast<T *>(arg);
    wrap_error(PL_put_pointer(t, val));
    wrap_error(PL_cons_functor_v(pt, ptrfunc, t));
  }

  static void p2c(T * & arg, pl_term pt) {
    static auto ptrfunc = PL_new_functor(PL_new_atom("__ptr"), 1);
    if (PL_is_functor(pt, ptrfunc)) {
      Frame fid{};
      pl_term t = PL_new_term_ref();
      _PL_get_arg(1, pt, t);
      void *val;
      wrap_error(PL_get_pointer(t, &val));
      arg = static_cast<T *>(val);
      return;
    }
    throw TypeMismatch(pt, "__ptr/1");
  }
};

template <typename S>
struct Convert<S, std::enable_if_t<!std::is_enum<S>::value
                                   && std::is_convertible<S, pl_int>::value>>
{
  // int-like
  static void
  c2p(S const & arg, pl_term pt) {
    prolog::c2p(static_cast<pl_int>(arg), pt);
  }
  static void
  p2c(S & arg, pl_term pt) {
    pl_int val;
    prolog::p2c(val, pt);
    arg = val;
  }
};

template <typename S>
struct Convert<S, std::enable_if_t<std::is_enum<S>::value>>
{
  // Enums
  static void
  p2c(S & arg, pl_term pt) {
    std::string val;
    prolog::p2c(val, pt);
    arg = Str2Enum<S>(val);
  }
  static void
  c2p(S arg, pl_term pt) {
    prolog::c2p(Enum2Str(arg), pt);
  }
};

// build_query() is used to construct the arguments to a predicate that will be used for a
// query.  The first argument is a C++ query term, the second is the prolog term which will be
// unified with the C++ term, the third is the next term with which to unify query variables.

// Base case
template <typename T>
std::enable_if_t<!is_a_functor<T>::value, pl_term>
build_query(T const & arg, pl_term pt, pl_term vars)
{
  c2p(arg, pt);
  return vars;
}

// Case for Var<T>, which must unify with the next query variable
template <typename T>
pl_term build_query(Var<T> const & v, pl_term pt, pl_term vars)
{
  c2p(v, pt);
  wrap_error(PL_unify(pt, vars));
  return vars + 1;
}

// Functor args base case: no more arguments
template <typename... T>
pl_term build_query(BaseFunctor<T...> const &, pl_term, pl_term vars, std::index_sequence<>)
{
  return vars;
}

// Forward declaration
template <typename... T>
pl_term build_query(BaseFunctor<T...> const &, pl_term, pl_term);

// Handle functor arg i and recurse on further arguments
template <typename... T, std::size_t i, std::size_t... FRest>
pl_term build_query(BaseFunctor<T...> const & f, pl_term args, pl_term vars,
                    std::index_sequence<i, FRest...>)
{
  vars = build_query(std::get<i + 1>(f), args + i, vars);
  return build_query(f, args, vars, std::index_sequence<FRest...>{});
}

// Pharos-specific SWI initialization
void init();

// Output term to stream
std::ostream & term_to_stream(std::ostream & stream, pl_term pt);

template <typename T>
std::ostream &print_term(std::ostream & stream, T && t) {
  auto fid = Frame{};
  auto term = PL_new_term_ref();
  c2p(std::forward<T>(t), term);
  return term_to_stream(stream, term);
}

// Run command
bool command(char const *cmd, std::size_t len=std::size_t(-1));

// Run command
inline bool command(std::string const & s) {
  return command(s.c_str(), s.size());
}

// Case for functors
template <typename... T>
pl_term build_query(BaseFunctor<T...> const & f, pl_term pt, pl_term vars)
{
  Frame fid{};
  pl_term args = PL_new_term_refs(sizeof...(T) - 1);
  vars = build_query(f, args, vars, std::make_index_sequence<sizeof...(T) - 1>{});
  auto func = PL_new_functor(PL_new_atom(detail::chars_from_functor(f)), sizeof...(T) - 1);
  wrap_error(PL_cons_functor_v(pt, func, args));
  return vars;
}

template <typename... T>
class SpecificQuery;

// A non-templated base class for Query
class Query {
 public:
  void next();

  bool done() const { return finished; }

  explicit operator bool() const {
    return !done();
  }

  std::ostream & debug_print(std::ostream & stream) const;

  Query(Query const &) = delete;
  Query & operator=(Query const &) = delete;
  Query(Query &&) = delete;
  Query & operator=(Query &&) = delete;

  virtual ~Query() {
    lock_guard guard{mutex};
    _destroy();
  }

  template <typename... T>
  static auto instance(BaseFunctor<T...> const & p) {
    lock_guard guard{mutex};
    // Can't use make_shared here due to private constructor
    SpecificQuery<T...> *specific = nullptr;
    try {
      specific = specific_query(p);
    } catch (...) {
      delete specific;
      throw;
    }
    auto query = std::shared_ptr<Query>{specific};
    query_stack.emplace(query->query_handle, query);
    query->next();
    return query;
  }

  void close() {
    lock_guard guard{mutex};
    _destroy();
  }

 protected:
  Query() = default;

 private:
  template <typename T>
  static auto specific_query(BaseFunctor<T, AnyN> const & p) {
    return new SpecificQuery<T, AnyN>{chars_from_functor(p), std::get<1>(p).val};
  }

  template <typename... T>
  static auto specific_query(BaseFunctor<T...> const & p) {
    return new SpecificQuery<T...>{p};
  }

  // Query stack.  Used to make sure queries are properly nested.
  static std::stack<std::pair<qid_t, std::weak_ptr<Query>>> query_stack;
  static std::recursive_mutex mutex;
  using lock_guard = std::lock_guard<decltype(mutex)>;

  template<typename ... T> friend class SpecificQuery;
  qid_t query_handle = 0;
  predicate_t pred; // Predicate
  pl_term args;     // predicate term references
  pl_term vars;     // Prolog array of variables unified with the Var<> terms.
  fid_t frame;      // term frame
  bool finished = false;

  virtual void fill_references() = 0;

  void init_frame(char const *name, std::size_t num_args, std::size_t num_vars);
  void init_query();

  void _destroy_subqueries();
  void _close();
  void _destroy();

};

template <typename... T>
class SpecificQuery : public Query {
  // references_t is the type of a tuple of references to the C++ variables that were wrapped
  // by Var<>.
  using references_t =
    decltype(prolog::detail::extract_vars(std::declval<BaseFunctor<T...>>()));

  // Number of top-level predicate argument and number of variables in the query
  static constexpr auto num_args = sizeof...(T) - 1;
  static constexpr auto num_vars = std::tuple_size<references_t>::value;

  references_t variable_references; // Tuple of C++ variable references

  friend class Query;

 private:
  SpecificQuery(BaseFunctor<T...> const & p)
    : variable_references{prolog::detail::extract_vars(p)}
  {
    init_frame(detail::chars_from_functor(p), num_args, num_vars);
    // Populate args and vars
    auto vars_end = build_query(p, args, vars, std::make_index_sequence<num_args>{});
    assert(vars_end == vars + num_vars);
    MAYBE_UNUSED(vars_end);
    init_query();
  }

  SpecificQuery(char const *name, std::size_t arity) {
    init_frame(name, arity, 0);
    init_query();
  }

  void fill_references() override {
    fill_references(std::make_index_sequence<num_vars>{});
  }

  void fill_references(std::index_sequence<>) {}

  template <std::size_t i, std::size_t... Rest>
  void fill_references(std::index_sequence<i, Rest...>) {
    p2c(std::get<i>(variable_references), vars + i);
    fill_references(std::index_sequence<Rest...>{});
  }
};

class List;

template <>
struct Convert<List> {
  static void c2p(const List & lst, pl_term pt);
};

class List {
 public:
  template <typename... T>
  List(T &&... args) {
    push_back(std::forward<T>(args)...);
  }

  template <typename T>
  void push_back(const T & item) {
    list.emplace_back(std::make_shared<listitem<T>>(item));
  }

  template <typename T>
  void push_back(T && item) {
    list.emplace_back(std::make_shared<listitem<T>>(std::move(item)));
  }

  template <typename T, typename S, typename... Rest>
  void push_back(T && arg, S && arg2, Rest &&... args) {
    push_back(std::forward<T>(arg));
    push_back(std::forward<S>(arg2), std::forward<Rest>(args)...);
  }

 private:
  void push_back() {}

  struct listitem_t {
    virtual ~listitem_t() = default;
    virtual void c2p(pl_term) const = 0;
  };

  template <typename T>
  struct listitem : listitem_t {
    using type = std::conditional_t<
      std::is_array<T>::value,
      std::add_pointer_t<std::add_const_t<std::remove_extent_t<T>>>,
      std::remove_reference_t<T>>;
    type item;
    template<typename S> listitem(S && i) : item(std::forward<S>(i)) {}
    void c2p(pl_term pt) const override {
      prolog::c2p(item, pt);
    }
  };

  friend void Convert<List>::c2p(const List &, pl_term);

  using setters_t = std::vector<std::shared_ptr<listitem_t>>;
  setters_t list;
};

template<typename... T>
List list(T &&... args) {
  return List(std::forward<T>(args)...);
}

inline void Convert<List>::c2p(const List & lst, pl_term pt) {
  auto fid = impl::Frame{};
  auto val = PL_new_term_ref();
  wrap_error(PL_put_nil(pt));
  for (auto i = lst.list.rbegin(); i != lst.list.rend(); ++i) {
    (*i)->c2p(val);
    wrap_error(PL_cons_list(pt, val, pt));
  }
}

template <typename T>
inline void unify(T const & val, pl_term pt)
{
  auto fid = Frame{};
  auto term = PL_new_term_ref();
  c2p(val, term);
  wrap_error(PL_unify(pt, term));
}

using pred_fn = foreign_t (*)(pl_term, std::size_t, void *);

inline bool register_predicate(
  std::string const & name,
  std::size_t arity,
  pred_fn fn,
  std::string const & module)
{
  return PL_register_foreign_in_module(
    module.c_str(), name.c_str(), arity, reinterpret_cast<pl_function_t>(fn), PL_FA_VARARGS);
}

} // namespace impl
} // namespace prolog
} // namespace pharos

#endif  // Pharos_SWIPL_IMPL_HPP

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
