// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

// Prolog definitions that require no knowledge of the Prolog implementation

#ifndef Pharos_PROLOG_BASE_HPP
#define Pharos_PROLOG_BASE_HPP

#include <cstddef>
#include <stdexcept>
#include <type_traits>
#include <tuple>
#include <string>
#include <utility>

namespace pharos {
namespace prolog {

static constexpr auto prolog_default_module = "pharos";

// Base exception for all prolog errors
class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

namespace detail {

// Functor marker
struct IsAFunctor {};
template <typename T>
using is_a_functor = std::is_base_of<IsAFunctor, T>;

// Functor type
template <typename... Types>
struct BaseFunctor : public std::tuple<Types...>, public IsAFunctor {
  using std::tuple<Types...>::tuple;
};

// Functor type based on std::string
template <typename... Types>
struct Functor : public BaseFunctor<std::string, Types...> {
  using BaseFunctor<std::string, Types...>::BaseFunctor;
};

// Functor type based on char const *
template <typename... Types>
struct CFunctor : public BaseFunctor<char const *, Types...> {
  using BaseFunctor<char const *, Types...>::BaseFunctor;
};

// Creates a Functor
template <typename... Types>
constexpr Functor<Types...>
functor(std::string const & name, Types && ... args)
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
constexpr CFunctor<Types...>
functor(char const * name, Types && ... args)
{
  return CFunctor<Types...>(name, std::forward<Types>(args)...);
}

// Represents a variable binding
template <typename T>
struct Var {
  Var(T & v) : var{v} {}
  T & var;
  using type = T;
};

// Function to create a variable binding
template <typename T>
inline Var<T> var(T & v) {
  return Var<T>{v};
}

// The type of the "Don't care" variable  (underscore, in prolog)
struct Any {};

inline Any any() {
  return Any{};
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

template <typename T>
constexpr std::enable_if_t<!is_a_functor<T>::value, std::tuple<>>
extract_vars(T const &) {
  return {};
}

template <typename T>
constexpr std::tuple<Var<T>>
extract_vars(Var<T> const & v) {
  return std::make_tuple(v);
}

template <typename... T>
constexpr auto
extract_vars(BaseFunctor<T...> const & v) {
  return extract_vars(v, std::make_index_sequence<sizeof...(T) - 1>{});
}

template <typename... T>
constexpr std::tuple<>
extract_vars(BaseFunctor<T...> const &, std::index_sequence<>) {
  return {};
}

template <typename... T, std::size_t i, std::size_t... Next>
constexpr auto
extract_vars(const BaseFunctor<T...> & v, std::index_sequence<i, Next...>)
{
  return std::tuple_cat(extract_vars(std::get<i + 1>(v)),
                        extract_vars(v, std::index_sequence<Next...>{}));
}

template <typename... Types>
char const * chars_from_functor(BaseFunctor<char const *, Types...> const & f) {
  return std::get<0>(f);
}

template <typename... Types>
char const * chars_from_functor(BaseFunctor<std::string, Types...> const & f) {
  return std::get<0>(f).c_str();
}

template <typename T>
auto make_term(T && f) {
  return std::forward<T>(f);
}
template <typename... T>
auto make_term(const std::string & s, T &&... t) {
  return functor(s, std::forward<T>(t)...);
}
template <typename... T>
auto make_term(std::string && s, T &&... t) {
  return functor(std::move(s), std::forward<T>(t)...);
}
template <typename... T>
auto make_term(const char * s, T &&... t) {
  return functor(s, std::forward<T>(t)...);
}

template <typename T>
struct Fact {
  T val;
  Fact(T && p) : val{std::move(p)} {}
  Fact(T const & p) : val{p} {}
};

template <typename T>
struct is_a_fact : std::false_type {};
template <typename T>
struct is_a_fact<Fact<T>> : std::true_type {};

template <typename... T>
inline auto make_fact(T &&... args) {
  using type = decltype(make_term(std::forward<T>(args)...));
  return Fact<type>{make_term(std::forward<T>(args)...)};
}

} // namespace detail

using detail::functor;
using detail::var;
using detail::any;
using detail::make_fact;

} // namespace prolog
} // namespace pharos



#endif // Pharos_PROLOG_BASE_HPP
