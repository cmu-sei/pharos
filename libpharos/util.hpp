// Copyright 2015-2023 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Utility_H
#define Pharos_Utility_H

#include <string>
#include <sstream>
#include <utility>
#include <type_traits>
#include <tuple>
#include <memory>
#include <vector>
#include <initializer_list>
#include <chrono>
#include <regex>

#include "md5.hpp"

// This file should be as minimal as possible to reduce circular inclusion pain.  If something
// you want to add here requires additional ROSE headers, try adding it to misc instead.  If it
// requires data types we've created, try adding it to one of the other files.

#define LEND std::endl

// For marking parameters and functions as unused (and supressing the warnings).
#define UNUSED __attribute__((unused))

namespace pharos {

std::string get_file_contents(const char *filename);
uint64_t parse_number(const std::string& str);
std::string to_lower(std::string input);
std::string to_hex(const std::string& input);

MD5Result get_string_md5(const std::string& input); // md5 of string contents
MD5Result get_file_md5(const std::string& fname); // md5 of file contents

// Are we on a color terminal?
bool color_terminal(int fd);

// This was a function created by Wes in several different classes.  It would have a nicer
// interface if it returned a string and the user could choose to print it to std::cout, but
// that's not how it was originally implemented. :-(
void dump_hex(char *buff, size_t len);

// Class for comparing version strings of the form N1.N2. ... .Nn, where Nx is an unsigned
// integer.
class Version {
  std::vector<unsigned> version;
 public:
  Version(const std::string & s);
  Version(std::initializer_list<unsigned> list) : version(list) {}
  bool operator== (const Version & other) const {
    return version == other.version;
  }
  bool operator!= (const Version & other) const {
    return version != other.version;
  }
  bool operator< (const Version & other) const {
    return version < other.version;
  }
  bool operator<= (const Version & other) const {
    return version <= other.version;
  }
  bool operator> (const Version & other) const {
    return version > other.version;
  }
  bool operator>= (const Version & other) const {
    return version >= other.version;
  }
};

// Invoke << and return a string with a && hack that correct for missing const qualifiers in
// Robb's code.
template<typename T>
std::string
to_string(T&& thing) {
  std::ostringstream os;
  os << std::forward<T>(thing);
  return os.str();
}

// Accessor functions for tuples and pairs, accessing by type.  Given a pair std::pair<A, B>,
// tget<A> can be used to get the first element, and tget<B> can be used to get the second
// element, assuming the types A and B differ, similarly for tuples.  This can be replaced by
// std::get once C++ 14 is used.  (The 't' in tget is for 'tuple'.)  There are multiple
// variants to allow the user to not have to care about const when declaring the extracted
// type.

namespace detail {
// Helper template for tget on tuples

template <std::size_t Pos, std::size_t Count, typename... Rest>
struct _tget_tuple_helper {
  static constexpr auto pos = Pos;
  static constexpr auto count = Count;
  using type = void;
};

template <std::size_t Pos, std::size_t Count, typename T, typename S, typename... Rest>
struct _tget_tuple_helper<Pos, Count, T, S, Rest...> {
  static constexpr auto match = std::is_same<T, typename std::decay<S>::type>::value;
  using parent = _tget_tuple_helper<Pos + 1, match ? Count + 1 : Count, T, Rest...>;
  static constexpr auto pos = match ? Pos : parent::pos;
  static constexpr auto count = parent::count;
  using type = typename std::conditional<match, S, typename parent::type>::type;
};

template <typename T, typename... Types>
using tget_tuple_helper = _tget_tuple_helper<0, 0, typename std::decay<T>::type, Types...>;
} /* namespace detail */


// Accessor by type functions for std::tuple
template <typename T, typename... Types>
constexpr
typename std::enable_if<detail::tget_tuple_helper<T, Types...>::count == 1,
                        typename detail::tget_tuple_helper<T, Types...>::type &>::type
tget(std::tuple<Types...> & t) {
  return std::get<detail::tget_tuple_helper<T, Types...>::pos>(t);
}
template <typename T, typename... Types>
constexpr
typename std::enable_if<detail::tget_tuple_helper<T, Types...>::count == 1,
                        typename detail::tget_tuple_helper<T, Types...>::type const &>::type
tget(std::tuple<Types...> const & t) {
  return std::get<detail::tget_tuple_helper<T, Types...>::pos>(t);
}

// Accessor by type functions for std::pair
template <typename T, typename A, typename B>
constexpr
typename std::enable_if<detail::tget_tuple_helper<T, A, B>::count == 1,
                        typename detail::tget_tuple_helper<T, A, B>::type &>::type
tget(std::pair<A, B> & t) {
  return std::get<detail::tget_tuple_helper<T, A, B>::pos>(t);
}

template <typename T, typename A, typename B>
constexpr
typename std::enable_if<detail::tget_tuple_helper<T, A, B>::count == 1,
                        typename detail::tget_tuple_helper<T, A, B>::type const &>::type
tget(std::pair<A, B> const & t) {
  return std::get<detail::tget_tuple_helper<T, A, B>::pos>(t);
}

// make_unique, which should have been in c++11, but is not
#if __cplusplus < 201402L
template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
#else
using std::make_unique;
#endif

template<typename M, typename K, typename V>
void map_add_or_replace(M & map, K && key, V && value) {
  auto loc = map.find(key);
  if (loc != map.end()) {
    map.erase(loc);
  }
  map.emplace(std::forward<K>(key), std::forward<V>(value));
}

template<typename M, typename K, typename... V>
auto & map_emplace_or_replace(M & map, K && key, V &&... value) {
  auto loc = map.find(key);
  if (loc != map.end()) {
    map.erase(loc);
  }
  auto result = map.emplace(std::piecewise_construct,
                            std::forward_as_tuple(std::forward<K>(key)),
                            std::forward_as_tuple(std::forward<V>(value)...));
  assert(result.second);
  return result.first->second;
}

struct Immobile {
  Immobile() = default;
  Immobile(Immobile const &) = delete;
  Immobile(Immobile &&) = delete;
  Immobile & operator=(Immobile const &) = delete;
  Immobile & operator=(Immobile &&) = delete;
};


template <typename Rep = double, typename Period = std::ratio<1>>
class Timer {
 public:
  using clock = std::chrono::steady_clock;
  using duration = std::chrono::duration<Rep, Period>;
  using time_point = std::chrono::time_point<clock, duration>;

  Timer() : start_(clock::now()), stop_(start_) {}

  duration stop() { stop_ = clock::now(); stopped_ = true; return stop_ - start_; }
  duration dur() const {
    if (!stopped_) { stop_ = clock::now(); }
    return stop_ - start_;
  }
  template <typename Stream>
  Stream & dur(Stream & stream) const {
    return stream << dur().count();
  }
  std::string dur_str() const {
    std::ostringstream os;
    return dur(os).str();
  }

 private:
  bool stopped_ = false;
  time_point start_;
  mutable time_point stop_;
};

template <typename Stream, typename Rep, typename Period>
Stream & operator<<(Stream & stream, Timer<Rep, Period> const & timer) {
  return timer.dur(stream);
}

template <typename Rep = double, typename Period = std::ratio<1>>
auto make_timer() {
  return Timer<Rep, Period>{};
}

namespace detail {
template <typename T>
struct is_duration : std::false_type {};
template <typename Rep, typename Period>
struct is_duration<std::chrono::duration<Rep, Period>> : std::true_type {};
} // namespace detail

template <typename Duration>
std::enable_if_t<detail::is_duration<Duration>::value,
                 Timer<typename Duration::rep, typename Duration::period>>
make_timer() {
  return Timer<typename Duration::rep, typename Duration::period>{};
}

// A generic RAII finalizer class
template <typename F>
class Finalizer {
  F fn;
  bool call = true;
 public:
  Finalizer(F f) : fn(f) {}
  Finalizer(Finalizer && o) : fn(o.fn) {
    o.call = false;
  }
  ~Finalizer() { if (call) { fn(); }}
};
template <typename F>
inline auto make_finalizer(F fn) { return Finalizer<F>(fn); }

// A std::regex that remembers the string from which it was constructed
class regex : public std::regex {
  string_type regex_string;
 public:
  regex() = default;
  regex(regex const &) = default;
  regex(regex &&) = default;
  regex & operator=(regex const &) = default;
  regex & operator=(regex &&) noexcept = default;

  explicit regex(std::string pattern, flag_type f = std::regex_constants::ECMAScript)
    : std::regex(pattern, f), regex_string(std::move(pattern)) {}

  string_type const & str() const { return regex_string; }
  regex & operator=(std::string pattern) { return assign(pattern); }
  regex & assign(regex const & other) { return *this = other; }
  regex & assign(regex && other) { return *this = std::move(other); }
  regex & assign(std::string pattern, flag_type f = std::regex_constants::ECMAScript) {
    std::regex::assign(pattern, f);
    regex_string = std::move(pattern);
    return *this;
  }
  void swap(regex & other) {
    std::regex::swap(other);
    regex_string.swap(other.regex_string);
  }
};

template <typename Stream>
Stream & operator<<(Stream & stream, regex const & r) {
  return stream << r.str();
}


} // namespace pharos

#endif // Pharos_Utility_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
