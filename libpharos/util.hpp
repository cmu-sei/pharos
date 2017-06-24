// Copyright 2015, 2016, 2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Utility_H
#define Pharos_Utility_H

#include <string>
#include <utility>
#include <type_traits>
#include <tuple>
#include <memory>

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

std::string get_string_md5(const std::string& input); // md5 of string contents
std::string get_file_md5(const std::string& fname); // md5 of file contents

// Are we on a color terminal?
bool color_terminal();

// This was a function created by Wes in several different classes.  It would have a nicer
// interface if it returned a string and the user could choose to print it to std::cout, but
// that's not how it was originally implemented. :-(
void dump_hex(char *buff, size_t len);

// Accessor functions for pairs, accessing by type.  Given a pair std::pair<A, B>, tget<A> can
// be used to get the first element, and tget<B> can be used to get the second element,
// assuming the types A and B differ.  This can be replaced by std::get once C++ 14 is used.
// (The 't' in tget is for 'tuple'.)  There are multiple variants to allow the user to not have
// to care about const when declaring the extracted type.
template<typename T, typename Second>
constexpr
typename std::enable_if<!std::is_same<typename std::decay<T>::type,
                                      typename std::decay<Second>::type>::value, T &>::type
tget(std::pair<T, Second> & p) {
  return p.first;
}
template<typename T, typename First>
constexpr
typename std::enable_if<!std::is_same<typename std::decay<T>::type,
                                      typename std::decay<First>::type>::value, T &>::type
tget(std::pair<First, T> & p) {
  return p.second;
}
template<typename T, typename Second>
constexpr
typename std::enable_if<!std::is_same<typename std::decay<T>::type,
                                      typename std::decay<Second>::type>::value,
                        const T &>::type
tget(const std::pair<T, Second> & p) {
  return p.first;
}
template<typename T, typename First>
constexpr
typename std::enable_if<!std::is_same<typename std::decay<T>::type,
                                      typename std::decay<First>::type>::value,
                        const T &>::type
tget(const std::pair<First, T> & p) {
  return p.second;
}
template<typename T, typename Second>
constexpr
typename std::enable_if<!std::is_same<typename std::decay<T>::type,
                                      typename std::decay<Second>::type>::value,
                        const T &>::type
tget(std::pair<const T, Second> & p) {
  return p.first;
}
template<typename T, typename First>
constexpr
typename std::enable_if<!std::is_same<typename std::decay<T>::type,
                                      typename std::decay<First>::type>::value,
                        const T &>::type
tget(std::pair<First, const T> & p) {
  return p.second;
}
template<typename T, typename Second>
constexpr
typename std::enable_if<!std::is_same<typename std::decay<T>::type,
                                      typename std::decay<Second>::type>::value,
                        const T &>::type
tget(const std::pair<const T, Second> & p) {
  return p.first;
}
template<typename T, typename First>
constexpr
typename std::enable_if<!std::is_same<typename std::decay<T>::type,
                                      typename std::decay<First>::type>::value,
                        const T &>::type
tget(const std::pair<First, const T> & p) {
  return p.second;
}

namespace detail {
// Helper template for tget on tuples

template <std::size_t Pos, std::size_t Count, typename... Rest>
struct _tget_tuple_helper {
    static constexpr auto pos = Pos;
    static constexpr auto count = Count;
};

template <std::size_t Pos, std::size_t Count, typename T, typename S, typename... Rest>
struct _tget_tuple_helper<Pos, Count, T, S, Rest...> {
    static constexpr auto match = std::is_same<T, typename std::decay<S>::type>::value;
    using parent = _tget_tuple_helper<Pos + 1, match ? Count + 1 : Count, T, Rest...>;
    static constexpr auto pos = match ? Pos : parent::pos;
    static constexpr auto count = parent::count;
};

template <typename T, typename... Types>
using tget_tuple_helper = _tget_tuple_helper<0, 0, typename std::decay<T>::type, Types...>;
} /* namespace detail */


// Accessor by type functions for std::tuple
template <typename T, typename... Types>
constexpr
typename std::enable_if<detail::tget_tuple_helper<T, Types...>::count == 1, T &>::type
tget(std::tuple<Types...> & t) {
    return std::get<detail::tget_tuple_helper<T, Types...>::pos>(t);
}
template <typename T, typename... Types>
constexpr
typename std::enable_if<detail::tget_tuple_helper<T, Types...>::count == 1, const T &>::type
tget(const std::tuple<Types...> & t) {
    return std::get<detail::tget_tuple_helper<T, Types...>::pos>(t);
}


#if __cplusplus < 201402L
template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
#else
using std::make_unique;
#endif

} // namespace pharos

#endif // Pharos_Utility_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
