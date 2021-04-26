// Copyright 2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Tags_H
#define Pharos_Tags_H

#include <functional>    // For std::hash
#include <string>        // For std::string
#include <unordered_map> // For std::unordered_map
#include <utility>       // For std::move

#if __cplusplus >= 201703L
#include <variant>
#else
#include <boost/variant.hpp>
#endif

#include "misc.hpp"
#include "yaml.hpp"

namespace pharos {
namespace tags {

template <typename T>
class StringIdentifier {
 private:
  std::string str;
 public:
  StringIdentifier(std::string const & s) : str(s) {}
  StringIdentifier(std::string && s) : str(std::move(s)) {}
  bool operator==(const StringIdentifier<T> & s) const { return str == s.str; }
  std::string const & operator()() const { return str; }
};

using Hash = StringIdentifier<struct HashTag>;
using Name = StringIdentifier<struct NameTag>;
} // namespace tags

class TagManager {
 private:

#if __cplusplus >= 201703L
  template <typename... T>
  using variant = std::variant<T...>;
#else
  template <typename... T>
  using variant = boost::variant<T...>;
#endif

 public:
  using Hash = tags::Hash;
  using Name = tags::Name;
  using key_t = variant<rose_addr_t, Hash, Name>;
  using tag_t = std::string;

 private:
  struct KeyHash {
    std::size_t operator()(key_t const & key) const;
  };
  using map_t = std::unordered_map<key_t, tag_t, KeyHash>;
  map_t map;

 public:

  TagManager() = default;

  void merge(YAML::Node node);
  void merge(std::string const & path);
  void merge(char const *yaml, std::size_t length);

  void remove(key_t const & key);

  void add(key_t const & key, tag_t const & tag);
  void add_hash(std::string key, tag_t const & tag) {
    return add(Hash{std::move(key)}, tag);
  }
  void add_name(std::string key, tag_t const & tag) {
    return add(Name{std::move(key)}, tag);
  }
  void remove(key_t const & key, tag_t const & tag);

  bool check(key_t const & key, tag_t const & tag) const;
  bool check_hash(std::string const & key, tag_t const & tag) const {
    return check(Hash{key}, tag);
  }
  bool check_name(std::string const & key, tag_t const & tag) const {
    return check(Name{key}, tag);
  }
  auto checker(tag_t tag) const {
    return [tag = std::move(tag), this](key_t const & key) { return check(key, tag); };
  }
  auto checker_hash(tag_t tag) const {
    return [tag = std::move(tag), this](std::string const & key) {
      return check(Hash{key}, tag); };
  }
  auto checker_name(tag_t tag) const {
    return [tag = std::move(tag), this](std::string const & key) {
      return check(Name{key}, tag); };
  }
  auto checker_address(tag_t tag) const {
    return [tag = std::move(tag), this](rose_addr_t key) {
      return check(key, tag); };
  }

}; // class TagManager

} // namespace pharos

#endif  // Pharos_Tags_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
