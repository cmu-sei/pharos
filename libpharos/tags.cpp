// Copyright 2021 Carnegie Mellon University.  See LICENSE file for terms.

#include "tags.hpp"

#include <algorithm>
#include <exception>

#if __cplusplus < 201703L
#include <boost/functional/hash.hpp>

namespace pharos {
namespace tags {
template<typename T>
std::size_t hash_value(StringIdentifier<T> const & i) {
  return std::hash<StringIdentifier<T>>{}(i);
}
}}
#endif

namespace std {
template<typename T>
struct hash<pharos::tags::StringIdentifier<T>> {
  auto operator()(pharos::tags::StringIdentifier<T> const & i) const {
    return std::hash<std::string>{}(i());
  }
};
} // namespace std

namespace pharos {

std::size_t TagManager::KeyHash::operator()(key_t const & key) const
{
#if __cplusplus < 201703L
  return hash_value(key);
#else
  return std::hash<key_t>{}(key);
#endif
}

void TagManager::add(key_t const & key, tag_t const & tag)
{
  auto current = map.equal_range(key);
  if (current.first != current.second) {
    map.emplace(key, tag);
  } else if (!std::any_of(current.first, current.second,
                          [&tag](auto const & t) { return t.second == tag; }))
  {
    map.emplace_hint(current.first, key, tag);
  }
}

void TagManager::remove(key_t const & key)
{
  auto current = map.equal_range(key);
  map.erase(current.first, current.second);
}

void TagManager::remove(key_t const & key, tag_t const & tag)
{
  auto current = map.equal_range(key);
  auto iter = std::find_if(current.first, current.second,
                           [&tag](auto const & t) { return t.second == tag; });
  if (iter != current.second) {
    map.erase(iter);
  }
}

bool TagManager::check(key_t const & key, tag_t const & tag) const
{
  auto current = map.equal_range(key);
  return std::any_of(current.first, current.second,
                     [&tag](auto const & t) { return t.second == tag; });
}

void TagManager::merge(char const *yaml, size_t length)
{
  merge(YAML::Load(std::string{yaml, length}));
}

void TagManager::merge(std::string const & path)
{
  merge(YAML::LoadFile(path));
}

void TagManager::merge(YAML::Node n)
{
  auto node = const_node(n);
  if (node.IsNull()) {
    return;
  }
  if (!node.IsMap()) {
    throw std::runtime_error("Illegal yaml node for tag manager");
  }
  auto hashes = node["hashes"];
  if (hashes) {
    if (!hashes.IsMap()) {
      throw std::runtime_error("Illegal hashes key for tag manager");
    }
    for (auto hnode: hashes) {
      auto key = hnode.first;
      auto tags = hnode.second;
      if (!key.IsScalar()) {
        throw std::runtime_error("Illegal key in hashes for tag manager");
      }
      auto hash = Hash{key.Scalar()};
      remove(hash);
      if (tags.IsScalar()) {
        add(std::move(hash), tags.Scalar());
      } else if (tags.IsSequence()) {
        for (auto tag: tags) {
          if (!tag.IsScalar()) {
            throw std::runtime_error("Illegal tag in hashes for tag manager");
          }
          add(hash, tag.Scalar());
        }
      } else {
        throw std::runtime_error("Illegal tag in hashes for tag manager");
      }
    }
  }
  auto names = node["names"];
  if (names) {
    if (!names.IsMap()) {
      throw std::runtime_error("Illegal names key for tag manager");
    }
    for (auto nnode: names) {
      auto key = nnode.first;
      auto tags = nnode.second;
      if (!key.IsScalar()) {
        throw std::runtime_error("Illegal key in names for tag manager");
      }
      auto name = Name{key.Scalar()};
      remove(name);
      if (tags.IsScalar()) {
        add(std::move(name), tags.Scalar());
      } else if (tags.IsSequence()) {
        for (auto tag: tags) {
          if (!tag.IsScalar()) {
            throw std::runtime_error("Illegal tag in names for tag manager");
          }
          add(name, tag.Scalar());
        }
      } else {
        throw std::runtime_error("Illegal tag in names for tag manager");
      }
    }
  }
  auto addresses = node["addresses"];
  if (addresses) {
    if (!addresses.IsMap()) {
      throw std::runtime_error("Illegal addresses key for tag manager");
    }
    for (auto anode: addresses) {
      auto key = anode.first;
      auto tags = anode.second;
      if (!key.IsScalar()) {
        throw std::runtime_error("Illegal key in addresses for tag manager");
      }
      auto address = key.as<rose_addr_t>();
      remove(address);
      if (tags.IsScalar()) {
        add(address, tags.Scalar());
      } else if (tags.IsSequence()) {
        for (auto tag: tags) {
          if (!tag.IsScalar()) {
            throw std::runtime_error("Illegal tag in addresses for tag manager");
          }
          add(address, tag.Scalar());
        }
      } else {
        throw std::runtime_error("Illegal tag in addresses for tag manager");
      }
    }
  }
}




} // addressespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
