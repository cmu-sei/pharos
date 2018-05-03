// Copyright 2016-2018 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Typedb_H
#define Pharos_Typedb_H

#include <memory>
#include <utility>
#include <vector>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop
#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <boost/range/adaptor/transformed.hpp>

#include "state.hpp"

namespace pharos {
namespace types {

enum class Objectness {
  // the case where a variable's objectness cannot be determined i.e. the top.
  Top,

  // This indicates that the pointer type in question is an aggregate (C++-style) object
  Object,

  // This lattice indicates that the pointer type is not an aggregate (C++-style) object
  NotObject,

  // This value denotes when a variable can be both an object pointer and not an object pointer
  // depending on the code path taken. It is the most general value, i.e.  the bottom
  Bottom
};

// This enumeration captures whether a type is signed or unsigned
enum class Signedness {

  // the case where a variable's sign cannot be determined i.e. the top.
  Top,

  // This indicates that the type in question is signed
  Signed,

  // This latticeindicates that the type in question is unsigned
  Unsigned,

  // This value denotes when a variable can be both signed and unsigned
  // depending on the code path taken. It is the most general value, i.e.
  // the bottom
  Bottom
};

// This enumeration captures whether a type is referential (i.e. a pointer)
// or a concrete value
enum class Pointerness {

  // This is the bottom of the lattice. Basically, we do not have enough
  // information about whether a data element is a pointer
  Top,

  // This abstract value means that the type is a pointer
  Pointer,

  // This abstract value mean that the type is not a pointers
  NotPointer,

  // This value indicates
  Bottom
};

} // types namespace

namespace typedb {

class Type;
class Value;
class TypeCallback;

using TypeRef = std::shared_ptr<const Type>;
using Path = boost::filesystem::path;

class DB {
 private:
  std::map<std::string, std::shared_ptr<Type>> db;

 public:
  DB() = default;

  enum handle_error_t { IGNORE, LOG_WARN, LOG_ERROR, THROW };

  static DB create_standard(const ProgOptVarMap &vm, handle_error_t handle = LOG_WARN);

  void load_json(const Path & path);
  void load_json(const YAML::Node & typemap, const std::string & filename);
  void add_type(const std::string & name, const YAML::Node & node);
  TypeRef lookup(const std::string & name) const;
 private:
  const std::shared_ptr<Type> & internal_lookup(const std::string & name);
  void update();
};


struct Param {
  template <typename T, typename N>
  Param(T && t, N && n) : type(std::forward<T>(t)), name(std::forward<N>(n)) {}
  TypeRef type;
  std::string name;
  size_t offset;
};

using ParamList = std::vector<Param>;

using types::Signedness;
using types::Pointerness;

class Type : public std::enable_shared_from_this<Type> {
 private:
  std::string name;
  const Signedness signedness;
  const Pointerness pointerness;

 public:
  Type(const std::string & _name,
       Signedness s = Signedness::Unsigned,
       Pointerness p = Pointerness::NotPointer)
    : name(_name), signedness(s), pointerness(p)
  {}

  Type(std::string && _name,
       Signedness s = Signedness::Unsigned,
       Pointerness p = Pointerness::NotPointer)
    : name(std::move(_name)), signedness(s), pointerness(p)
  {}

  template <typename N>
  Type(N && _name, Pointerness p)
    : Type(std::forward<N>(_name), Signedness::Unsigned, p)
  {}

  virtual ~Type() = default;

  const std::string & get_name() const {
    return name;
  }

  size_t arch_bytes() const;

  TypeRef ptr() const {
    return shared_from_this();
  }

  virtual size_t get_size() const = 0;
  virtual size_t get_align() const = 0;
  virtual bool is_unknown() const { return false; }

  Signedness get_signedness() const {
    return signedness;
  }

  Pointerness get_pointerness() const {
    return pointerness;
  }

  template <typename T>
  std::shared_ptr<const T> as() const {
    return std::dynamic_pointer_cast<const T>(shared_from_this());
  }

  Value get_value(
    const SymbolicValuePtr & value,
    const SymbolicState * memory = nullptr) const;

 private:
  friend class DB;
  virtual void update(const DB &) {}
};

class Pointer : public Type {
 private:
  TypeRef pointed_to;
 public:
  template <typename N, typename T>
  Pointer(N && _name, T && contained) :
    Type(std::forward<N>(_name), Pointerness::Pointer),
    pointed_to(std::forward<T>(contained))
  {}

  template <typename T>
  Pointer(T && contained)
    : Pointer(generate_name(contained), std::forward<T>(contained))
  {}

  const TypeRef & get_contained() const {
    return pointed_to;
  }
  size_t get_size() const override {
    return arch_bytes();
  }
  size_t get_align() const override {
    return arch_bytes();
  }

 private:
  void update(const DB & db) override;
  static std::string generate_name(const TypeRef & type);
};

class Struct : public Type {
 private:
  ParamList members;
  size_t size;
  size_t align;
 public:
  template <typename N, typename P>
  Struct(N && _name, P && params) :
    Type(std::forward<N>(_name)),
    members(std::forward<P>(params))
  {
    init();
  }

  const ParamList & get_members() const {
    return members;
  }

  ParamList::const_iterator begin() const {
    return members.cbegin();
  }

  ParamList::const_iterator end() const {
    return members.cend();
  }

  size_t get_size() const override {
    return size;
  }
  size_t get_align() const override {
    return align;
  }

 private:
  void update(const DB & db) override;
  void init();
};

class String : public Type {
 public:
  enum stype { CHAR, WCHAR, TCHAR };

  template <typename N>
  String(N && _name, stype _type = CHAR)
    : Type(std::forward<N>(_name), Pointerness::Pointer), type(_type)
  {}

  size_t get_size() const override {
    return arch_bytes();
  }
  size_t get_align() const override {
    return arch_bytes();
  }

  stype get_string_type() const {
    return type;
  }

 private:
  stype type;
};


class Sized : public Type {
 private:
  size_t size;
 public:
  template <typename N>
  Sized(N && _name, size_t _size, Signedness s)
    : Type(std::forward<N>(_name), s), size(_size)
  {}

  size_t get_size() const override {
    return size;
  }
  size_t get_align() const override {
    return size;
  }
};

class Unsigned : public Sized {
 public:
  template <typename N>
  Unsigned(N && _name, size_t _size)
    : Sized(std::forward<N>(_name), _size, Signedness::Unsigned)
  {}

  using Sized::Sized;

};

class Signed : public Sized {
 public:
  template <typename N>
  Signed(N && _name, size_t _size)
    : Sized(std::forward<N>(_name), _size, Signedness::Signed)
  {}

};

class Float : public Sized {
 public:
  template <typename N>
  Float(N && _name, size_t _size)
    : Sized(std::forward<N>(_name), _size, Signedness::Signed)
  {}
};

class Bool : public Sized {
 public:
  template <typename N>
  Bool(N && _name) : Sized(std::forward<N>(_name), 1, Signedness::Unsigned) {}

};

class UnknownType : public Type {
 private:
  size_t size;
 public:
  template <typename N>
  UnknownType(N && _name, size_t s = 1) :
    Type(std::forward<N>(_name), Signedness::Top, Pointerness::Top), size(s)
  {}

  bool is_unknown() const override {
    return true;
  }

  size_t get_size() const override {
    return size;
  }
  size_t get_align() const override {
    return std::min(size, arch_bytes());
  }
};

class IllegalConversion : public std::logic_error
{
 public:
  using std::logic_error::logic_error;
};


class Value {
 private:
  // Memory.  Might be NULL.
  const SymbolicState * memory;

  // Type
  TypeRef type;

  // Stored value
  SymbolicValuePtr node;

  // Used by val_from_param_wrapper
  Value val_from_param(const Param & param) const;

  // Used by member_values()
  struct val_from_param_wrapper {
    const Value * value;
    val_from_param_wrapper(const Value *v) : value(v) {}
    Value operator()(const Param & param) const {
      return value->val_from_param(param);
    }
  };

  // Used by vpair_from_param_wrapper
  std::pair<Param, Value> vpair_from_param(const Param & param) const {
    return std::make_pair(param, val_from_param(param));
  }

  // Used by members()
  struct vpair_from_param_wrapper {
    const Value * value;
    vpair_from_param_wrapper(const Value *v) : value(v) {}
    std::pair<Param, Value> operator()(const Param & param) const {
      return value->vpair_from_param(param);
    }
  };

 public:
  Value() : Value(std::make_shared<UnknownType>("<unknown>")) {}

  Value(const TypeRef & t) : memory(nullptr), type(t)
  {}

  template <typename TR>
  Value(TR && t, const SymbolicValuePtr & n, const SymbolicState * mem = nullptr)
    : memory(mem), type(std::forward<TR>(t)), node(n)
  {}

  const SymbolicValuePtr & get_raw() const {
    return node;
  }
  const TreeNodePtr & get_expression() const {
    static auto nullnode = TreeNodePtr();
    return node ? node->get_expression() : nullnode;
  }

  explicit operator bool() const {
    return node;
  }

  const TypeRef & get_type() const {
    return type;
  }

  // Iterator for structs over Types
  using type_range = boost::iterator_range<ParamList::const_iterator>;

  // Iterator for structs over Values
  using value_range = decltype(std::declval<type_range>() | boost::adaptors::transformed(
                                 std::declval<val_from_param_wrapper>()));
  // Iterator for structs over std::pair<Param, Value>
  using vpair_range = decltype(std::declval<type_range>() | boost::adaptors::transformed(
                                 std::declval<vpair_from_param_wrapper>()));


  // Pointer
  bool is_pointer() const;
  bool is_nullptr() const;
  Value dereference() const;

  // String
  bool is_string() const;
  boost::optional<std::string> as_string(bool tchar_is_wide = true) const;

  // Raw values
  bool is_unsigned() const;
  bool is_signed() const;
  bool is_bool() const;
  boost::optional<uint64_t> as_unsigned() const;
  boost::optional<int64_t> as_signed() const;
  boost::optional<bool> as_bool() const;

  // Struct
  bool is_struct() const;
  type_range member_types() const;
  value_range member_values() const;
  vpair_range members() const;

  // Unknown
  bool is_unknown() const {
    return type->is_unknown();
  }

};


} // namespace typedb
} // namespace pharos

#endif  // Pharos_Typedb_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
