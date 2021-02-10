// Copyright 2017-2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_json
#define Pharos_json

#include <cstddef>              // std::nullptr_t
#include <memory>               // std::unique_ptr
#include <ostream>              // std::ostream
#include <cstdint>              // std::nullptr_t, std::intmax_t, std::uintmax_t
#include <string>               // std::string
#include <type_traits>          // std::is_convertible_t

namespace pharos {
namespace json {

class Builder;
class Simple;
class Visitor;
class Node;

using NodeRef = std::unique_ptr<Node>;

class Node {
 public:
  virtual bool visit(Visitor & v) const = 0;
  virtual ~Node() = default;
  virtual Builder & builder() const = 0;
  NodeRef copy() const;
};

class Array : public virtual Node {
 public:
  virtual void add(NodeRef o) = 0;
  virtual void add(Simple && v) = 0;
  virtual std::size_t size() const = 0;
  bool empty() const { return 0 == size(); }

  // Workaround for g++ 5.4 bug
  template <typename T>
  std::enable_if_t< !std::is_convertible<T, NodeRef>::value>
  add(T && x);
};

using ArrayRef = std::unique_ptr<Array>;

class Object : public virtual Node {
 public:
  virtual void add(std::string const & str, NodeRef o) = 0;
  virtual void add(std::string const & str, Simple && v) = 0;
  virtual void add(std::string && str, NodeRef o) = 0;
  virtual void add(std::string && str, Simple && v) = 0;
  virtual std::size_t size() const = 0;
  bool empty() const { return 0 == size(); }

  // Workaround for g++ 5.4 bug
  template <typename T>
  std::enable_if_t< !std::is_convertible<T, NodeRef>::value>
  add(std::string const & str, T && x);
  template <typename T>
  std::enable_if_t< !std::is_convertible<T, NodeRef>::value>
  add(std::string && str, T && x);
};

using ObjectRef = std::unique_ptr<Object>;

class Simple {
 public:
  using integer = std::intmax_t;
  using uinteger = std::uintmax_t;

 private:
  enum type_t { INT, UINT, DOUBLE, BOOL, NULLP, STRING, CSTRING, STRINGRR };
  type_t type;
  union {
    integer i;
    uinteger u;
    double d;
    bool b;
    std::string const * s;
    char const * c;
    std::string r;
  };

 public:
  Simple(short int v) : type(INT), i(integer(v)) {}
  Simple(unsigned short int v) : type(UINT), i(uinteger(v)) {}
  Simple(int v) : type(INT), i(integer(v)) {}
  Simple(unsigned int v) : type(UINT), i(uinteger(v)) {}
  Simple(long int v) : type(INT), i(integer(v)) {}
  Simple(unsigned long int v) : type(UINT), i(uinteger(v)) {}
  Simple(long long int v) : type(INT), i(integer(v)) {}
  Simple(unsigned long long int v) : type(UINT), i(uinteger(v)) {}
  Simple(double v) : type(DOUBLE), d(v) {}
  Simple(bool v) : type(BOOL), b(v) {}
  Simple() : type(NULLP) {}
  Simple(std::nullptr_t) : type(NULLP) {}
  Simple(std::string const & v) : type(STRING), s(&v) {}
  Simple(char const * v) : type(CSTRING), c(v) {}
  Simple(std::string && v) : type(STRINGRR), r(std::move(v)) {}

  ~Simple() {
    if (type == STRINGRR) {
      // The commented out code is correct, but fails in older version of clang++ due to a
      // compiler bug.

      //r.std::string::~string();
      r.~basic_string();
    }
  }

  NodeRef apply(Builder const & b);
};

// Workaround for g++ 5.4 bug
template <typename T>
std::enable_if_t< !std::is_convertible<T, NodeRef>::value>
Array::add(T && x) {
  add(Simple{std::forward<T>(x)});
}
template <typename T>
std::enable_if_t< !std::is_convertible<T, NodeRef>::value>
Object::add(std::string const & str, T && x) {
  add(str, Simple{std::forward<T>(x)});
}
template <typename T>
std::enable_if_t< !std::is_convertible<T, NodeRef>::value>
Object::add(std::string && str, T && x) {
  add(std::move(str), Simple{std::forward<T>(x)});
}

class Visitor {
 private:
  static bool do_nothing() { return true; }
 public:
  virtual bool data_number(double) { return do_nothing(); }
  virtual bool data_number(Simple::integer i) { return data_number(double(i)); }
  virtual bool data_number(Simple::uinteger u) { return data_number(double(u)); }
  virtual bool data_bool(bool) { return do_nothing(); }
  virtual bool data_null() { return do_nothing(); }
  virtual bool data_string(std::string const &) { return do_nothing(); }
  virtual bool begin_array() { return do_nothing(); }
  virtual bool end_array() { return do_nothing(); }
  virtual bool begin_object() { return do_nothing(); }
  virtual bool end_object() { return do_nothing(); }
  virtual bool data_key(std::string const &) { return do_nothing(); }
  virtual bool data_value(Node const & n) { return n.visit(*this); }
};

class Builder {
 public:
  virtual ~Builder() = default;

  virtual NodeRef simple(Simple::integer i) const = 0;
  virtual NodeRef simple(Simple::uinteger i) const = 0;
  virtual NodeRef simple(double d) const = 0;
  virtual NodeRef simple(bool b) const = 0;
  virtual NodeRef null() const = 0;
  virtual NodeRef simple(std::string const & str) const = 0;
  virtual NodeRef simple(std::string && str) const = 0;
  virtual ArrayRef array() const = 0;
  virtual ObjectRef object() const = 0;

  NodeRef simple(std::nullptr_t) const {
    return null();
  }
  NodeRef simple(char const * s) const {
    return s ? simple(std::string(s)) : null();
  }
  virtual NodeRef simple(Simple && val) const {
    return val.apply(*this);
  }

  NodeRef copy(Node const &) const;
};

using BuilderRef = std::unique_ptr<Builder>;

std::ostream & operator<<(std::ostream & stream, Node const & n);

class pretty {
 private:
  unsigned indent;
  unsigned initial_indent;
 public:
  explicit pretty(unsigned indent_ = 4, unsigned initial_indent_ = 0) :
    indent(indent_), initial_indent(initial_indent_) {}
  friend std::ostream & operator<<(std::ostream & s, pretty const & p);
};
std::ostream & operator<<(std::ostream & stream, pretty const & p);

BuilderRef simple_builder();

} // namespace json
} // namespace pharos

#endif // Pharos_json

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
