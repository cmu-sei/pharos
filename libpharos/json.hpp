// Copyright 2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_json
#define Pharos_json

#include <cstddef>              // std::nullptr_t
#include <memory>               // std::unique_ptr
#include <ostream>              // std::ostrem
#include <cstdint>              // std::nullptr_t
#include <string>               // std::string

namespace json {
namespace wrapper {

class Builder;
class Simple;;

class Node {
 public:
  virtual std::ostream & write(std::ostream & stream) const = 0;
  virtual ~Node() = default;
};

using NodeRef = std::unique_ptr<Node>;

class Array : public Node {
 public:
  virtual void add(NodeRef o) = 0;
  virtual void add(Simple && v) = 0;
};

using ArrayRef = std::unique_ptr<Array>;

class Object : public Node {
 public:
  virtual void add(std::string const & str, NodeRef o) = 0;
  virtual void add(std::string const & str, Simple && v) = 0;
  virtual void add(std::string && str, NodeRef o) = 0;
  virtual void add(std::string && str, Simple && v) = 0;
};

using ObjectRef = std::unique_ptr<Object>;

class Simple {
 private:
  enum type_t { INT, DOUBLE, BOOL, NULLP, STRING, CSTRING, STRINGRR };
  type_t type;
  union {
    std::intmax_t i;
    double d;
    bool b;
    std::string const * s;
    char const * c;
    std::string r;
  };

 public:
  Simple(short int v) : type(INT), i(std::intmax_t(v)) {}
  Simple(unsigned short int v) : type(INT), i(std::intmax_t(v)) {}
  Simple(int v) : type(INT), i(std::intmax_t(v)) {}
  Simple(unsigned int v) : type(INT), i(std::intmax_t(v)) {}
  Simple(long int v) : type(INT), i(std::intmax_t(v)) {}
  Simple(unsigned long int v) : type(INT), i(std::intmax_t(v)) {}
  Simple(long long int v) : type(INT), i(std::intmax_t(v)) {}
  Simple(unsigned long long int v) : type(INT), i(std::intmax_t(v)) {}
  Simple(double v) : type(DOUBLE), d(v) {}
  Simple(bool v) : type(BOOL), b(v) {}
  Simple() : type(NULLP) {}
  Simple(std::nullptr_t) : type(NULLP) {}
  Simple(std::string const & v) : type(STRING), s(&v) {}
  Simple(char const * v) : type(CSTRING), c(v) {}
  Simple(std::string && v) : type(STRINGRR), r(std::move(v)) {}

  ~Simple() {
    if (type == STRINGRR) {
      r.std::string::~string();
    }
  }

  NodeRef apply(Builder const & b);
};

class Builder {
 public:

  virtual NodeRef simple(std::intmax_t i) const = 0;
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
};

std::ostream & operator<<(std::ostream & stream, Node const & n);

} // namespace json::wrapper

std::unique_ptr<wrapper::Builder> simple_builder();

} // namespace json

#endif // Pharos_json

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
