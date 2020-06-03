// Copyright 2017-2018 Carnegie Mellon University.  See LICENSE file for terms.

#include "json.hpp"

#include <vector>               // std::vector
#include <map>                  // std::map
#include <utility>              // std::move
#include <cctype>               // std::iscntrl
#include <ios>                  // std::hex
#include <iomanip>              // std::setw
#include <iterator>             // std::ostreambuf_iterator
#include <algorithm>            // std::fill_n
#include <functional>           // std::function

namespace pharos {
namespace json {

#if __cplusplus < 201402L
template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
#else
using std::make_unique;
#endif

NodeRef Simple::apply(Builder const & builder)
{
  switch(type) {
   case INT:
    return builder.simple(i);
   case UINT:
    return builder.simple(u);
   case DOUBLE:
    return builder.simple(d);
   case BOOL:
    return builder.simple(b);
   case NULLP:
    return builder.null();
   case STRING:
    return builder.simple(*s);
   case CSTRING:
    return builder.simple(c);
   case STRINGRR:
    return builder.simple(std::move(r));
  }
  return builder.null();
}

namespace {
// Return whether this is a valid utf-8 string.  If it is is, return 0.  If not, return -1.  If
// it is valid, but truncated, return the number of bytes that need to be truncated to make the
// string valid.
int is_valid_utf8(std::string const & s) {
  std::string::size_type count = 0;
  int trailing_chars = 0;
  int tcc = 0;
  int nonzero = 0;
  uint32_t val = 0;
  for (unsigned char c : s) {
    if (c & 0x80) {
      if (trailing_chars) {
        if ((c & 0x40) || (nonzero && !(c & nonzero))) {
          return -1;
        }
        val = (val << 6) | (c & 0x3f);
        nonzero = 0;
        ++tcc;
        if (trailing_chars == tcc) {
          if (val > 0x10ffff) {
            return -1;
          }
          trailing_chars = 0; tcc = 0;
        }
      } else if (!(c & 0x40)) {
        return -1;
      } else if ((c & 0xe0) == 0xc0) {
        if (!(c & 0x1e)) {
          return -1;
        }
        val = c & 0x1f;
        nonzero = 0;
        trailing_chars = 1; tcc = 0; ++count;
      } else if ((c & 0xf0) == 0xe0) {
        val = c & 0x0f;
        nonzero = val ? 0 : 0x20;
        trailing_chars = 2; tcc = 0; ++count;
      } else if ((c & 0xf8) == 0xf0) {
        val = c & 0x07;
        nonzero = val ? 0 : 0x30;
        trailing_chars = 3; tcc = 0; ++count;
      } else {
        return -1;
      }
    } else if (trailing_chars) {
      return -1;
    } else {
      val = c;
    }
  }

  if (trailing_chars) {
    return count > 1 ? tcc + 1 : -1;
  }

  return 0;
}

std::ostream & output_string(std::ostream & stream, std::string const & s)
{
  stream << '"';
  auto ut = is_valid_utf8(s);
  auto e = s.size();
  if (ut >= 0) {
    e -= ut;
  }
  for (std::string::size_type i = 0; i < e; ++i) {
    unsigned char c = s[i];
    const char *v;
    switch(c) {
     case '"':
      v = "\\\""; break;
     case '\\':
      v = "\\\\"; break;
     case '\b':
      v = "\\b";  break;
     case '\f':
      v = "\\f";  break;
     case '\n':
      v = "\\n";  break;
     case '\r':
      v = "\\r";  break;
     case '\t':
      v = "\\t";  break;
     default:
      if (std::iscntrl(c) || ((ut < 0) && c & 0x80)) {
        auto flags = stream.flags();
        auto fill = stream.fill('0');
        stream << "\\u00" << std::setw(2) << std::hex << unsigned(c);
        stream.flags(flags);
        stream.fill(fill);
        continue;
      }
      stream.put(c);
      continue;
    }
    stream << v;
  }
  return stream << '"';
}

class Writer : public Visitor {
 private:
  std::ostream & stream;
  unsigned indent;
  unsigned current_indent;
  bool empty;
  bool kv = false;

  void simple_indent() {
    if (!kv) {
      do_indent();
    }
  }

  template <typename T>
  bool simple_write(T v) {
    simple_indent();
    stream << v;
    return true;
  }
  void inc_indent() {
    current_indent += indent;
  }
  void dec_indent() {
    current_indent -= indent;
  }
  void do_indent() {
    std::fill_n(
      std::ostreambuf_iterator<std::ostream::char_type, std::ostream::traits_type>(stream),
      current_indent, ' ');
  }
  void newline() {
    if (indent) {
      stream << '\n';
    }
  }
  void do_comma() {
    if (empty) {
      empty = false;
    } else {
      stream << ',';
    }
    newline();
  }

 public:
  Writer(std::ostream & _stream, unsigned _indent = 0, unsigned _initial_indent = 0) :
    stream(_stream), indent(_indent), current_indent(_initial_indent) {}

  bool data_number(double n) override {
    return simple_write(n);
  }
  bool data_number(json::Simple::integer n) override {
    return simple_write(n);
  }
  bool data_number(json::Simple::uinteger n) override {
    return simple_write(n);
  }
  bool data_bool(bool b) override {
    return simple_write(b ? "true" : "false");
  }
  bool data_null() override {
    return simple_write("null");
  }
  bool data_string(std::string const & s) override {
    simple_indent();
    output_string(stream, s);
    return true;
  }
  bool begin_array() override {
    simple_indent();
    stream << '[';
    empty = true;
    kv = false;
    inc_indent();
    return true;
  }
  bool end_array() override {
    dec_indent();
    if (!empty) {
      newline();
      do_indent();
    }
    stream << ']';
    return true;
  }
  bool data_value(Node const & n) override {
    if (!kv) {
      do_comma();
    }
    auto rval = n.visit(*this);
    kv = false;
    empty = false;
    return rval;
  }
  bool begin_object() override {
    simple_indent();
    stream << '{';
    empty = true;
    inc_indent();
    return true;
  }
  bool end_object() override {
    dec_indent();
    if (!empty) {
      newline();
      do_indent();
    }
    stream << '}';
    return true;
  }
  bool data_key(std::string const & k) override {
    do_comma();
    do_indent();
    kv = true;
    output_string(stream, k) << ": ";
    return true;
  }
};

class Copier : public Visitor {
  Builder const & builder;
  NodeRef node;
  std::function<void(NodeRef &&)> adder;
  std::string key;
  template <typename T>
  bool simple(T v) { node = builder.simple(v); return true; }
 public:
  Copier(Builder const & b) : builder(b) {}
  NodeRef operator()() { return std::move(node); }
  bool data_number(double d) override { return simple(d); }
  bool data_number(Simple::integer i) override { return simple(i); }
  bool data_number(Simple::uinteger u) override { return simple(u); }
  bool data_bool(bool b) override { return simple(b); }
  bool data_null() override { return simple(nullptr); }
  bool data_string(std::string const &s) override { return simple(s); }
  bool begin_array() override {
    auto array = builder.array();
    auto a = array.get();
    node = std::move(array);
    adder = [a](NodeRef && r) { a->add(std::move(r)); };
    return true;
  }
  bool begin_object() override {
    auto obj = builder.object();
    auto o = obj.get();
    node = std::move(obj);
    adder = [this, o](NodeRef && r) { o->add(std::move(key), std::move(r)); };
    return true;
  }
  bool data_key(std::string const &k) override {
    key = k;
    return true;
  }
  bool data_value(Node const & n) override {
    Copier c{builder};
    n.visit(c);
    adder(c());
    return true;
  }
};

} // unnamed namespace

NodeRef Node::copy() const {
  return builder().copy(*this);
}

NodeRef Builder::copy(Node const & n) const {
  Copier c{*this};
  n.visit(c);
  return c();
}

namespace simple {

class Node : public virtual json::Node
{
  static BuilderRef builder_;

 public:
  json::Builder & builder() const override {
    return *builder_;
  }
};

template <typename T>
class Simple : public Node
{
 protected:
  T val;
 public:
  Simple(T const & v) : val(v) {}
  Simple(T && v) : val(std::move(v)) {}
};

template <typename T>
class Number : public Simple<T>
{
 public:
  using Simple<T>::Simple;
  bool visit(Visitor & v) const override {
    return v.data_number(this->val);
  }
};

class Bool : public Simple<bool> {
 public:
  using Simple<bool>::Simple;
  bool visit(Visitor & v) const override {
    return v.data_bool(val);
  }
};

class String : public Simple<std::string> {
 public:
  using Simple<std::string>::Simple;
  bool visit(Visitor & v) const override {
    return v.data_string(val);
  }
};

class Null : public Node
{
 public:
  bool visit(Visitor & v) const override {
    return v.data_null();
  }
};

class Array : public Node, public json::Array
{
  std::vector<NodeRef> vec;
 public:
  using Node::builder;

  void add(NodeRef o) override {
    vec.push_back(std::move(o));
  }

  void add(json::Simple && o) override;

  std::size_t size() const override {
    return vec.size();
  }

  bool visit(Visitor & v) const override {
    if (!v.begin_array()) {
      return false;
    }
    for (auto & node : vec) {
      if (!v.data_value(*node)) {
        return false;
      }
    }
    return v.end_array();
  }

};

class Object : public Node, public json::Object {
  std::map<std::string, NodeRef> map;
 public:
  using Node::builder;

  void add(std::string const & str, NodeRef o) override {
    map.emplace(str, std::move(o));
  }
  void add(std::string && str, NodeRef o) override {
    map.emplace(std::move(str), std::move(o));
  }

  void add(std::string const & str, json::Simple && v) override;
  void add(std::string && str, json::Simple && v) override;

  std::size_t size() const override {
    return map.size();
  }

  bool visit(Visitor & v) const override {
    if (!v.begin_object()) {
      return false;
    }
    for (auto & pair : map) {
      if (!v.data_key(pair.first)) {
        return false;
      }
      if (!v.data_value(*pair.second)) {
        return false;
      }
    }
    return v.end_object();
  }
};

class Builder : public json::Builder
{
 public:
  using json::Builder::simple;

  NodeRef simple(json::Simple::integer i) const override {
    return make_unique<Number<json::Simple::integer>>(i);
  }
  NodeRef simple(json::Simple::uinteger i) const override {
    return make_unique<Number<json::Simple::uinteger>>(i);
  }
  NodeRef simple(double d) const override {
    return make_unique<Number<double>>(d);
  }
  NodeRef simple(bool b) const override {
    return make_unique<Bool>(b);
  }
  NodeRef null() const override {
    return make_unique<Null>();
  }
  NodeRef simple(std::string && s) const override {
    return make_unique<String>(std::move(s));
  }
  NodeRef simple(std::string const & s) const override {
    return make_unique<String>(s);
  }
  ArrayRef array() const override {
    return make_unique<Array>();
  }
  ObjectRef object() const override {
    return make_unique<Object>();
  }
};

BuilderRef Node::builder_ = json::simple_builder();

void Array::add(json::Simple && v) {
  add(builder().simple(std::move(v)));
}

void Object::add(std::string const & str, json::Simple && v) {
  add(str, builder().simple(std::move(v)));
}

void Object::add(std::string && str, json::Simple && v) {
  add(std::move(str), builder().simple(std::move(v)));
}

} // namespace simple

namespace {
const int indent_idx = std::ios_base::xalloc();
const int initial_indent_idx = std::ios_base::xalloc();
}

std::ostream & operator<<(std::ostream & stream, Node const & n)
{
  Writer w(stream, stream.iword(indent_idx), stream.iword(initial_indent_idx));
  n.visit(w);
  if (stream.iword(indent_idx)) {
    stream << '\n';
  }
  return stream;
}

std::ostream & operator<<(std::ostream & stream, pretty const & p)
{
  stream.iword(indent_idx) = p.indent;
  stream.iword(initial_indent_idx) = p.initial_indent;
  return stream;
}

BuilderRef simple_builder()
{
  return make_unique<simple::Builder>();
}

} // namespace json
} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
