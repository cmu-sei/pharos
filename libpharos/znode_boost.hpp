// Copyright 2019 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Znode_Boost_H
#define Pharos_Znode_Boost_H

// This file adapts Z3 vectors so that they fit the Boost range concept.

// This is a wrapper class for Z3's iterators that adds the
// pre-increment operator.
namespace z3 {

template <class T>
struct iterator_wrapper {
  typename z3::ast_vector_tpl<T>::iterator it;
  iterator_wrapper (const typename z3::ast_vector_tpl<T>::iterator &&it_) : it (it_) {}
  iterator_wrapper (const iterator_wrapper &) = default;
  iterator_wrapper& operator++() {
    it++;
    return *this;
  }
  iterator_wrapper operator++(int) {
    iterator_wrapper copy (*this);
    it++;
    return copy;
  }
  bool operator==(const iterator_wrapper &b) {
    return it == b.it;
  }
  bool operator!=(const iterator_wrapper &b) {
    return it != b.it;
  }
  T operator*() {
    return *it;
  }
};
}

// These are required for the boost range concept
namespace boost {
template <class T>
struct range_mutable_iterator <z3::ast_vector_tpl <T> > {
  typedef typename z3::iterator_wrapper<T> type;
};
template <class T>
struct range_const_iterator <z3::ast_vector_tpl <T> > {
  typedef typename z3::iterator_wrapper <T> type;
};
namespace iterators {
template <>
struct iterator_traversal <typename z3::ast_vector_tpl <z3::expr>::iterator> {
  typedef forward_traversal_tag type;
};
template <>
struct iterator_traversal <typename z3::ast_vector_tpl <z3::sort>::iterator> {
  typedef forward_traversal_tag type;
};
}
}

// These are also required for the boost range concept
namespace z3 {
template <class T>
inline typename z3::iterator_wrapper<T> range_begin (z3::ast_vector_tpl <T> &vec) {
  return z3::iterator_wrapper<T> (vec.begin ());
}

template <class T>
inline typename z3::iterator_wrapper<T> range_begin (const z3::ast_vector_tpl <T> &vec) {
  return z3::iterator_wrapper<T> (vec.begin ());
}

template <class T>
inline typename z3::iterator_wrapper<T> range_end (z3::ast_vector_tpl <T> &vec) {
  return z3::iterator_wrapper<T> (vec.end ());
}

template <class T>
inline typename z3::iterator_wrapper<T> range_end (const z3::ast_vector_tpl <T> &vec) {
  return z3::iterator_wrapper<T> (vec.end ());
}
}

// These are the iterator traits for the iterator wrapper class
namespace std {
template <>
struct iterator_traits <z3::iterator_wrapper <z3::expr> > {
  using difference_type = int;
  using value_type = z3::expr;
  using pointer = z3::expr *;
  using reference = z3::expr;
  using iterator_category = forward_iterator_tag;
};

template <>
struct iterator_traits <z3::iterator_wrapper <z3::sort>> {
  using difference_type = int;
  using value_type = z3::sort;
  using pointer = z3::sort *;
  using reference = z3::sort;
  using iterator_category = forward_iterator_tag;
};
}

#endif
