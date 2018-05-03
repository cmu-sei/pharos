// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#ifndef Pharos_MATCHER_HPP_
#define Pharos_MATCHER_HPP_

#include <rose.h>
#include <cstddef>
#include <utility>
#include <functional>
#include <type_traits>
#include <cassert>

namespace pharos {

//     **********************************
//     ***  Expression Tree Matchers  ***
//     **********************************
//
// This library makes Matcher objects, which implement pattern matching on Rose TreeNodes.
// Another way to think of these objects are as regular expressions over trees, with the
// ability to refer to matched sub-expressions within successfully applied expression.
//
// Here is an example:
//
// #include "matcher.hpp"
//
// using Rose::BinaryAnalysis::SymbolicExpr::Ptr;
//
// void myFunction(const Ptr tn)
// {
//   // The matchers are implemented in a 'matcher' namespace, due to a
//   // large number of named types
//   using namespace matcher;
//
//   // left and right will be filled with our matched references
//   node_t left, right;
//
//   // Here is the matcher object itself.  I highly recommend using auto
//   // here.  This matcher matches an ITE clause, returning
//   // references to the true and false nodes.
//   auto m = Matcher<Expr<Op<OP_ITE>, Any, Ref<Any>, Ref<Any>>>(left, right);
//
//   // Here we test for a match:
//   if (m(tn)) {
//     // There was a match!  'left' and 'right' are now bound to the
//     // true and false nodes from the ITE expression.
//     do_something(left, right);
//   }
// }
//
// The full syntax of matchers is described below.  In these expressions, 'T' will refer to a
// matcher tag.  'v' will refer to a value, the type of which can be found in the description.
// In the matcher namespace there are type aliases for node pointers, etc., which are used in
// the descriptions below.  They are:
//
// using node_t     = Rose::BinaryAnalysis::SymbolicExpr::Ptr;          // TreeNodePtr
// using leaf_t     = Rose::BinaryAnalysis::SymbolicExpr::LeafPtr;      // LeafNodePtr
// using interior_t = Rose::BinaryAnalysis::SymbolicExpr::InteriorPtr;  // InternalNodePtr
// using nodelist_t = Rose::BinaryAnalysis::SymbolicExpr::Nodes;        // std::vector<node_t>
// using operator_t = Rose::BinaryAnalysis::SymbolicExpr::Operator;     // OP_ITE, etc.
//
// Matcher<T> creates a matcher that matches an expression based on the tag T.  The matcher's
// constructor will take as its arguments variables that will be filled in by the Ref<>
// patterns in T in the order that they occur, left to right.
//
// The simple tags 'T' along with their capture reference types (see Ref<> below) are:
//
//     Any         - Matches anything (node_t)
//     Leaf        - Matches a leaf node (node_t, leaf_t)
//     Var         - Matches a variable (node_t, leaf_t)
//     Mem         - Matches a memory location (node_t, leaf_t)
//     Int         - Matches a constant integer (node_t, leaf_t, uint64_t)
//     Const<v>    - Matches a specific constant integer 'v'.  For example: Const<4> matches
//                   a literal 4.  (node_t, leaf_t, uint64_t)
//     Interior    - Matches an interior node (node_t, interior_t)
//
// Matching the contents of an interior node is done with the Expr tag:
//
//     Expr<O, T, ...>  - (node_t, interior_t)
//
// In this expression, O is the operator, and it is followed by 0 to N tags.  Exprs can be
// nested to any level.  The arguments can be:
//
//     Any         - Matches any operator (operator_t)
//     Op<v>       - Matches a specific operator 'v' (operator_t)
//
// As a special case, an Expr<> can end with an ArgList, which matches all remaining arguments:
//
//     ArgList     - The rest of the arguments of the Expr (nodelist_t)
//
// As such, any Expr can be matched by Expr<Any, ArgList>.
//
// There are also the node attribute tags:
//
//     Bits<v, T>         - Matches a 'T' that has a bit-width of 'v'
//     Flags<f, T>        - Matches a 'T' if the high bits in 'f' are set are set in T's flags
//     FlagsMask<m, f, T> - Matches a 'T' where the bits defined by the mask 'm' are
//                          equivalent to 'f'
//
// The capture reference types (see Ref<> below) of the node attribute flags are the same of
// that of their argument tag, T.
//
// To match one or more possible expressions, you can use the Or tag:
//
//     Or<T1, T2, ...>  - Matches T1, or if that fails T2, or if that fails...
//
// The Or<> tag can also be used in Operator matches as well (E.g.: Or<Op<OP_ADD>,
// Op<OP_SUB>>).  Please note that Ref<> tags (see below) within Or<> tags may or may not
// modify their capture variables depending on what branch of the Or<> the Ref<> tag is within.
// Ref<>s within the first macthing branch of an Or<>are guaranteed a capture.  Others are not.
//
// The capture reference type (see Ref<> below) of Or<> is the intersection of the capture
// reference types of its arguments.
//
// Finally, the special tag Ref<> can be placed in any location.
//
//     Ref<T>      - A marked reference to the value matched by T
//
// Refs are special.  They do not affect pattern matching at all.  Rather, they mark the parts
// of the pattern that you want to refer to after a successful match.  For each Ref<> in the
// pattern, the Matcher's constructor takes a single argument (a capture variable).  The type
// of the argument depends on what the argument of the Ref<> is.  See the noted capture
// reference types in the descriptions of each individual tag.
//
// Please note: Capture variables in non-matched expressions are *not* guaranteed to not
// change.
//
//
//     **********************************
//     ***  Extending Tree Matchers  ***
//     **********************************
//
// Extending Matcher to match new concepts is easy.  It does not even need to be done in this
// header file, but can be done anywhere the code that needs the new concepts can see them.
// Extending Matcher for a new concept is a two or three-step process:
//
// 1) Create a new tag.
//
//    Creating a new tag is easy.  Simply create a new struct that inherits from Tag.  Tag
//    takes one or two type arguments.  One is a set of captures.  Captures are the set of
//    types that a Ref<> of this tag should be able to fill.  Pass the capture types to Tag
//    using a Captures<type1, type2, ...> argument.  The second is a set of sub-tags.  See
//    Expr, FlagsMask, and Or for examples.  The sub-tags should be passed to Tag using a
//    SubTags<type1, type2, ...> argument.
//
//    Both the Captures and SubTags arguments are optional.  SubTags need not be included if
//    the tag has no sub-tags.  If no Captures is passed, Ref<> will not be allowed to refer to
//    this tag.
//
//    There are some utility functions for the Captures argument that make working with them
//    more convenient.  CapturesOf<T> will return T's Captures argument.  This can but used
//    when a tag has a single sub-tag and should capture the same types as its sub-tag.  See
//    FlagsMask for an example.  CommonCaptures<T1, T2, ...> will return a Captures argument
//    that consists of the capture types in common between the given set of tags.  See Or for
//    an example.
//
// 2) Create a specialization for Matcher
//
//    Specialize matcher::Matcher<> for your new tag.  The matcher should declare an operator()
//    const method which returns bool and takes a const node_t & argument.  This operator()
//    should test the node and return whether it matches the tag.
//
//    If a tag has sub-tags, you probably want to recurse by calling Matcher<> objects on the
//    sub-tags.  If you have a single sub-tag, you can have your Matcher inherit from the
//    Matcher for the sub-tag, and thus possibly exploit the empty base class optimization.
//    When you do this, remember to inherit the constructor from the base matcher class.  See
//    FlagsMask for an example.
//
//    If a tag has multiple sub-tags, you can use MultiMatcher as a base.  MultiMatcher takes
//    as type arguments a matcher for the first sub-tag, the first sub-tag, a matcher for the
//    rest of the sub-tags, and the rest of the sub-tags.  The left and right matchers are
//    exposed as 'left' and 'right' respectively.  They must be referred to via 'this->left'
//    and 'this->right' due to vagaries of name lookup in templated classes.  See Expr and Or
//    for examples.
//
//    Note: make sure this specialization is in the matcher namespace.
//
// 3) (optional) Create a type converter
//
//    If your tag has a capture type that the matching node must be converted to on a
//    successful match, there needs to be code that knows how to do that conversion.  To do
//    this, create a specialization of struct matcher::Convert<> with the given From and To
//    types, and implement the static assign function.  See the Convert structs in this file
//    for examples.
//
//    Note: make sure this specialization is in the matcher namespace.
//

namespace matcher {

// Simplified name for the SymbolicExpr namespace
namespace rse = Rose::BinaryAnalysis::SymbolicExpr;

// Aliases from rose/src/midend/binaryAnalysis/BinarySymbolicExpr.h
using operator_t = rse::Operator;
using node_t     = rse::Ptr;
using interior_t = rse::InteriorPtr;
using leaf_t     = rse::LeafPtr;
using nodelist_t = rse::Nodes;

using std::size_t;

} // namespace matcher
} // namespace pharos

// Include Tags and tag operations
#include "matchertags.hpp"

namespace pharos {
namespace matcher {

// ***
// ***  Type tags which are used to build a TreeNode match expression
// ***

// Match anything
struct Any : Tag<Captures<node_t>> {};

// Match a leaf node
struct Leaf : Tag<Captures<node_t, leaf_t>> {};

// Match a named variable
struct Var : Tag<Captures<node_t, leaf_t>> {};

// Match memory
struct Mem : Tag<Captures<node_t, leaf_t>> {};

// Match any integer constant
struct Int : Tag<Captures<node_t, leaf_t, uint64_t>> {};

// Match the constant value 'val'
template <uint64_t val>
struct Const : Tag<Captures<node_t, leaf_t, uint64_t>> {};

// Match an interior node
struct Interior : Tag<Captures<node_t, interior_t>> {};

// Match an interior node by structure
template <typename Operator, typename... Args>
struct Expr : Tag<Captures<node_t, interior_t>, SubTags<Operator, Args...>> {};

// Match a specific operator
template <operator_t op>
struct Op : Tag<Captures<operator_t>> {};

// Match an argument list of any size
struct ArgList : Tag<Captures<nodelist_t>> {};

// Match 'T', and return the match
template <typename T>
struct Ref : Tag<CapturesOf<T>, SubTags<T>> {};

// Match T with 'bits' significant bits
template <size_t bits, typename T>
struct Bits : Tag<CapturesOf<T>, SubTags<T>> {};

// Match T when T's flag bits or-ed with 'mask' are equal to 'flags'
template <unsigned mask, unsigned flags, typename T>
struct FlagsMask : Tag<CapturesOf<T>, SubTags<T>> {};

// Match T where T's flags have the 'flags' bits set
template <unsigned flags, typename T>
using Flags = FlagsMask<flags, flags, T>;

// Match T1, or T2, or ...
template <typename T1, typename... T>
struct Or : Tag<CommonCaptures<T1, T...>, SubTags<T1, T...>> {};


// ***
// ***  Converters
// ***


// Conversion operators.  These are used to convert a tree data type to a capture reference
// data type, when we know that the conversion is safe.
template <typename From, typename To>
struct Convert {
  static void assign(const From & from, To & to);
  // If you pass a capture variable which is not of a type supported by the tag you are
  // capturing, the static_assert below will fire.  Make sure you are using the correct type
  // for the tag.  In particular, make sure uint64_t is used for ints (and not other integer
  // types), and operator_t is used for operators.
  static_assert(sizeof(From) == 0, "No conversion defined for these types.");
};

// The null-conversion.
template <typename T>
struct Convert<T, T> {
  static void assign(const T & from, T & to) {
    to = from;
  }
};

// Conversion from a node_t to an interior_t
template <>
struct Convert<node_t, interior_t> {
  static void assign(const node_t & from, interior_t & to) {
    to = from->isInteriorNode();
    assert(to);
  }
};

// Conversion from a node_t to a leaf_t
template <>
struct Convert<node_t, leaf_t> {
  static void assign(const node_t & from, leaf_t & to) {
    to = from->isLeafNode();
    assert(to);
  }
};

// Conversion from a node_t to a uint64_t
template <>
struct Convert<node_t, uint64_t> {
  static void assign(const node_t & from, uint64_t & to) {
    leaf_t in = from->isLeafNode();;
    assert(in && in->isNumber());
    to = in->toInt();
  }
};


// ***
// ***  The implementation of the Matcher object
// ***

// The type of a matcher
template <typename Match>
struct Matcher {
  // Any instantiation of this base class is an error.  All real instantiations are done by
  // specializations of this class.  If you get an error here, you have either used a Tag which
  // is invalid in this context, or someone forgot to implement support for that tag.
  static_assert(IsTag<Match>::value, "The type argument to Matcher<> is not a valid Tag");
  static_assert(!IsTag<Match>::value, "No specialization has been implemented for this Tag");
};

// A matcher for operators
template <typename Operator>
struct OpMatcher {
  // Any instantiation of this base class is an error.  All real instantiations are done by
  // specializations of this class.  If you get an error here, you have either used a Tag which
  // is invalid in this context, or someone forgot to implement support for that tag.
  static_assert(IsTag<Operator>::value, "The type argument to Matcher<> is not a valid Tag");
  static_assert(!IsTag<Operator>::value,
                "No specialization has been implemented for this Tag");
};


} // namespace matcher
} // namespace pharos

// Matching Exprs, even with their recursive structure is easy.  Properly capturing the correct
// number of Ref<>s in these Exprs is hard.  The guts necessary to do this are implemented in a
// separate file, which is included here.
#include "matcherimpl.hpp"

namespace pharos {
namespace matcher {

// Matching anything
template <>
struct Matcher<Any> {
  bool operator()(const node_t & tn) const noexcept {
    return tn;
  }
};

// Match a leaf node
template <>
struct Matcher<Leaf> {
  bool operator()(const node_t &tn) const {
    if (!tn) { return false; }
    return tn->isLeafNode();
  }
};

// Match a named variable
template <>
struct Matcher<Var> {
  bool operator()(const node_t &tn) const {
    if (!tn) { return false; }
    auto n = tn->isLeafNode();
    return n && n->isVariable();
  }
};

// Match memory
template <>
struct Matcher<Mem> {
  bool operator()(const node_t &tn) const {
    if (!tn) { return false; }
    auto n = tn->isLeafNode();
    return n && n->isMemory();
  }
};

// Match any integer value
template <>
struct Matcher<Int> {
  bool operator()(const node_t &tn) const {
    if (!tn) { return false; }
    auto n = tn->isLeafNode();
    return n && n->isNumber();
  }
};

// Match a specific integer value
template <uint64_t val>
struct Matcher<Const<val>> {
  bool operator()(const node_t &tn) const {
    if (!tn) { return false; }
    auto n = tn->isLeafNode();
    return n && (n->isNumber() && n->nBits() <= 64 && n->toInt() == val);
  }
};

// Match an interior node
template <>
struct Matcher<Interior> {
  bool operator()(const node_t &tn) const {
    if (!tn) { return false; }
    return tn->isInteriorNode();
  }
};

// Matches an Expr
template <typename Operator, typename... Args>
struct Matcher<Expr<Operator, Args...>> :
    MultiMatcher<OpMatcher<Operator>, Operator,
                 NodeListMatcher<Args...>, Args...>
{
  using MultiMatcher<OpMatcher<Operator>, Operator,
                     NodeListMatcher<Args...>, Args...>::MultiMatcher;

  bool operator()(const node_t & tn) const {
    if (!tn) { return false; }
    interior_t i = tn->isInteriorNode();
    return i && this->left(i->getOperator()) && this->right(i);
  }
};

// Match a T, and store a reference to the match
template <typename T>
struct Matcher<Ref<T>> : private Matcher<T> {

  // Enable constructors where the first argument is a reference to a valid capture type
  template <typename Arg, typename... Args,
            typename = std::enable_if<CaptureValidFor<Arg, T>::value>>
  Matcher(Arg & ref, Args &&... args) :
    Matcher<T>(std::forward<Args>(args)...),
    // setref is a closure that converts the node to the Arg type and assigns it to ref
    setref([&ref](const node_t & tn) { Convert<node_t, Arg>::assign(tn, ref); })
  {}

  bool operator()(const node_t & tn) const {
    bool rv = Matcher<T>::operator()(tn);
    if (rv) {
      setref(tn);
    }
    return rv;
  }

 private:
  std::function<void(const node_t & tn)> setref;
};

// Match T with 'bits' significant bits
template <size_t bits, typename T>
struct Matcher<Bits<bits, T>> : private Matcher<T> {
  using Matcher<T>::Matcher;

  bool operator()(const node_t & tn) const {
    if (!tn) { return false; }
    return bits == tn->nBits() && Matcher<T>::operator()(tn);
  }
};

// Match T when T's flag bits or-ed with 'mask' are equal to 'flags'
template <unsigned mask, unsigned flags, typename T>
struct Matcher<FlagsMask<mask, flags, T>> : private Matcher<T> {
  static_assert((flags & ~mask) == 0,
                "There are bits set in flags that are not set in mask.  "
                "This will always be false and is likely an error.");

  using Matcher<T>::Matcher;

  bool operator()(const node_t & tn) const {
    if (!tn) { return false; }
    return (flags == (tn->flags() & mask)) && Matcher<T>::operator()(tn);
  }
};

// Match T1 or T2
template <typename T>
struct Matcher<Or<T>> : Matcher<T> {
  using Matcher<T>::Matcher;
};


template <typename S, typename... T>
struct Matcher<Or<S, T...>> :
    MultiMatcher<Matcher<S>, S, Matcher<Or<T...>>, Or<T...>>
{
  using MultiMatcher<Matcher<S>, S, Matcher<Or<T...>>, Or<T...>>::MultiMatcher;

  bool operator()(const node_t & tn) const {
    return this->left(tn) || this->right(tn);
  }
};

// Match any operator
template <>
struct OpMatcher<Any> {
  constexpr bool operator()(operator_t) const noexcept {
    return true;
  }
};

// Match a specific operator
template <operator_t op>
struct OpMatcher<Op<op>> {
  bool operator()(operator_t in) const {
    return in == op;
  }
};

// Match and return an operator
template <typename T>
struct OpMatcher<Ref<T>> : private OpMatcher<T> {
  template <typename... Args>
  OpMatcher(operator_t & op, Args &&... args)
    : OpMatcher<T>(std::forward<Args>(args)...), v(op)
  {}

  bool operator()(operator_t in) const {
    bool rv = OpMatcher<T>::operator()(in);
    if (rv) {
      v = in;
    }
    return rv;
  }

 private:
  operator_t & v;
};

template <typename T>
struct OpMatcher<Or<T>> : OpMatcher<T> {
  using OpMatcher<T>::OpMatcher;
};

template <typename T1, typename... T2>
struct OpMatcher<Or<T1, T2...>> :
    MultiMatcher<OpMatcher<T1>, T1, OpMatcher<Or<T2...>>, Or<T2...>>
{
  using MultiMatcher<OpMatcher<T1>, T1, OpMatcher<Or<T2...>>, Or<T2...>>::MultiMatcher;

  bool operator()(operator_t in) const {
    return this->left(in) || this->right(in);
  }
};

} // namespace matcher
} // namespace pharos

#endif  // Pharos_MATCHER_HPP_

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* c-basic-offset: 2  */
/* End:               */
