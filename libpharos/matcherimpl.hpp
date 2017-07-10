// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#ifndef Pharos_MATCHERIMPL_HPP_
#define Pharos_MATCHERIMPL_HPP_

#include <utility>
#include <type_traits>
#include <algorithm>

// This file contains the gory guts of the matcher, especially the parts necessary to match
// Expr nodes.  Some of the techniques used here are experimental, and might be able to be
// implemented in a simpler fashion.

namespace pharos {
namespace matcher {
namespace detail {

// Indices serves two purposes.  To hold a sequence of size_t template parameters, and to help
// generate the simple sequence starting at zero and incrementing by one.
template <size_t... Idx>
struct Indices {
  // The next largest Indices, assuming it is a sequence starting at zero
  using next = Indices<Idx..., sizeof...(Idx)>;
};

// Create an Indices of size n starting at 0
// Inductive step: get the indices of the next step
template <size_t n>
struct MakeIndices_ {
  using type = typename MakeIndices_<n - 1>::type::next;
};

// Base case: empty indices
template <>
struct MakeIndices_<0> {
  using type = Indices<>;
};


// Adds offset to the integers in the Indices<> in Seq.
template <size_t offset, typename Seq>
struct ApplyOffset_;

// Does the work for ApplyOffset_
template <size_t offset, size_t... idx>
struct ApplyOffset_<offset, Indices<idx...>> {
  using type = Indices<(idx + offset)...>;
};

// MakeIndices generates an Indices of the given size starting from offset.  For example:
//
// MakeIndices<0> == Indices<>
// MakeIndices<3> == Indices<0, 1, 2>
// MakeIndices<3, 2> == Indices<2, 3, 4>
template <size_t size, size_t offset = 0>
using MakeIndices = typename ApplyOffset_<
  offset, typename MakeIndices_<size>::type>::type;


// PackGet_ returns the idx'th type in Arg, Args...
// Inductive step: recurse on Args...
template <size_t idx, typename Arg, typename... Args>
struct PackGet_ {
  using type = typename PackGet_<idx - 1, Args...>::type;
};

// Base case: return the zero'th type, Arg
template <typename Arg, typename... Args>
struct PackGet_<0, Arg, Args...> {
  using type = Arg;
};

// PackGet returns the idx'th type in Args.  For example:
//
// PackGet<0, A, B, C> == A
// PackGet<1, A, B, C> == B
// PackGet<2, A, B, C> == C
template <size_t idx, typename... Args>
using PackGet = typename PackGet_<idx, Args...>::type;

// Return the n'th arg in a set of arguments, whose type is T
// Inductive step: recurse on get()
template <typename T, size_t n, typename Arg, typename... Args>
struct PackGetValue_ {
  static constexpr T && get(Arg &&, Args &&... args) noexcept {
    return std::forward<T>(
      PackGetValue_<T, n - 1, Args...>::get(std::forward<Args>(args)...));
  }
};

// Base case: return the argument
template <typename T, typename... Args>
struct PackGetValue_<T, 0, T, Args...> {
  static constexpr T && get(T && arg, Args &&...) noexcept {
    return std::forward<T>(arg);
  }
};

// pack_get returns the nth argument in its list of args.  For example:
//
// pack_get<0>(1, 2, 3, 4) -> 1
// pack_get<2>(1, 2, 3, 4) -> 3
template <size_t n, typename... Args>
constexpr PackGet<n, Args...> &
pack_get(Args &&... args) noexcept {
  using GetValue = PackGetValue_<PackGet<n, Args...>, n, Args...>;
  return GetValue::get(std::forward<Args>(args)...);
}

// Ref counter.  CountRef<T>::value is the number of Refs in the tag T, or the number of Refs
// in the tags in the Types<> argument T.
// Inductive step: the number of Refs in T is the number of refs in T's subtags
template <typename T>
struct CountRef : CountRef<typename T::subtags> {};

// Base case: empty Types<>.  There are zero refs here
template <>
struct CountRef<Types<>> : std::integral_constant<size_t, 0> {};

// Inductive step on Types<>: The number of Refs is the number of Refs in the tag S plus the
// number of Refs in the tags T....
template <typename S, typename... T>
struct CountRef<Types<S, T...>>
  : std::integral_constant<size_t, CountRef<S>::value +
                           CountRef<Types<T...>>::value> {};

// Special case: Ref tag.  The number of Refs is one plus the number of Refs in T
template <typename T>
struct CountRef<Ref<T>> :
    std::integral_constant<size_t, 1 + CountRef<T>::value> {};


// An IndexedMatcher is an instance of the passed in Matcher type that is constructed with the
// subset of arguments matching the Indices<> in Idx
template <typename Matcher, typename Idx>
struct IndexedMatcher;

// IndexedMatcher implementation.  Call Matcher's constructor with only the args in idx....
template <typename Matcher, size_t... idx>
struct IndexedMatcher<Matcher, Indices<idx...>> : Matcher {
  template <typename... T>
  IndexedMatcher(T &&... args) :
    Matcher(std::forward<PackGet<idx, T...>>(pack_get<idx>(args...))...) {}
};

// Used to implement matchers with multiple tags at the same level.  This struct generates the
// proper IndexedMatcher for a MultiMatcher whose first tag is Left, and whose other tags are
// Right.  The Matcher is either the left matcher or the right matcher, depending on the
// booleant 'left' argument.
template <bool left, typename Matcher, typename Left, typename... Right>
struct Wrapper_ {
  static constexpr auto left_args = detail::CountRef<Left>::value;
  static constexpr auto right_args = detail::CountRef<Types<Right...>>::value;
  using left_idx = detail::MakeIndices<left_args>;
  using right_idx = detail::MakeIndices<right_args, left_args>;
  using type = IndexedMatcher<Matcher,
                              typename std::conditional<left, left_idx, right_idx>::type>;
};

// User-friendly version of Wrapper_::type
template <bool left, typename Matcher, typename Left, typename... Right>
using Wrapper = typename Wrapper_<left, Matcher, Left, Right...>::type;

// A left wrapper is an IndexedMatcher that matches the Ref arguments for Left
template <typename Matcher, typename Left>
struct LeftWrapper : Wrapper<true, Matcher, Left> {
  using Wrapper<true, Matcher, Left>::Wrapper;
};

// A left wrapper is an IndexedMatcher that matches the Ref arguments for Right
template <typename Matcher, typename Left, typename... Right>
struct RightWrapper : Wrapper<false, Matcher, Left, Right...> {
  using Wrapper<false, Matcher, Left, Right...>::Wrapper;
};

// A MultiMatcher implements a matcher for a list of tags.  Left is the matcher for the first
// tag.  LeftTags is that tag.  Right is the matcher for the rest of the tags.  RightTags are
// those tags.
//
// MultiMatcher exposes a left and right matcher, which generally must be called from the
// derived class with this->left() and this->right().
//
// This class inherits from the left matcher in order to exploit the empty base class
// optimization.  It cannot, sadly, also inherit from the right matcher because that can cause
// ambiguity when referring to base class members.  As such, the right member will always
// consume at least one byte of memory (since C++ requires every class member to be uniquely
// addressable).
template <typename Left, typename LeftTag, typename Right, typename... RightTags>
struct MultiMatcher : private LeftWrapper<Left, LeftTag> {
  using left_t = LeftWrapper<Left, LeftTag>;

  template <typename... T>
  MultiMatcher(T &&... args) :
    left_t(std::forward<T>(args)...),
    right(std::forward<T>(args)...)
  {}

  template <typename... T>
  bool left(T &&... args) const noexcept(noexcept(std::declval<left_t>()(args...))) {
    return left_t::operator()(args...);
  }

  RightWrapper<Right, LeftTag, RightTags...> right;
};

// Matches a list of node tags in an interior_t.  The current node being matched is the idx'th
// child of the interior_t.  Args is the list of tags to be matched.
template <size_t idx, typename... Args>
struct NodeListMatcher;

// Base case: there are no more tags
template <size_t idx>
struct NodeListMatcher<idx> {
  // Succeed if there are no children left
  bool operator()(const interior_t & tn) const noexcept {
    return tn->nChildren() == idx;
  }
};

// Special case matching ArgList as the last tag.  Always true
template <size_t idx>
struct NodeListMatcher<idx, ArgList> {
  constexpr bool operator()(const interior_t &) const noexcept {
    return true;
  }
};

// Special case matching Ref<ArgList> as the last tag
// Note: Ref<Ref<ArgList>> will fail, but is also reasonably nonsensical.
template <size_t idx>
struct NodeListMatcher<idx, Ref<ArgList>> {
  NodeListMatcher(nodelist_t & vec) : v(vec) {}

  // Fill the nodelist_t reference with the remaining child nodes
  bool operator()(const interior_t & tn) const  {
    auto count = tn->nChildren() - idx;
    v.resize(count);
    std::copy_n(tn->children().begin() + idx, count, v.begin());
    return true;
  }

 private:
  nodelist_t & v;
};

// Inductive case: A NodeListMatcher is a MultiMatcher with the a Matcher<> on T, and a
// NodeListMatcher<> on Rest....
template <size_t idx, typename T, typename... Rest>
struct NodeListMatcher<idx, T, Rest...>  :
    MultiMatcher<Matcher<T>, T, NodeListMatcher<idx + 1, Rest...>, Rest...>
{
  using MultiMatcher<Matcher<T>, T, NodeListMatcher<idx + 1, Rest...>, Rest...>::MultiMatcher;

  bool operator()(const interior_t & tn) const {
    return (idx < tn->nChildren()) && this->left(tn->child(idx)) && this->right(tn);
  }
};

} // namespace detail


template <typename Left, typename LeftTag, typename Right, typename... RightTags>
using MultiMatcher = detail::MultiMatcher<Left, LeftTag, Right, RightTags...>;

template <typename... T>
using NodeListMatcher = detail::NodeListMatcher<0, T...>;

} // namespace matcher
} // namespace pharos

#endif  // Pharos_MATCHERIMPL_HPP_

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* c-basic-offset: 2  */
/* End:               */
