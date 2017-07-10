// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#ifndef Pharos_MATCHERTAGS_HPP_
#define Pharos_MATCHERTAGS_HPP_

// This file contains base tag and tag/type manipulation definitions for use by matcher.hpp.

// The intent is for types in the detail namespace not to be available to the user, but are
// used in the

#include <type_traits>

namespace pharos {
namespace matcher {
namespace detail {

// A holder for types of any type
template <typename... T>
struct Types {
  Types() = delete;
  using types = Types<T...>;
};

// Base class for Tags, so std::is_base_of() can be used.
struct TagBase {
  TagBase() = delete;
};


// Boolean template: is T a Tag?
template <typename T>
using IsTag = std::is_base_of<detail::TagBase, T>;

// AreTags<T...> Are the list of types T... all tags?
// Base case: true (will be used when T is empty)
template <typename... T>
struct AreTags : std::true_type {};

// Inductive step: false if S is not a tag, otherwise test T...
template <typename S, typename... T>
struct AreTags<S, T...> :
    std::conditional<IsTag<S>::value, AreTags<T...>, std::false_type>::type {};

// Allow AreTags to be called with a Types<> argument.  In this case, test if all the types in
// Types<> are tags.
template <typename... T>
struct AreTags<Types<T...>> : AreTags<T...> {};


// A type holder for capture (reference) types
template <typename... T>
struct Captures {
  Captures() = delete;
  using types = Types<T...>;
};

// A type holder for a Tag's sub-tags
template <typename... T>
struct SubTags {
  SubTags() = delete;
  using types = Types<T...>;
};

// Base of match tag types.  This type holds the following information:
//
// A) subtags, which is a list of tags that this tag has as arguments.  This is used by
//    detail::CountRef.
// B) captures, which is a list of valid capture types for this node.  This is used by the
//    Matcher<Ref<T>> implementation.
//
// A Tag can have an optional Captures<> argument, and an optional Subtags<> argument.
template <typename... T>
struct Tag;

// The base case: store the Captures and SubTags
template <typename... RefTypes, typename... SubT>
struct Tag<Captures<RefTypes...>, SubTags<SubT...>> : detail::TagBase {

  static_assert(detail::AreTags<SubT...>::value,
                "There is a SubTag that does not inherit from TypedTag");

  using subtags = Types<SubT...>;
  using captures = Captures<RefTypes...>;
};

// Allow Captures and SubTags to appear in a different order
template <typename... RefTypes, typename... SubT>
struct Tag<SubTags<SubT...>, Captures<RefTypes...>> :
    Tag<Captures<RefTypes...>, SubTags<SubT...>> {};

// Allow only a Captures<> argument
template <typename... RefTypes>
struct Tag<Captures<RefTypes...>> : Tag<Captures<RefTypes...>, SubTags<>> {};

// Allow only a SubTags<> argument
template <typename... SubT>
struct Tag<SubTags<SubT...>> : Tag<Captures<>, SubTags<SubT...>> {};

// Allow a tag with no captures or subtags
template <>
struct Tag<> : Tag<Captures<>, SubTags<>> {};

// Returns the captures of a tag
template <typename T>
using CapturesOf = typename T::captures;

// Returns the captures of a tag, wrapped in Types<> instead of Captures<>
template <typename T>
using CapturedTypes = typename CapturesOf<T>::types;

// Determine if type S is one of the types in Rest.  If Rest is Types<...>, then it will
// determine if S is one of the types in Types<...>.  This will be either std::true_type or
// std::false_type.
template <typename S, typename... Rest>
struct HasType;

// Base case: false
template <typename S>
struct HasType<S> : std::false_type {};

// Inductive step:  true if S is same as T, recurse on Rest otherwise
template <typename S, typename T, typename... Rest>
struct HasType<S, T, Rest...> :
    std::conditional<std::is_same<S, T>::value,
                     std::true_type,
                     HasType<S, Rest...>>::type {};

// Allow a Types<> argument instead of template parameter pack
template <typename S, typename... Rest>
struct HasType<S, Types<Rest...>> : HasType<S, Rest...> {};

// TypesInCommon_ determines what types are in common between A and B (with accumulator Acc)
template <typename A, typename B, typename Acc = Types<>>
struct TypesInCommon_;

// Base case: If A has no types, there are no types left in common.  Return the accumulator.
template <typename B, typename Acc>
struct TypesInCommon_<Types<>, B, Acc> {
  using type = Acc;
};

// Inductive step: If A has types, see if the first type in A is in B.  If so, add it to the
// accumulator and recurse.  Otherwise, just recurse.
template <typename T, typename... A, typename B, typename... Acc>
struct TypesInCommon_<Types<T, A...>, B, Types<Acc...>> {
  using type = typename TypesInCommon_<
    Types<A...>, B, typename std::conditional<HasType<T, B>::value,
                                              Types<Acc..., T>,
                                              Types<Acc...>>::type>::type;
};

// TypesInCommonN_ determines what types are in common between the Types<> argments to
// TypesInCommonN_.
template <typename... T>
struct TypesInCommonN_;

// The user-friendly version of TypesInCommonN_ (doesn't require ::type)
template <typename... T>
using TypesInCommon = typename TypesInCommonN_<T...>::type;

// Base case: if only one set of types is left, return it
template <typename... T>
struct TypesInCommonN_<Types<T...>> {
  using type = Types<T...>;
};

// Inductive case: Using the types in common between A and B, recurse on T.
template <typename A, typename B, typename... T>
struct TypesInCommonN_<A, B, T...> {
  using type = TypesInCommon<typename TypesInCommon_<A, B>::type, T...>;
};

// Accumulate the Capture arguments of the tags T, storing them as Types<> arguments in the
// accumulator Acc
template <typename Acc, typename... T>
struct CommonCaptures_;

// Base case: No more tags.  Calculate the types in common between the Types<> arguments in the
// accumulator, wrap them up in a Captures<> and store that in type
template <typename... Acc>
struct CommonCaptures_<Types<Acc...>> {
  // Get the types in common
  using common = TypesInCommon<Acc...>;

  // Convert a Types<T...> to a Captures<T...>
  template <typename T> struct ToCaptures;
  template <typename... T> struct ToCaptures<Types<T...>> {
    using type = Captures<T...>;
  };

  // Store the Captures in common
  using type = typename ToCaptures<common>::type;
};

// Inductive step: Accumulate the captures types of S, and recurse
template <typename... Acc, typename S, typename... T>
struct CommonCaptures_<Types<Acc...>, S, T...> :
    CommonCaptures_<Types<Acc..., CapturedTypes<S>>, T...> {};

} // namespace detail


template <typename T>
using IsTag = detail::IsTag<T>;

template <typename... T>
using Captures = detail::Captures<T...>;

template <typename... T>
using SubTags = detail::SubTags<T...>;

template <typename... T>
using Tag = detail::Tag<T...>;

template <typename T>
using CapturesOf = detail::CapturesOf<T>;

// Returns true if the type T is a valid capture type for the tag Tg
template <typename T, typename Tg>
using CaptureValidFor = detail::HasType<T, typename CapturesOf<Tg>::types>;

// Returns the capture types in common between the given set of tags
template <typename... T>
using CommonCaptures = typename detail::CommonCaptures_<detail::Types<>, T...>::type;

} // namespace matcher
} // namespace pharos

#endif // Pharos_MATCHERTAGS_HPP_

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* c-basic-offset: 2  */
/* End:               */
