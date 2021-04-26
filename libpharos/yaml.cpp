// Copyright 2021 Carnegie Mellon University.  See LICENSE file for terms.

#include "yaml.hpp"

using YAML::Node;

namespace pharos {

Node merge_nodes(Node a, Node b)
{
  if (!b.IsMap()) {
    // If b is not a map, merge result is b, unless b is null
    return b.IsNull() ? a : b;
  }
  if (const_node(b)["_replace"]) {
    Node c(YAML::NodeType::Map);
    for (Node::iterator::value_type n : b) {
      if (n.first.IsScalar() && n.first.Scalar() == "_replace") {
        continue;
      }
      c[n.first] = n.second;
    }
    return c;
  }
  if (!a.IsMap()) {
    // If a is not a map, merge result is b
    return b;
  }
  if (!b.size()) {
    // If a is a map, and b is an empty map, return a
    return a;
  }
  // Create a new map 'c' with the same mappings as a, merged with b
  Node c(YAML::NodeType::Map);
  for (Node::iterator::value_type n : a) {
    if (n.first.IsScalar()) {
      const std::string & key = n.first.Scalar();
      Node t(const_node(b)[key]);
      if (t) {
        c[n.first] = merge_nodes(n.second, t);
        continue;
      }
    }
    c[n.first] = n.second;
  }
  // Add the mappings from 'b' not already in 'c'
  for (Node::iterator::value_type n : b) {
    if (!n.first.IsScalar() || !const_node(c)[n.first.Scalar()]) {
      c[n.first] = n.second;
    }
  }
  return c;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
