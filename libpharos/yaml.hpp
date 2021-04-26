// Copyright 2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Yaml_H
#define Yaml_H

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop

namespace pharos {

YAML::Node merge_nodes(YAML::Node a, YAML::Node b);

inline const YAML::Node & const_node(const YAML::Node & n) { return n; }

}


#endif  // Yaml_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
