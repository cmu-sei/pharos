// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include "config.hpp"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

using YAML::Node;

// Needed in older versions of yaml-cpp.  Will cause an redeclaration error in newer versions.
#if 0
namespace YAML {
template <>
struct convert<Node> {
  static Node encode(const Node& node) { return node; }
  static bool decode(const Node & node, Node & rhs) {
    rhs.reset(node);
    return true;
  }
};
}
#endif

namespace pharos {

#include "config.yaml.ii"

const std::string ConfigNode::empty_string;

ConfigNode
ConfigNode::path_get(
  const std::string &p,
  char               sep)
  const
{
  std::stringstream ss(p);
  std::string item;

  // We jump through hoops here to ensure that c can be a Config or a ConfigNode, and call the
  // correct virtual get()
  const ConfigNode *c = this;
  ConfigNode n;
  while (std::getline(ss, item, sep)) {
    n = (*c)[item];
    c = &n;
  }
  return *c;
}

ConfigNode
ConfigNode::lookup(
  const ConfigNode &value)
  const
{
  if (value.IsDefined() && value.IsScalar() && IsDefined() && IsMap()) {
    ConfigNode v = (*this)[value.Scalar()];
    if (v) {
      return v;
    }
  }
  return value;
}

ConfigNode &
ConfigNode::operator=(
  const ConfigNode &rhs)
{
  if (!rhs) {
    Node::reset(Node(YAML::NodeType::Undefined));
  } else {
    Node::reset(rhs);
  }
  path_ = rhs.path_;
  filemap_.reset(rhs.filemap_);
  return *this;
}

const std::string &
ConfigNode::source() const
{
  if (!IsDefined() || !filemap_) {
    return empty_string;
  }
  const Node &t = *this;
  const Node n = cnode(filemap_)[t];
  if (!n.IsDefined()) {
    return empty_string;
  }
  return n.Scalar();
}

Node
ConfigNode::merge_nodes(
  Node a, Node b)

{
  if (!b.IsMap()) {
    // If b is not a map, merge result is b, unless b is null
    return b.IsNull() ? a : b;
  }
  if (cnode(b)["_replace"]) {
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
      Node t(cnode(b)[key]);
      if (t) {
        c[n.first] = merge_nodes(n.second, t);
        continue;
      }
    }
    c[n.first] = n.second;
  }
  // Add the mappings from 'b' not already in 'c'
  for (Node::iterator::value_type n : b) {
    if (!n.first.IsScalar() || !cnode(c)[n.first.Scalar()]) {
      c[n.first] = n.second;
    }
  }
  return c;
}

void
ConfigNode::Pathlist::path(
  std::ostream &s,
  char          sep)
  const
{
  if (next) {
    s << next->path(sep) << sep;
  }
  s << key;
}

std::string
ConfigNode::Pathlist::path(
  char sep)
  const
{
  std::ostringstream s;
  path(s, sep);
  return s.str();
}

void
ConfigNode::update_map(
  const Node &src,
  const Node &item)
{
  switch (item.Type()) {
   case YAML::NodeType::Map:
    for (Node::const_iterator i = item.begin(); i != item.end(); ++i) {
      update_map(src, i->first);
      update_map(src, i->second);
    }
    break;
   case YAML::NodeType::Sequence:
    for (Node::const_iterator i = item.begin(); i != item.end(); ++i) {
      update_map(src, *i);
    }
    break;
   default:
    break;
  }
  Node n = cnode(filemap_)[item];
  if (!n) {
    filemap_[item] = src;
  }
}

Config
Config::default_config(const std::string &appname) {
  Config cfg(appname);
  std::string config(
    reinterpret_cast<const char *>(&config_yaml),
    config_yaml_len);
  cfg.merge(config, "<default>");
  return cfg;
}

Config &
Config::mergeFile(const std::string &filename, const std::string &name)
{
  boost::filesystem::ifstream file;
  boost::filesystem::path p(filename);
  file.open(p);
  if (!file) {
    throw BadFileError(filename);
  }
  this->merge(file, name.empty() ? filename : name);
  return *this;
}

namespace {
bool
get_file(const char *filename, boost::filesystem::ifstream &stream) {
  assert(filename);
  boost::filesystem::path path(filename);
  if (!boost::filesystem::exists(path)) {
    return false;
  }
  stream.open(path);
  if (!stream) {
    throw BadFileError(filename);
  }
  return true;
}
} // anonymous namespace

Config
Config::load_config(
  const std::string &appname,
  const char *default_location,
  const char *env_override,
  const char *home_config)
{
  boost::filesystem::ifstream file;
  Config cfg = Config::default_config(appname);
  bool env = false;
  if (env_override) {
    char *loc = getenv(env_override);
    if (loc && get_file(loc, file)) {
      cfg.merge(file, std::string(loc));
      env = true;
      file.close();
    }
  }
  if (!env && default_location) {
    if (get_file(default_location, file)) {
        cfg.merge(file, std::string(default_location));
        file.close();
    }
  }
  const char *home = getenv("HOME");
  if (home && home_config) {
    std::string home_str(home);
    home_str.push_back('/');
    home_str.append(home_config);
    if (get_file(home_str.c_str(), file)) {
        cfg.merge(file, home_str);
        file.close();
    }
  }
  return cfg;
}

std::string
ConfigException::build_what(
  const ConfigNode  &node,
  const std::string &msg)
{
  std::stringstream o;
  if (node.IsScalar()) {
    o << msg << ": '" << node.path() << "': '" << node.Scalar()
      << "' from source '" << node.source() << "'";
  } else {
    o << msg << ": '" << node.path() << "' from source '"
      << node.source() << "'";
  }
  return o.str();
}

std::string
BadFileError::build_what(
  const std::string &filename)
{
  std::stringstream o;
  o << "Could not open " << filename;
  return o.str();
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
