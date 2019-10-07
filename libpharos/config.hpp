// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Config_H
#define Config_H

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop
#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/optional.hpp>

// Default config path separator
#define CONFIG_PATH_SEPERATOR '.'

namespace pharos {
namespace detail {

/// Iterator template for ConfigNode elements.  This needs to be a template in order to handle
/// mutual dependency.  'Base' is included in the template so that Node::iterator or
/// Node::const_iterator can be adapted.  Currently, only the latter is being adapted.
template <typename Node, typename Base>
class ConfigNode_iterator :
  public boost::iterator_adaptor<ConfigNode_iterator<Node, Base>,
                                 Base, std::pair<Node, Node>,
                                 boost::use_default,
                                 std::pair<Node, Node> >
{
  using base_t = boost::iterator_adaptor<ConfigNode_iterator<Node, Base>,
                                         Base,
                                         std::pair<Node, Node>,
                                         boost::use_default,
                                         std::pair<Node, Node> >;
 public:
  ConfigNode_iterator(const ConfigNode_iterator<Node, Base> &i) : base_t(i) {}
  ConfigNode_iterator(const Node &parent, const Base &i) :
    base_t(i), parent_(parent) {}

  // Return the key/value pair, wrapped as ConfigNode objects
  std::pair<Node, Node> dereference() const {
    auto & node = this->base();
    if (parent_.IsSequence()) {
      Node key;
      Node value(*node);
      // the following shiould really have the sequence index as the second argument.
      // Currently that's hard to get.  Save it for a later version of yaml-cpp.
      // value.add_path(parent_, node->first);
      value.filemap_ = parent_.filemap_;
      return std::make_pair(key, value);
    } else {
      Node key(node->first);
      Node value(node->second);
      value.add_path(parent_, node->first);
      key.filemap_ = parent_.filemap_;
      value.filemap_ = parent_.filemap_;
      return std::make_pair(key, value);
    }
  }

 private:
  Node parent_;
};

} // namespace detail


/// An exception representing an invalid node value
class BadFileError : public std::runtime_error {
 public:
  BadFileError() : std::runtime_error("Cannot open file") {}
  BadFileError(const std::string &filename) : std::runtime_error(build_what(filename)) {}
 private:
  static std::string build_what(const std::string &filename);
};

class ConfigNode;

/// Exceptions from the ConfigNode module that can output information about a failed node's
/// path and source
class ConfigException : public std::runtime_error {
 public:
  ConfigException(const ConfigNode &node, const std::string & msg)
    : std::runtime_error(build_what(node, msg)) {}
 private:
  static std::string build_what(const ConfigNode &node, const std::string & msg);
};

/// An exception representing an invalid node value
class BadNodeError : public ConfigException {
 public:
  BadNodeError(const ConfigNode &node, const std::string &msg)
    : ConfigException(node, msg) {}
};

class ConfigNode : public YAML::Node {
 public:
  /// Define the iterator type, which will iterate over std::pair<ConfigNode,ConfigNode>
  /// elements
  using iterator = detail::ConfigNode_iterator<ConfigNode, Node::const_iterator>;

  /// Create an empty config
  ConfigNode() : filemap_(YAML::NodeType::Map) {}

  /// Copy constructor
  ConfigNode(ConfigNode const &) = default;

  /// Look up the value of the current ConfigNode's 'key' attribute.  If there is no attribute
  /// for 'key', a ConfigNode that is undefined (!IsDefined()) will be returned.  If a
  /// ConfigNode has no key named 'A', a construction of cfg["A"]["B"] will still work, and
  /// will return a ConfigNode that is undefined, and has a path of just "A".
  template <typename Key>
  ConfigNode operator[](const Key& key) const {
    ConfigNode c;
    if (IsScalar()) {
      c = new_node(YAML::Node());
    } else if (IsDefined()) {
      c = new_node(cnode(*this)[key]);
    } else {
      c = new_node(*this);
    }
    c.add_path(*this, key);
    return c;
  }

  /// Look up the given path in the ConfigNode.  If the seperator is '.', cfg.path_get("A.B.C")
  /// is equivalent to cfg["A"]["B"]["C"].
  virtual ConfigNode path_get(const std::string &path,
                              char sep = CONFIG_PATH_SEPERATOR) const;

  /// If 'value' is a scalar, this is a map, and the map contains the value, return the value
  /// in the map.  Otherwise, return 'value'.
  ConfigNode lookup(const ConfigNode &value) const;

  /// Replace this ConfigNode with the contents of 'rhs'
  ConfigNode& operator=(const ConfigNode& rhs);

  /// Return the value of this node as the given type.  If the conversion fails, the value will
  /// be boost::none.
  template <typename T>
  boost::optional<T> as() const {
    try {
      return Node::as<T>();
    } catch (const YAML::BadConversion &) {
      return boost::none;
    }
  }

  /// Return the value of this node as the given type.  Throw a BadNodeError exception if the
  /// conversion fails.
  template <typename T>
  const T expect(const char *msg = "Illegal conversion") const {
    try {
      return Node::as<T>();
    } catch (const YAML::BadConversion &) {
      throw BadNodeError(*this, msg);
    }
  }

  /// Return the value of this node as the given type.  Throw a BadNodeError exception if the
  /// conversion fails.
  template <typename T>
  const T expect(const std::string &msg) const {
    return as<T>(msg.c_str());
  }

  /// Return the value of this node as the given type.  Return 'fallback' if the conversion
  /// fails.
  template <typename T, typename S>
  const T as_fallback(const S& fallback) const {
      return Node::as<T, S>(fallback);
  }

  /// Return the path to this ConfigNode.  If this ConfigNode was returned by
  /// baseconfig["A"]["B"], where baseconfig was generated by ConfigNode() or
  /// ConfigNode::default_config(), the path to this config would be "A.B".
  std::string path(char sep = CONFIG_PATH_SEPERATOR) const {
    return path_->path(sep);
  }

  /// Return the source of this ConfigNode.  The source of a ConfigNode is the name that was
  /// passed to merge() or mergeFile().
  const std::string &source() const;

  /// Return an iterator over the node.  For maps and sequences this iterator will return
  /// values of the type std::pair<ConfigNode, ConfigNode>, where the first ConfigNode is the
  /// key, and the second is the value.  For sequences, the keys are integers, beginning with
  /// zero.
  iterator begin() const {
    return iterator(*this, Node::begin());
  }

  /// Return an end iterator
  iterator end() const {
    return iterator(*this, Node::end());
  }

  // Return as YAML::Node
  Node as_node() const {
    return *this;
  }

 protected:
  /// Construct an empty ConfigNode from a Node
  ConfigNode(const Node &o) : Node(o) {}

  // Our iterators need access to our private members
  friend class detail::ConfigNode_iterator<ConfigNode, Node::const_iterator>;

  // Stream operator needs access to our private base class
  friend std::ostream &operator<<(std::ostream &, const ConfigNode &);

  // An empty string that can be used as a default parameter
  static const std::string empty_string;

  /// Create a ConfigNode from a node with the same filemap as this one
  ConfigNode new_node(const Node &n) const {
    ConfigNode node(n);
    node.filemap_ = filemap_;
    return node;
  }

  /// Maintains a linked list of key values that led to this config
  struct Pathlist {
    std::string key;
    std::shared_ptr<const Pathlist> next;
    void path(std::ostream& s, char sep) const;
    std::string path(char sep) const;
  };
  std::shared_ptr<Pathlist> path_;

  /// Merge node 'b' into node 'a', returning 'a'.
  static
  Node merge_nodes(Node a, Node b);

  Node merge_nodes(Node a) {
    return merge_nodes(*this, a);
  }

  /// Return a constant reference to n (used to guarantee calling operator[] const even on
  /// non-const nodes)
  static
  const Node &cnode(const Node &n) {
    return n;
  }

  /// Add an element to this ConfigNode's path
  template<typename Key>
  void add_path(const ConfigNode &base, const Key &key) {
    if (!path_) {
      path_.reset(new Pathlist());
    }
    path_->next = base.path_;
    std::ostringstream s;
    s << key;
    path_->key = s.str();
  }

  /// A map of nodes to source identifiers
  Node filemap_;

  /// Update the filemap_ from node 'item', adding all elements from 'item' not currently in
  /// filemap_ with the value 'src'.
  void update_map(const Node &src, const Node &item);

  /// Update the filemap_ from node 'item', adding all elements from 'item' not currently in
  /// filemap_ with the value 'src'.
  void update_map(const std::string &src, const Node &item) {
    update_map(Node(src), item);
  }
};

inline std::ostream &operator<<(std::ostream &stream, const ConfigNode &conf) {
  return stream << static_cast<const YAML::Node &>(conf);
}

class Config : public ConfigNode {
 public:
  /// Default constructor
  Config() {}

  /// Primary constructor
  Config(const std::string &_appname) : appname(_appname) {}

  /// Create a config with pharos's default values
  static Config default_config(const std::string &appname);

  /// Load a config starting with default_config, merging from file at default_location,
  /// overriden by a file name in the env_override environment variable, followed by the file
  /// named home_config in the $HOME directory.  Any of these arguments are nullable.
  static Config load_config(
    const std::string &appname,
    const char *default_location,
    const char *env_override,
    const char *home_config);

  Config
  include(const ConfigNode &config,
          const std::string &name = empty_string) const
  {
    YAML::Node m = merge_nodes(*this, config);
    Config r = new_node(m);
    r.update_map(name, r);
    return r;
  }

  /// Return a Config representing the merged state of this Config and he YAML representation
  /// identified by source with a given name.  Source may be a std::string, a const char *, or
  /// a std::istream &.  In all three cases, the contents are the YAML representation, not the
  /// name of a file.
  template <typename Source>
  Config
  include(Source &src, const std::string &name = empty_string) const {
    YAML::Node n = YAML::Load(src);
    YAML::Node m = merge_nodes(*this, n);
    Config r = new_node(m);
    r.update_map(name, r);
    return r;
  }

  /// Return a Config representing the merged state of this Config and a YAML representation
  /// read from the given filename.  If 'name' is left empty, 'filename' will be used as the
  /// source's name.
  Config
  include(const std::string &filename,
          const std::string &name = empty_string) const
  {
    std::ifstream s(filename.c_str());
    if (!s) {
      throw BadFileError(filename);
    }
    return include<std::ifstream&>(s, name.empty() ? filename : name);
  }

  /// Change this Config to represent the merged state of this Config and he YAML
  /// representation identified by source with a given name.  Source may be a std::string, a
  /// const char *, or a std::istream &.  In all three cases, the contents are the YAML
  /// representation, not the name of a file.
  template <typename Source>
  Config &
  merge(Source &src, const std::string &name = empty_string) {
    *static_cast<ConfigNode *>(this) = include(src, name);
    return *this;
  }

  /// Change this Config to represent the merged state of this Config and a YAML representation
  /// read from the given filename.  If 'name' is left empty, 'filename' will be used as the
  /// source's name.
  Config &
  mergeFile(const std::string &filename,
            const std::string &name = empty_string);

  /// Look up the value of the current ConfigNode's 'key' attribute.  The attribute will first
  /// be looked up in the "application.<appname>" path.  Otherwise it will be looked for from
  /// the root of the config.  If there is no attribute for 'key', a ConfigNode that is
  /// undefined (!IsDefined()) will be returned.  If a ConfigNode has no key named 'A', a
  /// construction of cfg["A"]["B"] will still work, and will return a ConfigNode that is
  /// undefined, and has a path of just "A".
  template <typename Key>
  ConfigNode operator[](const Key& key) const {
    ConfigNode appnode = (*static_cast<const ConfigNode *>(const_cast<const Config *>(this)))
                         ["application"][appname];
    if (appnode) {
      ConfigNode val = appnode[key];
      if (val) {
        return val;
      }
    }
    return ConfigNode::operator[](key);
  }

  /// Look up the given path in the ConfigNode.  If the seperator is '.', cfg.path_get("A.B.C")
  /// is equivalent to cfg["A"]["B"]["C"].
  virtual ConfigNode path_get(const std::string &p,
                              char sep = CONFIG_PATH_SEPERATOR) const
  {
    ConfigNode appnode = (*static_cast<const ConfigNode *>(const_cast<const Config *>(this)))
                         ["application"][appname];
    if (appnode) {
      ConfigNode val = appnode.path_get(p, sep);
      if (val) {
        return val;
      }
    }
    return ConfigNode::path_get(p, sep);
  }

 private:
  /// Construct an empty Config from a Node
  Config(const YAML::Node &o) : ConfigNode(o) {}

  /// Create a ConfigNode from a node with the same filemap as this one
  ConfigNode
  new_node(const YAML::Node &n) const {
    Config node(n);
    node.filemap_ = filemap_;
    return node;
  }

  std::string appname;
};

} // namespace pharos

#endif // Config_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
