// Copyright 2016, 2017 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#ifndef Pharos_PROLOG_HPP
#define Pharos_PROLOG_HPP

#include "prologimpl.hpp"
#include "descriptors.hpp"
#include <boost/filesystem.hpp>
#include <Sawyer/Message.h>

namespace pharos {
namespace prolog {

using Path = boost::filesystem::path;

using impl::Functor;

// Represents a prolog functor.  It has a name and a variable number of arguments.
//
// functor(name[, arg0[, arg1[, ...]]])
using impl::functor;

// Represents a prolog list.  It has a variable number of arguments, and more arguments can be
// pushed onto the back.
//
// auto x = list([arg0[, arg1[, ...]]])
// x.push_back(arg)
// list(std::vector<T>)
using impl::list;

// Represents a prolog variable in a query.  The argument is a reference to a variable that
// will be filled by the query.
//
// var(arg)
using impl::var;

// Represents a prolog "don't care" variable '_' (underscore).
//
// any()
using impl::any;

// Represents a prolog query result.
//
// auto q = session.query(...)
// for (; !query->done; query->next()) {
//   ...
// }
using impl::Query;

class Session {
 public:
  Session() : Session(nullptr)
  {}

  Session(const ProgOptVarMap & vm);

  Session(const std::string & rule_filename) :
    Session(global_descriptor_set->get_arguments(), rule_filename)
  {}

  Session(const ProgOptVarMap & vm, const std::string & rule_filename) : Session(vm) {
    if (!consult(rule_filename)) {
      throw Error("Could not load rules");
    }
  }

  template <typename... T>
  bool command(T &&... t) {
    return session->command(std::forward<T>(t)...);
  }

  template <typename... T>
  bool add_fact(T &&... t) {
    bool rv = session->add_fact(std::forward<T>(t)...);
    if (!rv) {
      std::cerr << "Prolog could not assert fact!" << std::endl;
    }
    return rv;
  }

  template <typename... T>
  std::shared_ptr<Query> query(T &&... t) {
    return session->query(std::forward<T>(t)...);
  }

  bool consult(const std::string & name);

  const Path & get_default_rule_dir() const {
    return default_rule_dir;
  }

  std::ostream * get_debug_log() const {
    return session->get_debug_log();
  }

  template <typename... T>
  std::ostream * set_debug_log(T &&... t) {
    return session->set_debug_log(std::forward<T>(t)...);
  }

  template <typename Stream>
  std::size_t print_predicate(
    Stream & stream, const std::string & predicate, std::size_t arity)
  {
    return session->print_predicate(stream, predicate, arity);
  }

  bool register_predicate(const std::string & predname, int arity, int (*cfun)(),
                          const std::string & modname = prolog_default_module)
  {
    return session->register_predicate(predname, arity, cfun, modname);
  }

  bool register_cxx_predicate(const std::string & predname, int arity,
                              std::function<int()> func,
                              const std::string & modname = prolog_default_module)
  {
    return session->register_cxx_predicate(predname, arity, func, modname);
  }

 private:
  static int prolog_log_base(bool newline);
  static int prolog_log() {
    return prolog_log_base(false);
  }
  static int prolog_logln() {
    return prolog_log_base(true);
  }
  std::shared_ptr<impl::Session> session;
  Path default_rule_dir;
};

} // namespace prolog
} // namespace pharos


#endif  // Pharos_PROLOG_HPP

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
