// Copyright 2016-2019 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#ifndef Pharos_PROLOG_HPP
#define Pharos_PROLOG_HPP

#include "prologimpl.hpp"
#include "options.hpp"
#include <boost/filesystem.hpp>
#include <Sawyer/Message.h>

namespace pharos {
namespace prolog {

using Path = boost::filesystem::path;

// Represents a prolog functor.  It has a name and a variable number of arguments.
//
// functor(name[, arg0[, arg1[, ...]]])
using detail::functor;

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
using detail::var;

// Represents a prolog "don't care" variable '_' (underscore).
//
// any()
using detail::any;

// Represents a prolog query result.
//
// auto q = session.query(...)
// for (; !query->done; query->next()) {
//   ...
// }
using detail::Query;

// Represents arguments to a registered predicate
using detail::Args;

// Represents an argument to a registered predicate
using detail::Arg;

class Session {
 public:
  Session(const ProgOptVarMap & vm);

  Session(const ProgOptVarMap & vm, const std::string & rule_filename) : Session(vm) {
    consult(rule_filename);
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
  static auto make_fact(T &&... t) {
    return detail::make_fact(std::forward<T>(t)...);
  }

  template <typename... T>
  Query query(T &&... t) {
    return session->query(std::forward<T>(t)...);
  }

  void consult(const std::string & name);

  std::ostream * get_debug_log() const {
    return session->get_debug_log();
  }

  template <typename... T>
  std::ostream * set_debug_log(T &&... t) {
    return session->set_debug_log(std::forward<T>(t)...);
  }

  std::size_t print_predicate(
    std::ostream & stream, const std::string & predicate, std::size_t arity)
  {
    return session->print_predicate(stream, predicate, arity);
  }

  bool register_predicate(const std::string & predname, int arity,
                          std::function<bool(Args)> fn,
                          const std::string & modname = prolog_default_module)
  {
    return session->register_predicate(predname, arity, fn, modname);
  }

  template <typename T>
  bool register_predicate(const std::string & predname, int arity,
                          T & obj, bool (T::*fn)(Args),
                          const std::string & modname = prolog_default_module)
  {
    return session->register_predicate(
      predname, arity, [&obj, fn](Args args) { return (obj.*fn)(args); },
      modname);
  }

 private:
  static bool prolog_log_base(bool newline, Args args);
  static bool prolog_log(Args args) {
    return prolog_log_base(false, args);
  }
  static bool prolog_logln(Args args) {
    return prolog_log_base(true, args);
  }
  std::shared_ptr<impl::Session> session;
};

} // namespace prolog
} // namespace pharos


#endif  // Pharos_PROLOG_HPP

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
