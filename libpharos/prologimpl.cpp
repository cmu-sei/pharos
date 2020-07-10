// Copyright 2016-2020 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#include "prologimpl.hpp"

#include <cassert>
#include <sstream>

namespace pharos {
namespace prolog {

std::string FileNotFound::build_msg(const std::string & filename)
{
  std::ostringstream os;
  os << "Unable to load Prolog file: " << filename;
  return os.str();
}

InitError::InitError() : Error("Error during prolog initialization")
{}

namespace detail {

std::shared_ptr<Session> Session::current_session;

Session::Session(const std::string & location)
{
  std::vector<const char *> args = {
    location.c_str(),
    "--quiet=true",
    "--threads=false"
  };
  auto rv = impl::prolog_init(args.size(), const_cast<char **>(args.data()));
  if (!rv) {
    throw InitError();
  }
  impl::init();
}

std::shared_ptr<Session> &
Session::get_session(std::string const & location)
{
  if (current_session) {
    lock_guard lock{current_session->mutex};
    if (current_session.use_count() > 1) {
      throw SessionError(
        "Cannot generate a new Prolog session until current one is destroyed.");
    }
    // Commented out for now, as there are problems automatically reverting user state
    // current_session->revert_state();
    return current_session;
  } else {
    current_session.reset(new Session{location});
    // current_session->save_state();
  }
  return current_session;
}

// save_state() and restore_state() do their best to try to make a single Prolog session
// behave like multiple concurrent sessions.  save_state() keeps track of what predicates exist
// at a point in time.  restore_state() abolishes all predicates that exist that aren't noted
// in the saved state.
//
// (mwd) In practice, it may make more sense to instead keep track of all predicates added
// using add_fact(), and abolish only these.  The potential downside is that it does just
// abolish predicates that were added using add_fact().  Predicates added via other means would
// be untouched.


void Session::save_state()
{
  saved_state.clear();
  std::string func;
  int arity;
  auto qp = query("current_predicate",
                  functor(":", "user", functor("/", var(func), var(arity))));
  for (; !qp->done(); qp->next()) {
    saved_state.emplace(std::move(func), arity);
  }
}

void Session::revert_state()
{
  // Reset all tabled state
  command("abolish_all_tables");

  predspec_t ps;
  std::vector<predspec_t> new_preds;
  auto qp = query("current_predicate",
                  functor(":", "user",
                          functor("/", var(std::get<0>(ps)), var(std::get<1>(ps)))));
  for (; !qp->done(); qp->next()) {
    if (saved_state.find(ps) == std::end(saved_state)) {
      new_preds.emplace_back(std::move(ps));
    }
  }
  for (auto & pred : new_preds) {
    try {
      command("abolish", std::get<0>(pred), std::get<1>(pred));
    } catch (impl::Error const &) {
      // SWIPL will pull system predicates into the user namespace at random points in time.
      // We fail to abolish these.  Don't error out.
    }
  }
}

std::size_t Session::print_predicate(
  std::ostream & stream,
  std::string const & predicate,
  std::size_t arity)
{
  std::size_t n = 0;
  auto q = query(predicate, AnyN{arity});
  for (; !q->done(); q->next()) {
    ++n;
    q->debug_print(stream);
  }
  return n;
}


foreign_t Session::predicate_wrapper(pl_term args_, std::size_t arity_, void *)
{
  auto args = Args{args_, arity_};
  pl_int idx;
  args.get_value<pl_int>(0, idx);
  if (current_session->registry.at(idx)(Args{args_ + 1, arity_ - 1})) {
    return true;
  } else {
    return false;
  }
}

bool Session::register_predicate(
  const std::string & predname,
  std::size_t arity,
  std::function<bool(Args)> func,
  const std::string & modname)
{
  static const char * const result = "Registration result: ";
  bool debug = log && *log;
  if (debug) {
    *log << "Registering C++ predicate: " << modname << ':' << predname << '/' << arity
         << std::endl;
  }
  // Add a Prolog binding for predicate_wrapper if there isn't one already; once per arity
  if (registry_arity.find(arity) == registry_arity.end()) {
    if (impl::register_predicate(wrapper_name, arity + 1, predicate_wrapper,
                                 prolog_default_module))
    {
      registry_arity.emplace(arity);
    } else {
      if (debug) {
        *log << result << "failure" << std::endl;
      }
      return false;
    }
  }

  auto register_command =
    functor("call",
            functor(":", prolog_default_module,
                    functor("register_predicate", modname, predname, arity, registry.size())));
  bool rv = command(register_command);
  if (rv) {
    registry.push_back(func);
  }
  if (debug) {
    *log << result << (rv ? "success" : "failure") << std::endl;
  }
  return rv;
}

} // namespace impl

} // namespace prolog
} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
