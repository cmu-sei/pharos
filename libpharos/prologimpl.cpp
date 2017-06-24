// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.

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

std::string term_type(impl::xsb_term pt) {
  using namespace impl::xsb::impl;
  if (is_string(pt)) {
    return "string";
  }
  if (is_int(pt)) {
    return "integer";
  }
  if (is_functor(pt)) {
    std::ostringstream os;
    os << "functor/" << p2c_arity(pt);
    return  os.str();
  }
  if (is_list(pt)) {
    return "list";
  }
  if (is_nil(pt)) {
    return "nil";
  }
  if (is_float(pt)) {
    return "float";
  }
  if (is_var(pt)) {
    return "variable";
  }
  if (is_attv(pt)) {
    return "attributed";
  }
  return "unknown";
}

std::string TypeMismatch::build_msg(xsb_term pt, const std::string & expected)
{
  std::ostringstream os;
  os << errmsg << ": expected " << expected << ", got " << term_type(pt);
  return os.str();
}

namespace impl {
namespace xsb {
namespace {
// static convenience functions for xsb interaction

std::string generate_error_string()
{
  std::ostringstream os;
  os << "XSB Error: " << impl::xsb_get_error_type()
     << '/' << impl::xsb_get_error_message();
  return os.str();
}

std::string generate_init_error_string()
{
  std::ostringstream os;
  os << "XSB Initialization Error: " << impl::xsb_get_init_error_type()
     << '/' << impl::xsb_get_init_error_message();
  return os.str();
}

} // unnamed namespace

XSBError::XSBError() : Error(generate_error_string())
{}

InitError::InitError() : XSBError(generate_init_error_string())
{}

std::shared_ptr<Session> Session::current_session;

Session::Session(const std::string & location)
{
  std::vector<const char *> args = {
    location.c_str(),
    "--nobanner",
    "--quietload",
    "--nofeedback"
  };
  auto rv = impl::xsb_init(args.size(), args.data());
  if (rv == status::ERROR) {
    throw InitError();
  }
  assert(rv == status::SUCCESS);
}

void Session::close_query()
{
  auto q = current_query.lock();
  if (q) {
    q->terminate();
  }
}

Session::~Session()
{
  lock_guard lock(mutex);
  close_query();
  impl::xsb_close();
}

std::shared_ptr<Session> & Session::get_session(const std::string & location)
{
  if (current_session) {
    lock_guard lock(current_session->mutex);
    if (current_session.use_count() > 1) {
      throw SessionError("Cannot generate a new XSB session until current one is destroyed.");
    }
    current_session->revert_state();
    return current_session;
  } else {
    current_session.reset(new Session(location));
    current_session->save_state();
  }
  return current_session;
}


// save_state() and restore_state() do their best to try to make a single XSB prolog session
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
  saved_modules.clear();
  std::string func;
  int arity;
  auto qp = query("current_functor",
                  functor(":", "usermod", functor("/", var(func), var(arity))));
  for (; !qp->done(); qp->next()) {
    saved_state.emplace(std::move(func), arity);
  }
  std::string module;
  auto qm = query("current_module", var(module));
  for (; !qm->done(); qm->next()) {
    saved_modules.emplace(std::move(module));
  }
}

void Session::revert_state()
{
  close_query();

  // Reset all tabled state
  command("abolish_all_tables");

  predspec_t ps;
  std::vector<predspec_t> new_preds;
  auto qp = query("current_predicate",
                  functor(":", "usermod",
                          functor("/", var(std::get<0>(ps)), var(std::get<1>(ps)))));
  for (; !qp->done(); qp->next()) {
    if (saved_state.find(ps) == std::end(saved_state)) {
      new_preds.emplace_back(std::move(ps));
    }
  }
  for (auto & pred : new_preds) {
    command("abolish", std::get<0>(pred), std::get<1>(pred));
  }

#if 0
  std::string module;
  std::vector<std::string> new_modules;
  auto qm = query("current_module", var(module));
  for (; !qm->done(); qm->next()) {
    if (saved_modules.find(module) == std::end(saved_modules)) {
      new_modules.emplace_back(std::move(module));
    }
  }

  for (auto & m : new_modules) {
    auto q = query("current_predicate",
                   functor(":", m,
                           functor("/", var(std::get<0>(ps)), var(std::get<1>(ps)))));
    for (; !q->done(); q->next()) {
      command("abolish", functor(":", m,
                                 functor("/", std::get<0>(ps), std::get<1>(ps))));
    }
  }
#endif
}

bool Session::run_command(const char *cmd)
{
  static const char * const result = "Prolog command result: ";
  bool debug = log && *log;
  if (debug) {
    *log << "Prolog command: ";
    if (cmd) {
      *log << cmd;
    } else {
      term_to_stream(*log, impl::reg_term(1));
    }
    *log << std::endl;
  }
  auto rv = cmd ? impl::xsb_command_string(cmd) : impl::xsb_command();
  switch (rv) {
   case status::SUCCESS:
    if (debug) {
      *log << result << "success" << std::endl;
    }
    return true;
   case status::FAILURE:
    if (debug) {
      *log << result << "failure" << std::endl;
    }
    return false;
   case status::ERROR:
    if (debug) {
      *log << result << "error" << std::endl;
    }
    throw XSBError();
   default:
    abort();
  }
}

bool Session::register_predicate(
  const std::string & predname, int arity, int (*cfun)(), const std::string & modname)
{
  static const char * const result = "Registration result: ";
  bool debug = log && *log;
  if (debug) {
    *log << "Registering C predicate: " << modname << ':' << predname << '/' << arity
         << std::endl;
  }
  auto rv = impl::xsb_add_c_predicate(predname, arity, cfun, modname);
  switch (rv) {
   case status::SUCCESS:
    if (debug) {
      *log << result << "success" << std::endl;
    }
    return true;
   case status::FAILURE:
    if (debug) {
      *log << result << "failure" << std::endl;
    }
    return false;
   case status::ERROR:
    if (debug) {
      *log << result << "error" << std::endl;
    }
    throw XSBError();
   default:
    abort();
  }
}

int Session::predicate_wrapper()
{
  auto idx = arg<std::size_t>(0);
  return current_session->registry.at(idx)();
}

bool Session::register_cxx_predicate(
  const std::string & predname,
  int arity,
  std::function<int()> func,
  const std::string & modname)
{
  static const char * const result = "Registration result: ";
  bool debug = log && *log;
  if (debug) {
    *log << "Registering C++ predicate: " << modname << ':' << predname << '/' << arity
         << std::endl;
  }
  // Add a Prolog binding for predicate_wrapper if there isn't one already; once per arity
  if (0 == registry_arity.count(arity)) {
    if (register_predicate(wrapper_name, arity + 1, predicate_wrapper, prolog_default_module))
    {
      registry_arity.emplace(arity);
    } else {
      if (debug) {
        *log << result << "failure" << std::endl;
      }
      return false;
    }
  }

  // Build the command:
  // assert((modname:predname(A1, A2, ...) :- pharos:registry_wrapper(<idx>, A1, A2, ...)))."
  auto idx = registry.size();
  auto pt = impl::reg_term(1);
  // assert(...)
  impl::c2p_functor("assert", 1, pt);
  pt = impl::p2p_arg(pt, 1);
  // ... :- ...
  impl::c2p_functor(":-", 2, pt);
  auto lhs = impl::p2p_arg(pt, 1);
  auto rhs = impl::p2p_arg(pt, 2);
  // modname:predname(...)
  impl::c2p_functor(modname.c_str(), predname.c_str(), arity, lhs);
  // pharos:registry_wrapper(...)
  impl::c2p_functor(prolog_default_module, wrapper_name, arity + 1, rhs);
  // pharos:registry_wrapper(<idx>, ...)
  impl::c2p_int(idx, impl::p2p_arg(rhs, 1));
  // unify A1 to A1, A2 to A2, etc.
  for (int i = 0; i < arity; ++i) {
    bool check = impl::p2p_unify(impl::p2p_arg(lhs, i + 1), impl::p2p_arg(rhs, i + 2));
    assert(check);
  }
  bool rv = run_command();
  if (rv) {
    registry.push_back(func);
  }
  if (debug) {
    *log << result << (rv ? "success" : "failure") << std::endl;
  }
  return rv;
}

bool Query::next()
{
  auto log = session->get_debug_log();
  bool debug = log && *log;
  switch (impl::xsb_next()) {
   case status::SUCCESS:
    if (debug) {
      *log << "Prolog query result: ";
      debug_print(*log);
    }
    break;
   case status::FAILURE:
    if (debug) {
      *log << "Prolog query end of results" << std::endl;
    }
    finished = true;
    return false;
   case status::OXFLOW:
    if (debug) {
      *log << "Prolog query overflow" << std::endl;
    }
    throw OverflowError();
   case status::ERROR:
    if (debug) {
      *log << "Prolog query error" << std::endl;
    }
    throw XSBError();
   default:
    abort();
  }
  apply_setters();
  return done();
}

void Query::call_query()
{
  auto log = session->get_debug_log();
  bool debug = log && *log;
  static const char * const result = "Prolog query ";
  if (debug) {
    *log << "Prolog query: ";
    debug_print(*log);
  }
  switch (impl::xsb_query()) {
   case status::SUCCESS:
    if (debug) {
      *log << result << "succeeded" << std::endl;
      *log << "Prolog query result: ";
      debug_print(*log);
    }
    apply_setters();
    break;
   case status::FAILURE:
    if (debug) {
      *log << result << "failed" << std::endl;
    }
    finished = true;
    break;
   case status::ERROR:
    if (debug) {
      *log << result << "errored" << std::endl;
    }
    throw XSBError();
   default:
    abort();
  }
}

} // namespace xsb
} // namespace impl
} // namespace prolog
} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
