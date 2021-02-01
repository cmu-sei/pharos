// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#include "swiimpl.hpp"

namespace pharos {
namespace prolog {

std::string TypeMismatch::build_msg(impl::pl_term pt, const std::string & expected)
{
  std::ostringstream os;
  os << "Type from prolog was not of expected type: expected " << expected
     << ", got " << impl::term_type(pt);
  return os.str();
}

namespace impl {

std::string term_type(pl_term pt)
{
  using namespace std::string_literals;
  switch (PL_term_type(pt)) {
   case PL_VARIABLE:
    return "variable"s;
   case PL_ATOM:
    return "atom"s;
   case PL_NIL:
    return "nil"s;
   case PL_BLOB:
    return "blob"s;
   case PL_STRING:
    return "string"s;
   case PL_INTEGER:
    return "integer"s;
   case PL_RATIONAL:
    return "rational"s;
   case PL_FLOAT:
    return "float"s;
   case PL_LIST_PAIR:
    return "list"s;
   case PL_TERM:
    {
      atom_t a;
      std::size_t s;
      if (PL_get_compound_name_arity_sz(pt, &a, &s)) {
        return "functor/"s + std::to_string(s);
      }
      return "functor"s;
    }
   case PL_DICT:
    return "dict"s;
   default:
    return "unknown"s;
  }
}

std::stack<std::pair<qid_t, std::weak_ptr<Query>>> Query::query_stack;
std::recursive_mutex Query::mutex;

std::ostream & Query::debug_print(std::ostream & stream) const
{
  if (!done()) {
    atom_t atom;
    std::size_t arity;
    PL_predicate_info(pred, &atom, &arity, nullptr);
    auto functor = PL_new_functor(atom, arity);
    auto fid = Frame{};
    pl_term term = PL_new_term_ref();
    wrap_error(PL_cons_functor_v(term, functor, args));
    term_to_stream(stream, term);
    stream << ".\n";
  }
  return stream;
}

void Query::next()
{
  lock_guard guard{mutex};
  if (finished) {
    return;
  }
  if (!query_handle) {
    _destroy();
    return;
  }
  _destroy_subqueries();
  switch (PL_next_solution(query_handle)) {
   case PL_S_TRUE:
    fill_references();
    return;
   case PL_S_LAST:
    fill_references();
    _close();
    return;
   case PL_S_EXCEPTION:
    throw Error{query_handle};
   case PL_S_FALSE:
    _destroy();
    return;
  }
}

void Query::_destroy_subqueries()
{
  while (std::get<qid_t>(query_stack.top()) != query_handle) {
    auto top = std::get<std::weak_ptr<Query>>(query_stack.top()).lock();
    if (top) {
      top->_destroy();
    }
  }
}

void Query::_close()
{
  if (!query_handle) {
    return;
  }
  _destroy_subqueries();
  bool good = PL_cut_query(query_handle);
  query_handle = 0;
  query_stack.pop();
  if (!good) {
    PL_close_foreign_frame(frame);
    finished = true;
    throw Error{};
  }
}

void Query::_destroy()
{
  _close();
  if (!finished) {
    PL_close_foreign_frame(frame);
    finished = true;
  }
}

void Query::init_frame(char const *name, std::size_t num_args, std::size_t num_vars)
{
  // Obtain a predicate from the functor name and number of arguments
  pred = PL_predicate(name, num_args, nullptr);
  // Hold onto the following variables until the query is over
  frame = PL_open_foreign_frame();
  // Create the array of vars that will be unified with the vars in the query
  vars = PL_new_term_refs(num_vars);
  // Create terms for the arguments of the predicate
  args = PL_new_term_refs(num_args);
}

void Query::init_query()
{
  // Instantiate the query
  constexpr auto query_flags = PL_Q_CATCH_EXCEPTION | PL_Q_EXT_STATUS | PL_Q_NODEBUG;
  query_handle = PL_open_query(nullptr, query_flags, pred, args);
  if (!query_handle) {
    throw Error{}; // TODO: Use better error
  }
}

std::string
Error::build_msg(qid_t qid)
{
  using namespace std::string_literals;
  auto err_str = "Unknown"s;
  auto exc = PL_exception(qid);
  if (exc) {
    Frame fid{};
    auto args = PL_new_term_refs(2);
#if PLVERSION >= 80306 // Since 8.3.6, PL_put_term() can fail
    bool put_term_success = PL_put_term(args, exc);
#else
    constexpr bool put_term_success = true;
    PL_put_term(args, exc);
#endif
    if (put_term_success) {
      static auto message_to_string = PL_predicate("message_to_string", 2, nullptr);
      if (PL_call_predicate(nullptr, PL_Q_NORMAL, message_to_string, args)) {
        char * msg;
        size_t size;
        if (PL_get_string_chars(args + 1, &msg, &size)) {
          err_str = std::string{msg, size};
        }
      }
    } else {
      err_str = "Could not generate Prolog error string"s;
    }
    PL_clear_exception();
  }
  return "SWI Prolog Error: "s + err_str;
}

bool command(char const * cmd, std::size_t len)
{
  auto fid = Frame{};
  auto term = PL_new_term_ref();
  wrap_error(PL_put_term_from_chars(term, REP_UTF8, len, cmd));
  return PL_call(term, nullptr);
}

void init()
{
  static constexpr auto integers_as_hex1 =
    "pharos:assert((integers_as_hex(0, _) :- !, false))";
  static constexpr auto integers_as_hex2 =
    "pharos:assert((integers_as_hex(X, _) :- integer(X), (X < 0 -> (Y is X * -1, system:format('-0x~16r', [Y])); system:format('0x~16r', [X]))))";
  static constexpr auto term_to_string =
    "pharos:assert((term_to_string(Term, String) :- with_output_to(string(String), write_term(Term, [quoted(true), spacing(next_argument), portray_goal(integers_as_hex)]))))";
  static constexpr auto register_predicate =
    "pharos:assert((register_predicate(Module, Name, Arity, Index) :- functor(BaseHead, Name, Arity), BaseHead =.. [_|Vars], Goal =.. [registry_wrapper, Index|Vars], Rule =.. [':-', Module:BaseHead, Goal], assert(Rule), compile_predicates([Module:Name/Arity])))";
  command(integers_as_hex1);
  command(integers_as_hex2);
  command(term_to_string);
  command(register_predicate);
  command("pharos:compile_predicates([integers_as_hex/2, term_to_string/2, register_predicate/4])");
}

std::ostream & term_to_stream(std::ostream & stream, pl_term pt)
{
  static auto pred = PL_predicate("term_to_string", 2, "pharos");
  auto fid = Frame{};
  auto args = PL_new_term_refs(2);
  wrap_error(PL_unify(pt, args));
  wrap_error(PL_call_predicate(nullptr, PL_Q_NODEBUG, pred, args));
  char const *str;
  p2c(str, args + 1);
  return stream << str;
}

} // namespace impl
} // namespace prolog
} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
