// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#ifndef Pharos_XSB_HPP
#define Pharos_XSB_HPP

#include <string>
#include "xsb_types.hpp"

// This header and associated C file are used to disassociate the namespace XSB's
// #include <cinterf.h> pulls in from libpharos's namespace.  (The cinterf.h file redefines a
// bunch of things that interfere with rose headers, etc.)

namespace pharos {
namespace prolog {
namespace impl {
namespace xsb {

// This validity of these types are asserted in xsb.cpp.
using xsb_int = std::int64_t;
using xsb_term = std::uint64_t;

enum class status {
  SUCCESS = 0,
  FAILURE = 1,
  ERROR = 2,
  OXFLOW = 3
};

namespace impl {

const char *xsb_get_error_type() noexcept;
const char *xsb_get_error_message() noexcept;
const char *xsb_get_init_error_type() noexcept;
const char *xsb_get_init_error_message() noexcept;

status      xsb_init(int, const char **) noexcept;
status      xsb_close() noexcept;

bool        c2p_functor(const char *, int, xsb_term) noexcept;
bool        c2p_functor(const char *, const char *, int, xsb_term) noexcept;
bool        c2p_int(xsb_int, xsb_term) noexcept;
bool        c2p_list(xsb_term) noexcept;
bool        c2p_nil(xsb_term) noexcept;
bool        c2p_string(const char *, xsb_term) noexcept;

int         p2c_arity(xsb_term) noexcept;
const char *p2c_functor(xsb_term) noexcept;
xsb_int     p2c_int(xsb_term) noexcept;
const char *p2c_string(xsb_term) noexcept;

bool        is_attv(xsb_term) noexcept;
bool        is_float(xsb_term) noexcept;
bool        is_functor(xsb_term) noexcept;
bool        is_int(xsb_term) noexcept;
bool        is_list(xsb_term) noexcept;
bool        is_nil(xsb_term) noexcept;
bool        is_string(xsb_term) noexcept;
bool        is_var(xsb_term) noexcept;

xsb_term    reg_term(int) noexcept;
xsb_term    p2p_arg(xsb_term, int) noexcept;
xsb_term    p2p_car(xsb_term) noexcept;
xsb_term    p2p_cdr(xsb_term) noexcept;
bool        p2p_unify(xsb_term, xsb_term) noexcept;

status      xsb_command_string(const char *) noexcept;
status      xsb_command() noexcept;
status      xsb_query() noexcept;
status      xsb_close_query() noexcept;
status      xsb_next() noexcept;

status xsb_add_c_predicate(
  const char *predname, int arity, int (*cfun)(), const char *modname = nullptr) noexcept;

inline bool c2p_functor(const std::string &s, int args, xsb_term pt) noexcept {
  return c2p_functor(s.c_str(), args, pt);
}

inline status xsb_add_c_predicate(
  const std::string & predname, int arity, int (*cfun)(),
  const std::string & modname = "usermod") noexcept
{
  return xsb_add_c_predicate(predname.c_str(), arity, cfun, modname.c_str());
}

} // namespace impl
} // namespace xsb
} // namespace impl
} // namespace prolog
} // namespace pharos

#endif // Pharos_XSB_HPP

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
