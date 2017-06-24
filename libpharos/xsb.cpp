#include "xsb.hpp"
#include <cinterf.h>
#include <type_traits>
#include <limits>

namespace pharos {
namespace prolog {
namespace impl {
namespace xsb {

namespace {

template <typename T>
constexpr bool valid_int() {
  return (std::is_integral<T>::value
          && std::numeric_limits<T>::is_specialized
          && std::numeric_limits<T>::is_exact);
}

template <typename P, typename X>
constexpr bool valid_conversion() {
  return (valid_int<P>() && valid_int<X>()
          && std::is_convertible<P, X>::value
          && std::is_convertible<X, P>::value
          && sizeof(P) <= sizeof(X));
}

static_assert(valid_conversion<xsb_int, prolog_int>(),
              "xsb_int and prolog_int aren't compatible");
static_assert(valid_conversion<xsb_term, prolog_term>(),
              "xsb_term and prolog_term aren't compatible");

// The global thread variable
#ifdef MULTI_THREAD
CTXTdecl;
#endif

static_assert(static_cast<int>(status::SUCCESS) == XSB_SUCCESS, "");
static_assert(static_cast<int>(status::FAILURE) == XSB_FAILURE, "");
static_assert(static_cast<int>(status::ERROR) == XSB_ERROR, "");
static_assert(static_cast<int>(status::OXFLOW) == XSB_OVERFLOW, "");

constexpr status to_status(int s) noexcept {
  return static_cast<status>(s);
}

} // unnamed namespace

namespace impl {

const char *xsb_get_error_type() noexcept {
  return ::xsb_get_error_type(CTXT);
}

const char *xsb_get_error_message() noexcept {
  return ::xsb_get_error_message(CTXT);
}

const char *xsb_get_init_error_type() noexcept {
  return ::xsb_get_init_error_type();
}

const char *xsb_get_init_error_message() noexcept {
  return ::xsb_get_init_error_message();
}

status xsb_init(int argc, const char **argv) noexcept {
  auto rv = to_status(::xsb_init(argc, const_cast<char **>(argv)));
#ifdef MULTI_THREAD
  if (rv == status::SUCCESS) noexcept {
    CTXT = xsb_get_main_thread();
  }
#endif
  return rv;
}

status xsb_close() noexcept {
  return to_status(::xsb_close(CTXT));
}

bool c2p_functor(const char *name, int args, xsb_term t) noexcept {
  return ::c2p_functor(CTXTc const_cast<char *>(name), args, t);
}

bool c2p_functor(const char *modname, const char *name, int args, xsb_term t) noexcept
{
  return ::c2p_functor_in_mod(CTXTc const_cast<char *>(modname),
                              const_cast<char *>(name), args, t);
}

bool c2p_int(xsb_int i, xsb_term t) noexcept {
  return ::c2p_int(CTXTc i, t);
}

bool c2p_list(xsb_term t) noexcept {
  return ::c2p_list(CTXTc t);
}

bool c2p_nil(xsb_term t) noexcept {
  return ::c2p_nil(CTXTc t);
}

bool c2p_string(const char *name, xsb_term t) noexcept {
  return ::c2p_string(CTXTc const_cast<char *>(name), t);
}

int p2c_arity(xsb_term t) noexcept {
  return ::p2c_arity(t);
}

const char *p2c_functor(xsb_term t) noexcept {
  return ::p2c_functor(t);
}

xsb_int p2c_int(xsb_term t) noexcept {
  return ::p2c_int(t);
}

const char *p2c_string(xsb_term t) noexcept {
  return ::p2c_string(t);
}

bool is_attv(xsb_term t) noexcept {
  return ::is_attv(t);
}

bool is_float(xsb_term t) noexcept {
  return ::is_float(t);
}

bool is_functor(xsb_term t) noexcept {
  return ::is_functor(t);
}

bool is_int(xsb_term t) noexcept {
  return ::is_int(t);
}

bool is_list(xsb_term t) noexcept {
  return ::is_list(t);
}

bool is_nil(xsb_term t) noexcept {
  return ::is_nil(t);
}

bool is_string(xsb_term t) noexcept {
  return ::is_string(t);
}

bool is_var(xsb_term t) noexcept {
  return ::is_var(t);
}

xsb_term reg_term(int arg) noexcept {
  return ::reg_term(CTXTc arg);
}

xsb_term p2p_arg(xsb_term t, int i) noexcept {
  return ::p2p_arg(t, i);
}

xsb_term p2p_car(xsb_term t) noexcept {
  return ::p2p_car(t);
}

xsb_term p2p_cdr(xsb_term t) noexcept {
  return ::p2p_cdr(t);
}

bool p2p_unify(xsb_term a, xsb_term b) noexcept {
  return ::p2p_unify(a, b);
}

status xsb_command_string(const char *cmd) noexcept {
  return to_status(::xsb_command_string(CTXTc const_cast<char *>(cmd)));
}

status xsb_command() noexcept {
  return to_status(::xsb_command(CTXT));
}

status xsb_query() noexcept {
  return to_status(::xsb_query(CTXT));
}

status xsb_close_query() noexcept {
  return to_status(::xsb_close_query(CTXT));
}

status xsb_next() noexcept {
  return to_status(::xsb_next(CTXT));
}

status xsb_add_c_predicate(
  const char *predname, int arity, int (*cfun)(), const char *modname) noexcept
{
  return to_status(::xsb_add_c_predicate(const_cast<char *>(modname),
                                         const_cast<char *>(predname), arity, cfun));
}


} // namespace impl
} // namespace xsb
} // namespace impl
} // namespace prolog
} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
