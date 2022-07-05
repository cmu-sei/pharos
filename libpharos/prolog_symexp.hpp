// Copyright 2022 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#ifndef Pharos_PROLOG_SYMEXP_HPP
#define Pharos_PROLOG_SYMEXP_HPP

#include <type_traits>
#include "misc.hpp"
#include "prolog.hpp"

namespace pharos {
namespace prolog {

class SymbolicExpr2PrologConversionError : public Error {
  static std::string build_msg(TreeNode const & expr);
 public:
  SymbolicExpr2PrologConversionError(TreeNode const & expr)
    : pharos::prolog::Error(build_msg(expr)) {}
};

namespace impl {

template<>
struct Convert<TreeNode> {
  static void c2p(TreeNode const & expr, pl_term pt) {
    if (expr.isInteriorNode()) {
      auto args = list();
      for (size_t i = 0; i < expr.nChildren(); ++i) {
        args.push_back(expr.child(i));
      }
      prolog::c2p(functor(SymbolicExpr::toStr(expr.getOperator()), args), pt);
    } else if (expr.isConstant() && (expr.isIntegerExpr() || expr.isMemoryExpr())) {
      prolog::c2p(*(expr.toUnsigned()), pt);
    } else if (expr.isVariable2()) {
      prolog::c2p(functor("sv", "sv_" + std::to_string(expr.hash()), expr.comment()), pt);
    } else {
      throw SymbolicExpr2PrologConversionError(expr);
    }
  }
};

template<typename T>
struct Convert<T, std::enable_if_t<std::is_base_of<TreeNode, T>::value>> {
  static void c2p(T const & expr, pl_term pt) {
    Convert<TreeNode>::c2p(expr, pt);
  }
};

template<typename T>
struct Convert<Sawyer::SharedPointer<T>,
               std::enable_if_t<std::is_base_of<TreeNode, T>::value>>
{
  static void c2p(Sawyer::SharedPointer<T> const & expr, pl_term pt) {
    Convert<TreeNode>::c2p(*expr, pt);
  }
};

} // namespace impl
} // namespace prolog
} // namespace pharos


#endif // Pharos_PROLOG_SYMEXP_HPP

