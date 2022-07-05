// Copyright 2022 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#include "prolog_symexp.hpp"

namespace pharos {
namespace prolog {

std::string SymbolicExpr2PrologConversionError::build_msg(TreeNode const & expr)
{
  std::stringstream ss;
  ss << "Unable to convert symbolic expression \"" << expr << "\" to a Prolog term";
  return ss.str();
}

} // namespace prolog
} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */

