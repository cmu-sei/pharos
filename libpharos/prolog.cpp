// Copyright 2016-2017 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#include "prolog.hpp"
#include "build.hpp"

namespace pharos {
namespace prolog {

Session::Session(const ProgOptVarMap& vm)
{
  Path libdir;
  if (global_descriptor_set) {
    libdir = global_descriptor_set->get_library_path();
  }
  auto prolog_dir = absolute(Path(PHAROS_XSB_BUILD_LOCATION));
  auto pdir = vm.config().path_get("pharos.prolog_dir");
  if (pdir && !pdir.Scalar().empty()) {
    prolog_dir = pdir.Scalar();
    if (!prolog_dir.has_root_directory()) {
      prolog_dir = libdir / prolog_dir;
    }
  }
  session = impl::Session::get_session(absolute(prolog_dir).native());
  default_rule_dir = libdir / "prolog";
  auto rdir = vm.config().path_get("pharos.prolog_rules_dir");
  if (rdir && ! rdir.Scalar().empty()) {
    default_rule_dir = rdir.Scalar();
    if (!default_rule_dir.has_root_directory()) {
      default_rule_dir = libdir / default_rule_dir;
    }
  }
}

bool Session::consult(const std::string & name)
{
  boost::filesystem::path path = name;
  if (!path.has_root_path()) {
    path = default_rule_dir;
    path /= name;
  }
  const auto libdir = path.parent_path().native();
  const auto pathfact = functor("library_directory", libdir);
  try {
    session->add_fact(pathfact);
    session->consult(path.native());
    session->command("retract", pathfact);
  } catch (const FileNotFound &) {
    session->command("retract", pathfact);
    return false;
  }
  return true;
}


} // namespace prolog
} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
