// Copyright 2016-2018 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#include "prolog.hpp"
#include "build.hpp"

namespace pharos {
namespace prolog {

namespace msg = ::Sawyer::Message;

static std::map<std::string, msg::Importance> importance_map;

msg::Facility plog{"PLOG"};

Session::Session(const ProgOptVarMap& vm)
{
  Path libdir = get_library_path();
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

  if (importance_map.empty()) {
    for (int i = 0; i < msg::N_IMPORTANCE; ++i) {
      importance_map.emplace(to_lower(msg::stringifyImportance(msg::Importance(i))),
                             msg::Importance(i));
    }
  }

  register_predicate("log", 2, prolog_log, "pharos");
  register_predicate("logln", 2, prolog_logln, "pharos");
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

int Session::prolog_log_base(bool newline)
{
  using pharos::prolog::impl::arg;

  try {
    std::string imp = arg<std::string>(0);
    auto level = importance_map.find(to_lower(imp));
    if (level == importance_map.end()) {
      return false;
    }
    if (plog[level->second]) {
      try {
        // Assume a string argument
        char const * message = arg<char const *>(1);
        plog[level->second] << message;
      } catch (TypeMismatch &) {
        // Handle non-string arguments
        std::string message = arg<void>(1);
        plog[level->second] << message;
      }
      if (newline) {
        plog[level->second] << std::endl;
      }
    }
    return true;
  } catch (const TypeMismatch &) {
    return false;
  }
}


} // namespace prolog
} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
