// Copyright 2016-2019 Carnegie Mellon University.  See LICENSE file for terms.

// Author: Michael Duggan

#include "prolog.hpp"

namespace pharos {
namespace prolog {

namespace msg = ::Sawyer::Message;

static std::map<std::string, msg::Importance> importance_map;

msg::Facility plog;

Session::Session(const ProgOptVarMap& vm)
{
  Path libdir = get_library_path();
  auto prolog_dir = Path();
  auto pdir = vm.config().path_get("pharos.prolog_dir");
  if (pdir && !pdir.Scalar().empty()) {
    prolog_dir = pdir.Scalar();
    if (!prolog_dir.has_root_directory()) {
      prolog_dir = libdir / prolog_dir;
    }
  }
  session = impl::Session::get_session(absolute(prolog_dir).native());
  auto default_rule_dir = libdir / "prolog";
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
  session->add_fact("file_search_path", "pharos", default_rule_dir.native());
}

void Session::consult(const std::string & name)
{
  boost::filesystem::path path = name;
  if (!path.has_root_path()) {
    session->consult("pharos", path.native());
  } else {
    session->consult(path.native());
  }
}

bool Session::prolog_log_base(bool newline, Args args)
{
  try {
    std::string imp = args.as<std::string>(0);
    auto level = importance_map.find(to_lower(imp));
    if (level == importance_map.end()) {
      return false;
    }
    if (plog[level->second]) {
      try {
        // Assume a string argument
        char const * message = args.as<char const *>(1);
        plog[level->second] << message;
      } catch (TypeMismatch &) {
        // Handle non-string arguments
        std::string message = args.to_string(1);
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
