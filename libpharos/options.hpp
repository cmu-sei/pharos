// Copyright 2015-2023 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Options_H
#define Pharos_Options_H

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#include <Sawyer/Message.h>
#include "config.hpp"
#include "util.hpp"

namespace YAML {
template<>
struct convert<boost::filesystem::path> {
  static Node encode(const boost::filesystem::path & path) {
    return Node(path.native());
  }
  static bool decode(const Node & node, boost::filesystem::path & rhs) {
    if (!node.IsScalar()) {
      return false;
    }
    rhs = node.Scalar();
    return true;
  }
};
}

namespace pharos {

class DescriptorSet;

// The option parsing logging facility.
extern Sawyer::Message::Facility olog;
#define OCRAZY (pharos::olog[Sawyer::Message::DEBUG]) && pharos::olog[Sawyer::Message::DEBUG]
#define OTRACE (pharos::olog[Sawyer::Message::TRACE]) && pharos::olog[Sawyer::Message::TRACE]
#define ODEBUG (pharos::olog[Sawyer::Message::WHERE]) && pharos::olog[Sawyer::Message::WHERE]
#define OMARCH pharos::olog[Sawyer::Message::MARCH]
#define OINFO  pharos::olog[Sawyer::Message::INFO]
#define OWARN  pharos::olog[Sawyer::Message::WARN]
#define OERROR pharos::olog[Sawyer::Message::ERROR]
#define OFATAL pharos::olog[Sawyer::Message::FATAL]

// misc.hpp needs this definition...
class ProgOptVarMap : public boost::program_options::variables_map{
 public:
  ProgOptVarMap() = default;
  ProgOptVarMap(int argc, char **argv);

  pharos::Config & config() {
    return _config;
  }

  const pharos::Config & config() const {
    return _config;
  }

  void config(const pharos::Config &cfg) {
    _config = cfg;
  }

  template <typename T>
  boost::optional<T> get(const std::string &config_option) const
  {
    auto node = _config.path_get(config_option);
    if (node) {
      return node.as<T>();
    }
    return boost::none;
  }

  template <typename T>
  boost::optional<T> get(const std::string &cli_option,
                         const std::string &config_option) const
  {
    if (count(cli_option)) {
      return (*this)[cli_option].as<T>();
    }
    return get<T>(config_option);
  }

  std::vector<char const *> const & args() const {
    return _args;
  }

  std::string command_line() const;

 private:
  pharos::Config _config;
  std::vector<char const *> _args;
};

class SpecimenName {
  std::string specimen_;
  std::size_t offset_;
  mutable boost::optional<MD5Result> md5_;
 public:
  SpecimenName(std::string const & arg);

  std::string const & specimen() const { return specimen_; }
  boost::filesystem::path filename() const;
  bool non_normal() const { return offset_; }
  operator boost::filesystem::path () const { return filename(); }
  MD5Result md5() const;
};

class Specimens {
  std::vector<SpecimenName> specs_;
 public:
  Specimens() = default;
  Specimens(std::vector<SpecimenName> && specs) : specs_{std::move(specs)} {}

  void add(std::vector<SpecimenName> && more);

  bool single_normal_executable() const;
  bool mapped_executable() const;
  std::set<boost::filesystem::path> filenames() const;
  std::vector<std::string> specimens() const;
  MD5Result unique_identifier() const;
  std::string name() const;
};

void validate(boost::any& v,
              std::vector<std::string> const & values,
              Specimens *, int);

void validate(boost::any& v,
              std::vector<std::string> const & values,
              SpecimenName *, int);
} // namespace pharos

namespace boost {
namespace filesystem {
void validate(boost::any& v,
              std::vector<std::string> const & values,
              boost::filesystem::path *, int);
}}

#include "misc.hpp"
#include "util.hpp"

namespace pharos {

using StrVector = std::vector<std::string>;

using ProgOptDesc = boost::program_options::options_description;
using ProgPosOptDesc = boost::program_options::positional_options_description;

using LogDestination = Sawyer::Message::UnformattedSinkPtr;

ProgOptDesc cert_standard_options();
// parse_cert_options should probably become a class at some point instead of a function
ProgOptVarMap parse_cert_options(
  int argc, char** argv,
  ProgOptDesc od,
  const std::string & proghelptext = std::string(),
  boost::optional<ProgPosOptDesc> posopt = boost::none,
  LogDestination logging = LogDestination());

AddrSet option_addr_list(ProgOptVarMap const & vm, const char *name);

AddrSet get_selected_funcs(const DescriptorSet& ds, ProgOptVarMap const & vm);

ProgOptVarMap const & get_global_options_vm();

const boost::filesystem::path& get_library_path();

#define PHAROS_PASS_EXCEPTIONS_ENV "PHAROS_PASS_EXCEPTIONS"

LogDestination get_logging_destination();
bool interactive_logging();

using main_func_ptr = int (*)(int argc, char** argv);
int pharos_main(std::string const & glog_name, main_func_ptr fn,
                int argc, char **argv, int logging_fileno = STDOUT_FILENO);

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
