// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Options_H
#define Pharos_Options_H

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#include <rose.h>

#include "config.hpp"

namespace pharos {

// Forward declarations to reduce the header interdependencies.
class DescriptorSet;
class FunctionDescriptor;

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

 private:
  pharos::Config _config;
};

} // namespace pharos

#include "misc.hpp"
#include "util.hpp"

namespace pharos {

typedef std::vector<std::string> StrVector;

typedef boost::program_options::options_description ProgOptDesc;
typedef boost::program_options::positional_options_description ProgPosOptDesc;

ProgOptDesc cert_standard_options();
// parse_cert_options should probably become a class at some point instead of a function
ProgOptVarMap parse_cert_options(int argc, char** argv, ProgOptDesc od,
                                 const std::string & proghelptext = std::string());
AddrSet option_addr_list(ProgOptVarMap& vm, const char *name);

ProgOptVarMap& get_global_options_vm();

boost::filesystem::path get_default_libdir();

#define PHAROS_PASS_EXCEPTIONS_ENV "PHAROS_PASS_EXCEPTIONS"

extern int global_logging_fileno;

typedef int (*main_func_ptr)(int argc, char** argv);
int pharos_main(main_func_ptr fn, int argc, char **argv, int logging_fileno = STDOUT_FILENO);

class BottomUpAnalyzer {

public:
  // Cory sees no reason not to make these public.  They're practically global.
  DescriptorSet* ds;
  ProgOptVarMap vm;

  size_t processed_funcs;
  size_t total_funcs;
  rose_addr_t current_func;

  BottomUpAnalyzer(DescriptorSet* ds_, ProgOptVarMap& vm_);

  // Call this method to do the actual work.
  void analyze();

  // Override this method if you want to alter the progress bar.
  virtual void update_progress() const;

  // Override this method which is called at the beginning of
  // analzye()
  virtual void start();

  // Override this method which is called at the end of analyze()
  virtual void finish();

  // Override this method, with is invoked for each selected function
  // in the appropriate bottom up order.
  virtual void visit(FunctionDescriptor *fd);
};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
