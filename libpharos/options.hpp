// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Options_H
#define Pharos_Options_H

#include <boost/foreach.hpp>
#include <boost/program_options.hpp>

#include <rose.h>
#include "config.hpp"

// Forward declarations to reduce the header interdependencies.
class DescriptorSet;
class FunctionDescriptor;

// misc.hpp needs this definition...
class ProgOptVarMap : public boost::program_options::variables_map{
 public:
  pharos::Config config() {
    return _config;
  }

  void config(const pharos::Config &cfg) {
    _config = cfg;
  }

  template <typename T>
  boost::optional<T> get(const std::string &cli_option,
                         const std::string &config_option) const
  {
    if (count(cli_option)) {
      return (*this)[cli_option].as<T>();
    }
    auto node = _config.path_get(config_option);
    if (node) {
      return node.as<T>();
    }
    return boost::none;
  }

 private:
  pharos::Config _config;
};

// The option parsing logging facility.
extern Sawyer::Message::Facility olog;
#define OCRAZY (olog[Sawyer::Message::DEBUG]) && olog[Sawyer::Message::DEBUG]
#define OTRACE (olog[Sawyer::Message::TRACE]) && olog[Sawyer::Message::TRACE]
#define ODEBUG (olog[Sawyer::Message::WHERE]) && olog[Sawyer::Message::WHERE]
#define OMARCH olog[Sawyer::Message::MARCH]
#define OINFO  olog[Sawyer::Message::INFO]
#define OWARN  olog[Sawyer::Message::WARN]
#define OERROR olog[Sawyer::Message::ERROR]
#define OFATAL olog[Sawyer::Message::FATAL]

#include "misc.hpp"
#include "util.hpp"

typedef std::vector<std::string> StrVector;

typedef boost::program_options::options_description ProgOptDesc;
typedef boost::program_options::positional_options_description ProgPosOptDesc;

ProgOptDesc cert_standard_options();
ProgOptVarMap parse_cert_options(int argc, char** argv, ProgOptDesc od);
AddrSet option_addr_list(ProgOptVarMap& vm, const char *name);

ProgOptVarMap& get_global_options_vm();

#define PHAROS_PASS_EXCEPTIONS_ENV "PHAROS_PASS_EXCEPTIONS"

template <typename T, int failure=EXIT_FAILURE>
int pharos_main(T fn, int argc, char **argv) {
  if (getenv(PHAROS_PASS_EXCEPTIONS_ENV)) {
    return fn(argc, argv);
  }
  try {
    return fn(argc, argv);
  } catch (const std::exception &e) {
    GFATAL << e.what() << LEND;
    return failure;
  }
}

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

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
