// Copyright 2016, 2017 Carnegie Mellon University.  See LICENSE file for terms.

// Analyzes function call points in binaries, attempting to determine
// their argument values.

#include <libpharos/descriptors.hpp>
#include <libpharos/typedb.hpp>

using namespace pharos;

// The global CERT message facility.
Sawyer::Message::Facility glog("CALA");

// The CallAnalyzer message facility.
Sawyer::Message::Facility clog("CLLA");

// Stack strings debugging
Sawyer::Message::Facility mlog("CDBG");

#define CINFO_STREAM clog[Sawyer::Message::INFO]
#define CINFO (CINFO_STREAM) && CINFO_STREAM
#define OUTPUT CINFO
#define OUTPUT_STREAM CINFO_STREAM

ProgOptDesc get_options() {
  namespace po = boost::program_options;

  ProgOptDesc opt("callanalyzer 0.01 Options");

  opt.add_options()
    ("allow-unknown", po::bool_switch(),
     "Output call information even when there is no useful parameter information")
    ("show-symbolic", po::bool_switch(),
     "Output symbolic values for <abstr> values")
    ("calls", po::value<std::vector<std::string>>(),
     "File containing a list of calls to output information about")
    ;

  opt.add(cert_standard_options());

  return opt;
}


class CallFilter {
  std::unordered_set<std::string> names;
  std::unordered_set<rose_addr_t> addresses;

 public:
  CallFilter() = default;
  CallFilter(std::istream & stream) {
    from_stream(stream);
  }

  bool operator()(const CallDescriptor & call) const;
  void from_stream(std::istream & stream);
};

bool CallFilter::operator()(const CallDescriptor & call) const
{
  if (!addresses.empty()) {
    for (auto & addr : call.get_targets()) {
      if (addresses.find(addr) != addresses.end()) {
        return true;
      }
    }
  }
  auto id = call.get_import_descriptor();
  if (id) {
    const std::string & name = id->get_name();
    if (names.find(name) != names.end()) {
      return true;
    }
  }
  return false;
}

void CallFilter::from_stream(std::istream & stream)
{
  std::string str;
  while (stream >> str) {
    assert(!str.empty());
    if (str.back() == ',') {
      str.pop_back();
      if (str.empty()) {
        continue;
      }
    }
    std::size_t pos;
    try {
      auto ival = std::stoll(str, &pos, 16);
      if (pos == str.size()) {
        addresses.insert(ival);
        continue;
      }
    }
    catch (const std::invalid_argument &) {}
    names.insert(str);
  }
}

class CallAnalyzer : public BottomUpAnalyzer {
 private:
  typedb::DB type_db;
  const typedb::DB & db() const {
    return type_db;
  }

  bool allow_unknown;
  bool show_raw;
  std::function<bool(const CallDescriptor &)> filter;
  std::ostream * out = &OUTPUT_STREAM;

  using printable_t = bool;

 public:
  CallAnalyzer(DescriptorSet * ds_, ProgOptVarMap & vm_)
    : BottomUpAnalyzer(ds_, vm_), type_db(typedb::DB::create_standard(vm_))
  {
    allow_unknown = vm_["allow-unknown"].as<bool>();
    show_raw = vm_["show-symbolic"].as<bool>();
    if (vm_.count("calls")) {
      auto cf = CallFilter();
      auto & paths = vm_["calls"].as<std::vector<std::string>>();
      for (auto & path : paths) {
        if (path == "-") {
          cf.from_stream(std::cin);
        } else {
          std::ifstream stream(path);
          cf.from_stream(stream);
        }
      }
      filter = cf;
    } else {
      filter = [](const CallDescriptor &){return true;};
    }
  }

  void visit (FunctionDescriptor *fd) override
  {
    fd->get_pdg();
    const CallDescriptorSet & callset = fd->get_outgoing_calls();
    for (CallDescriptor * call : callset) {
      handleCall(*call);
    }
  }

 public:

  printable_t output_raw(const typedb::Value & value)
  {
    auto & raw = value.get_expression();
    if (raw) {
      if (show_raw) {
        if (out) {
          *out << *raw;
        }
        return true;
      }
      if (out) {
        *out << "<abstr>";
      }
    } else {
      if (out) {
        *out << "<unknown>";
      }
    }
    return false;
  }

  printable_t output_value(const typedb::Value & value, bool wide)
  {
    printable_t printable = false;
    if (out) {
      *out << '{';
      *out << '(' << value.get_type()->get_name() << ')';
    }
    if (value.is_string()) {
      if (value.is_nullptr()) {
        if (out) {
          *out << "NULL";
        }
        printable = true;
      } else {
        auto v = value.as_string(wide);
        if (v) {
          if (out) {
            *out << '\"' << *v << '\"';
          }
          printable = true;
        } else {
          printable = output_raw(value);
        }
      }
    } else if (value.is_unsigned()) {
        auto v = value.as_unsigned();
        if (v) {
          if (out) {
            *out << *v;
          }
          printable = true;
        } else {
          printable = output_raw(value);
        }
    } else if (value.is_signed()) {
        auto v = value.as_signed();
        if (v) {
          if (out) {
            *out << *v;
          }
          printable = true;
        } else {
          printable = output_raw(value);
        }
    } else if (value.is_bool()) {
        auto v = value.as_bool();
        if (v) {
          if (out) {
            *out << *v;
          }
          printable = true;
        } else {
          printable = output_raw(value);
        }
    } else if (value.is_pointer()) {
      if (value.is_nullptr()) {
        if (out) {
          *out << "NULL";
        }
        printable = true;
      } else {
        auto raw = value.get_expression();
        if (raw && raw->isNumber()) {
          if (out) {
            auto f = out->flags();
            *out << "0x" << std::hex << raw->toInt();
            out->flags(f);
          }
          printable = true;
        } else {
          printable = output_raw(value);
        }
        if (out) {
          *out << " -> ";
        }
        printable |= output_value(value.dereference(), wide);
      }
    } else if (value.is_struct()) {
      if (out) {
        *out << '{';
      }
      bool comma = false;
      for (auto pv : value.members()) {
        if (comma) {
          if (out) {
            *out << ", ";
          }
        } else {
          comma = true;
        }
        if (out) {
          *out << tget<typedb::Param>(pv).name << ": ";
        }
        printable |= output_value(tget<typedb::Value>(pv), wide);
      }
      if (out) {
        *out << '}';
      }
    } else if (value.is_unknown()) {
      if (out) {
        *out << "<unknown>";
      }
    }
    if (out) {
      *out << '}';
    }
    return printable;
  }

  void output_param(const std::string & name, const typedb::Value & value, bool wide)
  {
    if (out) {
      *out << "  Param: " << name << " Value: ";
    }
    output_value(value, wide);
    if (out) {
      *out << '\n';
    }
  }

  void handleCall(const CallDescriptor & call)
  {
    if (!filter(call)) {
      return;
    }
    bool wide = false;
    auto id = call.get_import_descriptor();
    if (id) {
      const std::string & name = id->get_name();
      if (!name.empty() && std::tolower(name.back()) == 'w') {
        wide = true;
      }
    }
    const ParameterList & paramlist = call.get_parameters();
    const ParamVector & params = paramlist.get_params();
    auto & state = call.get_state();
    std::vector<std::pair<const std::string *, typedb::Value>> pvalues;
    bool printable = false;
    auto tmp = out;
    out = nullptr;
    for (const ParameterDefinition & param : params) {
      auto value = param.get_value();
      auto type = param.get_type();
      auto tref = type.empty() ? std::make_shared<typedb::UnknownType>("<unknown>") :
                  db().lookup(type);
      auto v = tref->get_value(value, &*state);
      if (!printable && v) {
        printable = output_value(v, wide);
      }
      pvalues.emplace_back(&param.get_name(), std::move(v));
    }
    out = tmp;
    if (!allow_unknown && !printable) {
      return;
    }
    *out << "Call: ";
    if (id) {
      *out <<  id->get_name() << ' ';
    } else {
      auto fd = call.get_function_descriptor();
      if (fd) {
        *out <<  fd->get_name() << ' ';
      }
    }

    *out << '(' << call.address_string() << ")\n";
    for (auto & pvalue : pvalues) {
      output_param(*pvalue.first, pvalue.second, wide);
    }
    *out << std::flush;
  }
};


static int callanalyzer_main(int argc, char **argv)
{
  // Debug logging context
  Sawyer::Message::FdSinkPtr mout = Sawyer::Message::FdSink::instance(STDERR_FILENO);
  Sawyer::Message::PrefixPtr mprefix =
    Sawyer::Message::Prefix::instance()
    ->showProgramName(false)
    ->showElapsedTime(true)
    ->showFacilityName(Sawyer::Message::Prefix::SOMETIMES)
    ->showImportance(true);
  mlog.initStreams(mout->prefix(mprefix));
  Sawyer::Message::mfacilities.insert(mlog);

  // Program logging context
  Sawyer::Message::FdSinkPtr cout = Sawyer::Message::FdSink::instance(STDOUT_FILENO);
  Sawyer::Message::PrefixPtr cprefix =
    Sawyer::Message::Prefix::instance()
    ->showProgramName(false)
    ->showElapsedTime(false)
    ->showFacilityName(Sawyer::Message::Prefix::NEVER)
    ->showImportance(false);
  clog.initStreams(cout->prefix(cprefix));
  Sawyer::Message::mfacilities.insert(clog);

  // Handle options
  ProgOptDesc opt = get_options();
  ProgOptVarMap vm = parse_cert_options(argc, argv, opt);

  // This should not be here, as it prevents the user from modifying the CLLA stream
  // information.  But parse_cert_options() disables all non-error logging messages at
  // options.cpp:256.  That should be fixed.
  Sawyer::Message::mfacilities.control("CLLA(all)");

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  if (ds.get_interp() == NULL) {
    GFATAL << "Unable to analyze file (no executable content found)." << LEND;
    return EXIT_FAILURE;
  }
  // Load a config file overriding parts of the analysis.
  if (vm.count("imports")) {
    std::string config_file = vm["imports"].as<std::string>();
    OINFO << "Loading analysis configuration file: " <<  config_file << LEND;
    ds.read_config(config_file);
  } else {
    // Load stack deltas from config files for imports.
    ds.resolve_imports();
  }

  CallAnalyzer analyzer(&ds, vm);
  analyzer.analyze();

  OINFO << "Complete." << LEND;
  return EXIT_SUCCESS;
}



int main(int argc, char **argv)
{
  return pharos_main(callanalyzer_main, argc, argv, STDERR_FILENO);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
