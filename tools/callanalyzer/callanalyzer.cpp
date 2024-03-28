// Copyright 2016-2023 Carnegie Mellon University.  See LICENSE file for terms.

// Analyzes function call points in binaries, attempting to determine
// their argument values.

#include <libpharos/descriptors.hpp>
#include <libpharos/typedb.hpp>
#include <libpharos/json.hpp>
#include <libpharos/bua.hpp>
#include <boost/range/combine.hpp>
#include <boost/filesystem.hpp>

// Move our code out of the global namespace to avoid a conflict with clog() from complex.h
namespace {
using namespace pharos;

namespace bf = boost::filesystem;

// The CallAnalyzer message facility.
Sawyer::Message::Facility clog;

// Stack strings debugging
Sawyer::Message::Facility mlog;

#define CINFO_STREAM clog[Sawyer::Message::INFO]
#define CINFO (CINFO_STREAM) && CINFO_STREAM
#define OUTPUT CINFO
#define OUTPUT_STREAM CINFO_STREAM

ProgOptDesc get_options() {
  namespace po = boost::program_options;

  ProgOptDesc opt("callanalyzer 0.8 Options");

  opt.add_options()
    ("allow-unknown", po::bool_switch(),
     "Output call information even when there is no useful parameter information")
    ("show-symbolic", po::bool_switch(),
     "Output symbolic values for <abstr> values")
    ("json,j", po::value<bf::path>(),
     "Output json representation to given file ('-' for stdout)")
    ("pretty-json,p", po::value<unsigned>()->implicit_value(4),
     "Pretty-print json.  Argument is the indent width")
    ("calls", po::value<std::vector<bf::path>>(),
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

class Outputter {
 protected:
  bool allow_unknown;
  bool show_raw;

 public:
  Outputter(ProgOptVarMap const &vm) {
    allow_unknown = vm["allow-unknown"].as<bool>();
    show_raw = vm["show-symbolic"].as<bool>();
  }

  virtual ~Outputter() = default;

  virtual void operator()(
    const CallDescriptor & call,
    const CallParamInfo & info) = 0;
};

class TextOutputter : public Outputter {
  std::ostringstream str;

 public:
  using Outputter::Outputter;

  void operator()(
    const CallDescriptor & call,
    const CallParamInfo & info) override;

 private:

  using printable_t = bool;

  printable_t output_raw(const typedb::Value & value);
  printable_t output_value(const typedb::Value & value, bool wide);
  printable_t output_param(const std::string & name, const typedb::Value & value, bool wide);
};

class JsonOutputter : public Outputter {
  json::BuilderRef builder;
  json::ArrayRef calls;
  json::ObjectRef main;
  std::ostream & out;

 public:
  JsonOutputter(ProgOptVarMap const &vm, std::ostream & stream);
  ~JsonOutputter() override;

  void operator()(
    const CallDescriptor & call,
    const CallParamInfo & info) override;

 private:
  bool build_value(json::ObjectRef & ob, const typedb::Value & value, bool wide);
};

class CallAnalyzer : public BottomUpAnalyzer {
 private:
  CallParamInfoBuilder builder;

  std::function<bool(const CallDescriptor &)> filter;
  std::unique_ptr<std::ofstream> out;
  std::unique_ptr<Outputter> outputter;

 public:
  CallAnalyzer(DescriptorSet& ds_, ProgOptVarMap & vm_);

  void visit (FunctionDescriptor *fd) override
  {
    fd->get_pdg();
    auto callset = fd->get_outgoing_calls();
    for (const CallDescriptor * call : callset) {
      handleCall(*call);
    }
  }

 public:

  void handleCall(const CallDescriptor & call)
  {
    if (!filter(call)) {
      return;
    }
    CallParamInfo info = builder(call);
    (*outputter)(call, info);
  }
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

TextOutputter::printable_t TextOutputter::output_raw(const typedb::Value & value)
{
  auto & raw = value.get_expression();
  if (raw) {
    if (show_raw) {
      str << *raw;
      return true;
    }
    str << "<abstr>";
  } else {
    str << "<unknown>";
  }
  return false;
}

TextOutputter::printable_t TextOutputter::output_value(const typedb::Value & value, bool wide)
{
  printable_t printable = false;
  str << '{'
      << '(' << value.get_type()->get_name() << ')';
  if (value.is_string()) {
    if (value.is_nullptr()) {
      str << "NULL";
      printable = true;
    } else {
      auto v = value.as_string(wide);
      if (v) {
        str << '\"' << *v << '\"';
        printable = true;
      } else {
        printable = output_raw(value);
      }
    }
  } else if (value.is_unsigned()) {
    auto v = value.as_unsigned();
    if (v) {
      str << *v;
      printable = true;
    } else {
      printable = output_raw(value);
    }
  } else if (value.is_signed()) {
    auto v = value.as_signed();
    if (v) {
      str << *v;
      printable = true;
    } else {
      printable = output_raw(value);
    }
  } else if (value.is_bool()) {
    auto v = value.as_bool();
    if (v) {
      str << *v;
      printable = true;
    } else {
      printable = output_raw(value);
    }
  } else if (value.is_pointer()) {
    if (value.is_nullptr()) {
      str << "NULL";
      printable = true;
    } else {
      auto raw = value.get_expression();
      if (raw && raw->isIntegerConstant()) {
        auto f = str.flags();
        str << "0x" << std::hex << *raw->toUnsigned();
        str.flags(f);
        printable = true;
      } else {
        printable = output_raw(value);
      }
      str << " -> ";
      printable |= output_value(value.dereference(), wide);
    }
  } else if (value.is_struct()) {
    str << '{';
    bool comma = false;
    for (auto pv : value.members()) {
      if (comma) {
        str << ", ";
      } else {
        comma = true;
      }
      str << tget<typedb::Param>(pv).name << ": ";
      printable |= output_value(tget<typedb::Value>(pv), wide);
    }
    str << '}';
  } else if (value.is_unknown()) {
    str << "<unknown>";
  }
  str << '}';
  return printable;
}

TextOutputter::printable_t TextOutputter::output_param(
  const std::string & name,
  const typedb::Value & value,
  bool wide)
{
  str << "  Param: " << name << " Value: ";
  printable_t printable = output_value(value, wide);
  str << '\n';
  return printable;
}

void TextOutputter::operator()(
  const CallDescriptor & call,
  const CallParamInfo & info)
{
  printable_t printable = false;
  bool wide = false;

  auto id = call.get_import_descriptor();
  if (id) {
    const std::string & name = id->get_name();
    if (!name.empty() && name.back() == 'W') {
      wide = true;
    }
  }
  str << "Call: ";
  if (id) {
    str << id->get_name() << ' ';
  } else {
    auto fd = call.get_function_descriptor();
    if (fd) {
      str << fd->get_name() << ' ';
    }
  }

  str << '(' << call.address_string() << ")\n";
  for (auto vp : boost::combine(info.names(), info.values())) {
    printable |= output_param(get<0>(vp), get<1>(vp), wide);
  }
  if (printable || allow_unknown) {
    OUTPUT_STREAM << str.str() << std::flush;
  }
  str.str(std::string());
  str.clear();
}

JsonOutputter::JsonOutputter(ProgOptVarMap const & vm, std::ostream & stream)
  : Outputter(vm), out(stream)
{
  builder = json::simple_builder();
  main = builder->object();
  main->add("tool", "callanalyzer");
  auto args = builder->array();
  for (auto & arg : vm.args()) {
    args->add(arg);
  }
  main->add("invocation", std::move(args));
  auto specs = vm["file"].as<Specimens>().specimens();
  if (specs.size() == 1) {
    main->add("analyzed_file", specs.front());
  } else {
    auto bspecs = builder->array();
    for (auto & spec : specs) {
      bspecs->add(spec);
    }
    main->add("analyzed_file", std::move(bspecs));
  }
  calls = builder->array();
  if (vm.count("pretty-json")) {
    out << json::pretty(vm["pretty-json"].as<unsigned>());
  }
}

JsonOutputter::~JsonOutputter()
{
  main->add("analysis", std::move(calls));
  out << *main;
}

void JsonOutputter::operator()(
  const CallDescriptor & call,
  const CallParamInfo & info)
{
  bool wide = false;
  bool output = false;
  auto jsoncall = builder->object();
  auto id = call.get_import_descriptor();
  if (id) {
    const std::string & name = id->get_name();
    if (!name.empty() && name.back() == 'W') {
      wide = true;
    }
    jsoncall->add("name", id->get_name());
  } else {
    auto fd = call.get_function_descriptor();
    if (fd) {
      jsoncall->add("name", fd->get_name());
    }
  }
  jsoncall->add("address", call.address_string());
  auto params = builder->array();
  for (auto vp : boost::combine(info.names(), info.values())) {
    auto pob = builder->object();
    auto const & name = get<0>(vp);
    if (!name.empty()) {
      pob->add("name", name);
    }
    output |= build_value(pob, get<1>(vp), wide);
    params->add(std::move(pob));
  }
  jsoncall->add("params", std::move(params));
  if (output || allow_unknown) {
    calls->add(std::move(jsoncall));
  }
}

bool JsonOutputter::build_value(
  json::ObjectRef & ob,
  const typedb::Value & value,
  bool wide)
{
  static char const * vkey = "value";
  bool output = false;
  auto raw = [this, &value]
             (json::ObjectRef & obj, char const * key) -> bool {
    if (show_raw) {
      auto & r = value.get_expression();
      if (r) {
        std::ostringstream os;
        auto vo = builder->object();
        os << *r;
        vo->add("raw", os.str());
        obj->add(key, std::move(vo));
        return true;
      }
    }
    return false;
  };

  if (value.is_unknown()) {
    return false;
  }
  ob->add("type", value.get_type()->get_name());
  if (value.is_string()) {
    if (value.is_nullptr()) {
      ob->add(vkey, builder->null());
      output = true;
    } else {
      auto v = value.as_string(wide);
      if (v) {
        ob->add(vkey, *v);
        output = true;
      } else {
        output = raw(ob, vkey);
      }
    }
  } else if (value.is_unsigned()) {
    auto v = value.as_unsigned();
    if (v) {
      ob->add(vkey, *v);
      output = true;
    } else {
      output = raw(ob, vkey);
    }
  } else if (value.is_signed()) {
    auto v = value.as_signed();
    if (v) {
      ob->add(vkey, *v);
      output = true;
    } else {
      output = raw(ob, vkey);
    }
  } else if (value.is_bool()) {
    auto v = value.as_bool();
    if (v) {
      ob->add(vkey, *v);
      output = true;
    } else {
      output = raw(ob, vkey);
    }
  } else if (value.is_pointer()) {
    if (value.is_nullptr()) {
      ob->add(vkey, builder->null());
    } else {
      bool aout = false;
      auto pob = builder->object();
      auto rawv = value.get_expression();
      if (rawv && rawv->isIntegerConstant()) {
        std::ostringstream os;
        os << "0x" << std::hex << *rawv->toUnsigned();
        pob->add("address", os.str());
        aout = true;
      } else {
        aout = raw(pob, "address");
      }
      auto vob = builder->object();
      bool vout = build_value(vob, value.dereference(), wide);
      if (vout) {
        pob->add("pointee", std::move(vob));
        output = true;
      }
      if (aout || vout) {
        ob->add(vkey, std::move(pob));
        output = true;
      }
    }
  } else if (value.is_struct()) {
    auto sarray = builder->array();
    for (auto pv : value.members()) {
      auto val = builder->object();
      auto const & name = tget<typedb::Param>(pv).name;
      if (!name.empty()) {
        val->add("name", name);
      }
      output |= build_value(val, tget<typedb::Value>(pv), wide);
      sarray->add(std::move(val));
    }
    ob->add(vkey, std::move(sarray));
  }
  return output;
}

CallAnalyzer::CallAnalyzer(DescriptorSet& ds_, ProgOptVarMap & vm_)
  : BottomUpAnalyzer(ds_, vm_), builder(vm_, ds_.memory)
{
  if (vm_.count("calls")) {
    auto cf = CallFilter();
    auto & paths = vm_["calls"].as<std::vector<bf::path>>();
    for (auto & path : paths) {
      if (path.compare("-") == 0) {
        cf.from_stream(std::cin);
      } else {
        std::ifstream stream(path.native());
        if (stream.fail()) {
          throw std::runtime_error("Could not open for reading: " + path.native());
        }
        cf.from_stream(stream);
      }
    }
    filter = cf;
  } else {
    filter = [](const CallDescriptor &){return true;};
  }
  if (vm_.count("json")) {
    auto & arg = vm_["json"].as<bf::path>();
    if (arg.compare("-") == 0) {
      outputter = make_unique<JsonOutputter>(vm_, std::cout);
    } else {
      out = make_unique<std::ofstream>(arg.native());
      outputter = make_unique<JsonOutputter>(vm_, *out);
    }
  } else {
    outputter = make_unique<TextOutputter>(vm_);
  }
}

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
  mlog.initialize("CDBG");
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
  clog.initialize("CLLA");
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
  // Resolve imports, load API data, etc.
  ds.resolve_imports();

  CallAnalyzer analyzer(ds, vm);
  analyzer.analyze();

  OINFO << "Complete." << LEND;
  return EXIT_SUCCESS;
}


} // unnamed namespace

int main(int argc, char **argv)
{
  return pharos_main("CALA", callanalyzer_main, argc, argv, STDERR_FILENO);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
