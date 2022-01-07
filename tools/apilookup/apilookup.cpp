// Copyright 2018-2021 Carnegie Mellon University.  See LICENSE file for terms.

#include <vector>
#include <cctype>
#include <algorithm>
#include <limits>
#include <libpharos/apidb.hpp>
#include <libpharos/options.hpp>
#include <libpharos/json.hpp>

#include <boost/filesystem.hpp>

using namespace pharos;

namespace bf = boost::filesystem;

namespace {

ProgOptDesc options() {
  namespace po = boost::program_options;
  ProgOptDesc opts("APILookup Options");
  opts.add_options()
    ("json,j", po::value<bf::path>()->value_name("FILENAME")->implicit_value("-"),
     "Ouput JSON to given file.  Default is to stdout (-).")
    ("pretty-json,p", po::value<unsigned>()->implicit_value(4),
     "Pretty-print json.  Argument is the indent width")
    ("regexp,r", po::bool_switch(), "Treat symbols as regular expressions")
    ("case-insensitive-regexp,c", po::bool_switch(),
     "Treat symbols as case-insensitive regular expressions")
    ("symbols,s", po::value<std::vector<std::string>>(),
     "Symbols to be queried");
  return opts;
}


void output_symbols(std::string const & symbol, APIDefinitionList const & defs)
{
  std::cout << "Lookup: " << symbol << '\n';
  if (defs.size() == 0) {
    std::cout << "  No definition found" << std::endl;
  } else {
    for (auto & def : defs) {
      std::cout << "  Definition found" << '\n'
                << "    Name: ";
      if (def->display_name.empty()) {
        std::cout << def->export_name;
      } else {
        std::cout << def->display_name;
      }
      std::cout << '\n'
                << "    Export: " << def->export_name << '\n'
                << "    DLL: " << def->dll_name;
      if (!def->dll_stamp.empty() || !def->dll_version.empty()) {
        std::cout << " (";
        if (!def->dll_stamp.empty()) {
          std::cout << def->dll_stamp;
        }
        if (!def->dll_version.empty()) {
          std::cout << '[' << def->dll_version << ']';
        }
        std::cout << ')';
      }
      std::cout << '\n'
                << "    Calling convention: " << def->calling_convention << '\n'
                << "    Return_type: " << def->return_type << '\n'
                << "    Parameters: ";
      bool first = true;
      for (auto & param : def->parameters) {
        if (first) {
          first = false;
        } else {
          std::cout << ", ";
        }
        if (param.type.empty()) {
          std::cout << "<unknown-type>";
        } else {
          std::cout << param.type;
        }
        if (!param.name.empty()) {
          std::cout << ' '  << param.name;
        }
        switch (param.direction) {
         case APIParam::NONE:
          break;
         case APIParam::IN:
          std::cout << "[in]";
          break;
         case APIParam::OUT:
          std::cout << "[out]";
          break;
         case APIParam::INOUT:
          std::cout << "[inout]";
          break;
        }
      }
      std::cout << '\n';
      if (def->stackdelta != std::numeric_limits<decltype(def->stackdelta)>::max()) {
        std::cout << "    Stack delta: " << def->stackdelta << '\n';
      }
      if (def->ordinal) {
        std::cout << "    Ordinal: " << def->ordinal << '\n';
      }
      std::cout << "    Source: " << def->source.describe() << '\n' << std::flush;
    }
  }
}

constexpr auto STACKDELTA_MAX =
  std::numeric_limits<decltype(APIDefinition::stackdelta)>::max();
constexpr auto RELATIVE_ADDRESS_MAX =
  std::numeric_limits<decltype(APIDefinition::relative_address)>::max();

void output_symbols(json::ArrayRef & arr, APIDefinitionList const & defs)
{
  auto & builder = arr->builder();
  for (auto & def : defs) {
    auto json_def = builder.object();
    auto add = [&json_def](char const * key, std::string const & value) {
      if (!value.empty()) {
        json_def->add(key, value);
      }
    };
    add("dll", def->dll_name);
    add("dll_version", def->dll_version);
    add("dll_stamp", def->dll_stamp);
    add("export_name", def->export_name);
    add("display_name", def->display_name);
    add("source" , def->source.describe());
    if (def->relative_address != RELATIVE_ADDRESS_MAX) {
      json_def->add("relative_address", addr_str(def->relative_address));
    }
    add("convention", def->calling_convention);
    add("type", def->return_type);
    if (def->ordinal) {
      json_def->add("ordinal", def->ordinal);
    }
    if (!def->parameters.empty()) {
      auto parr = builder.array();
      for (auto & param : def->parameters) {
        auto pob = builder.object();
        if (!param.name.empty()) {
          pob->add("name", param.name);
        }
        if (!param.type.empty()) {
          pob->add("type", param.type);
        }
        switch (param.direction) {
         case APIParam::NONE: break;
         case APIParam::IN: pob->add("inout", "in"); break;
         case APIParam::OUT: pob->add("inout", "out"); break;
         case APIParam::INOUT: pob->add("inout", "inout"); break;
        }
        parr->add(std::move(pob));
      }
      json_def->add("parameters", std::move(parr));
    } else if (def->stackdelta != STACKDELTA_MAX) {
      json_def->add("delta", def->stackdelta);
    } else {
      json_def->add("parameters", builder.array());
    }
    arr->add(std::move(json_def));
  }
}

int apilookup_main(int argc, char **argv) {
  // Handle options
  auto popt = options();
  popt.add(cert_standard_options());
  ProgPosOptDesc posopt;
  posopt.add("symbols", -1);
  auto vm = parse_cert_options(argc, argv, popt, "Inspect the API Database", posopt);
  auto apidb = APIDictionary::create_standard(vm);
  if (!vm.count("symbols")) {
    std::cout << "Usage: " << argv[0] << " [[DLL:]SYMBOL|DLL:ORDINAL]...\n"
              << "       " << argv[0] << " --regexp PATTERN [PATTERN...]\n"
              << '\n' << popt << std::endl;
    return EXIT_FAILURE;
  }

  bool as_regex = vm["regexp"].as<bool>();
  bool as_iregex = vm["case-insensitive-regexp"].as<bool>();
  if (as_regex && as_iregex) {
    using namespace boost::program_options::command_line_style;
    std::cerr << "The options "
              << popt.find("regexp", false).canonical_display_name(allow_long) << " and "
              << popt.find("case-insensitive-regexp", false).canonical_display_name(allow_long)
              << " are mutually exclusive" << std::endl;
    return EXIT_FAILURE;
  }

  json::ArrayRef json_records;
  std::unique_ptr<std::ofstream> json_fout;
  std::ostream * json_out = nullptr;
  auto & json = vm["json"];
  if (!json.empty()) {
    auto fname = json.as<bf::path>();
    if (fname.compare("-") == 0) {
      json_out = &std::cout;
    } else {
      json_fout = make_unique<std::ofstream>(fname.native());
      json_out = json_fout.get();
    }
    json_records = json::simple_builder()->array();
    if (vm.count("pretty-json")) {
      *json_out << json::pretty(vm["pretty-json"].as<unsigned>());
    }
  }

  for (auto & val : vm["symbols"].as<std::vector<std::string>>()) {
    APIDefinitionList defs;
    if (as_regex || as_iregex) {
      auto flags = regex::optimize | regex::ECMAScript;
      if (as_iregex) {
        flags |= regex::icase;
      }
      defs = apidb->get_api_definition(regex(val, flags));
    } else {
      size_t colon = val.find(':');
      std::string dll, sym;
      if (colon == std::string::npos) {
        sym = val;
      } else {
        dll = to_lower(val.substr(0, colon));
        if (dll.size() >= 4 && dll.compare(dll.size() - 4, 4, ".dll") == 0) {
          dll.erase(dll.size() - 4);
        }
        sym = val.substr(colon + 1);
      }
      if (dll.empty()) {
        defs = apidb->get_api_definition(sym);
      } else if (!sym.empty() &&
                 std::all_of(sym.begin(), sym.end(),
                             [](char c) { return std::isdigit(c); }))
      {
        size_t ordinal = std::stoull(sym);
        defs = apidb->get_api_definition(dll, ordinal);
      } else {
        defs = apidb->get_api_definition(dll, sym);
      }
    }
    if (json_records) {
      output_symbols(json_records, defs);
    } else {
      output_symbols(val, defs);
    }
  }

  if (json_records) {
    assert(json_out);
    (*json_out) << *json_records;
  }

  return EXIT_SUCCESS;
}

} // unnamed namespace

int main(int argc, char **argv)
{
  return pharos_main("APIL", apilookup_main, argc, argv, STDERR_FILENO);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
