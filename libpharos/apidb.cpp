// Copyright 2015-2022 Carnegie Mellon University.  See LICENSE file for terms.

#include <unordered_map>
#include <limits>
#include <algorithm>
#include <mutex>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop
#include "apidb.hpp"
#include "demangle.hpp"
#include "threads.hpp"
#include <sqlite3.h>
#include <boost/range/adaptor/map.hpp>

#if SQLITE_VERSION_NUMBER >= 3014000
#define SQLITE_TRACE_V2_EXISTS 1
#endif

namespace bf = boost::filesystem;

namespace pharos {

namespace {

using bf::is_directory;
using bf::weakly_canonical;
using boost::adaptors::values;
using boost::adaptors::keys;

using inout_map_t = std::map<std::string, APIParam::inout_t>;

inout_map_t create_inout_map()
{
  inout_map_t map;
  // These are our base names
  map["none"]  = APIParam::NONE;
  map["in"]    = APIParam::IN;
  map["out"]   = APIParam::OUT;
  map["inout"] = APIParam::INOUT;

  // These are from MSDN
  map["_In_"]  = APIParam::IN;
  map["_Out_"] = APIParam::OUT;
  map["_Inout_"] = APIParam::INOUT;
  map["_In_opt_"] = APIParam::IN;
  map["_Out_opt_"] = APIParam::OUT;
  map["_Inout_opt_"] = APIParam::INOUT;
  return map;
}

inout_map_t inout_map = create_inout_map();

using defkey_t = std::pair<std::string, std::string>;
using ordkey_t = std::pair<std::string, size_t>;

template <typename A, typename B>
struct pair_hash {
  std::hash<A> hash_a;
  std::hash<B> hash_b;
  size_t operator()(const std::pair<A, B> &key) const {
    return hash_a(key.first) + hash_b(key.second);
  }
};

using defhash = pair_hash<std::string, std::string>;
using ordhash = pair_hash<std::string, size_t>;
using defmap_t = std::unordered_multimap<defkey_t, APIDefinitionPtr, defhash>;
using ordmap_t = std::unordered_multimap<ordkey_t, APIDefinitionPtr, ordhash>;
using addrmap_t = std::unordered_multimap<rose_addr_t, APIDefinitionPtr>;

constexpr auto STACKDELTA_MAX =
  std::numeric_limits<decltype(APIDefinition::stackdelta)>::max();
constexpr auto RELATIVE_ADDRESS_MAX =
  std::numeric_limits<decltype(APIDefinition::relative_address)>::max();

} // unnamed namespace

Sawyer::Message::Facility APIDictionary::mlog;

APIDefinition::APIDefinition(APIDictionary const & src) :
  source(src),
  relative_address(RELATIVE_ADDRESS_MAX),
  stackdelta(STACKDELTA_MAX),
  ordinal(0)
{}

APIDefinitionList APIDictionary::get_api_definition(const std::string & func_name) const
{
  static auto escape_strings = std::regex(R":([.*+?[\](){}|^$\\]):");
  std::string escaped = std::regex_replace(func_name, escape_strings, "\\$&");
  return get_api_definition(regex("^" + escaped + "$"));
}

// This is essentially a macro used by all the MultiApiDictionary::get_api_definition
// definitions
template <typename... T>
APIDefinitionList MultiApiDictionary::_get_api_definition(T &&... args) const
{
  for (auto & dict : dicts) {
    auto result = dict->get_api_definition(std::forward<T>(args)...);
    if (!result.empty()) {
      return result;
    }
  }
  return APIDefinitionList();
}

APIDefinitionList MultiApiDictionary::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  return _get_api_definition(dll_name, func_name);
}

APIDefinitionList MultiApiDictionary::get_api_definition(
  const std::string & func_name) const
{
  APIDefinitionList list;
  std::unordered_map<std::string, std::unordered_set<ordkey_t, ordhash>> map;
  for (auto & dict : dicts) {
    auto results = dict->get_api_definition(func_name);
    for (auto & def : results) {
      auto & funcs = map[def->dll_name];
      auto result = funcs.emplace(func_name, def->ordinal);
      if (result.second) {
        list.emplace_back(def);
      }
    }
  }
  return list;
}

APIDefinitionList MultiApiDictionary::get_api_definition(
  const regex & func_name) const
{
  APIDefinitionList list;
  for (auto & dict : dicts) {
    auto results = dict->get_api_definition(func_name);
    std::move(results.begin(), results.end(), std::back_inserter(list));
  }
  return list;
}

APIDefinitionList MultiApiDictionary::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  return _get_api_definition(dll_name, ordinal);
}

APIDefinitionList MultiApiDictionary::get_api_definition(rose_addr_t addr) const
{
  return _get_api_definition(addr);
}

bool MultiApiDictionary::handles_dll(std::string const & dll_name) const
{
  for (auto & dict : dicts) {
    if (dict->handles_dll(dll_name)) {
      return true;
    }
  }
  return false;
}

std::string MultiApiDictionary::describe() const
{
  std::ostringstream os;
  os << "API database multi wrapper {";
  auto b = std::begin(dicts);
  for (auto i = b; i != std::end(dicts); ++i) {
    if (i != b) os << ", ";
    os << (*i)->describe();
  }
  os << '}';
  return os.str();
}

struct JSONApiDictionary::Data {
  defmap_t defmap;
  ordmap_t ordmap;
  addrmap_t addrmap;
  bool load_on_demand;
  std::unordered_map<std::string, bool> loaded_files;
};

// These need to be defined in the cpp file and not the header, because the definition of the
// Data struct is needed first
JSONApiDictionary::~JSONApiDictionary() = default;
JSONApiDictionary::JSONApiDictionary(JSONApiDictionary &&) noexcept = default;
JSONApiDictionary &JSONApiDictionary::operator=(JSONApiDictionary &&) = default;

JSONApiDictionary::JSONApiDictionary(const std::string & path_)
  : data(new Data()), path(path_)
{
  data->load_on_demand = is_directory(path);
  if (!data->load_on_demand) {
    load_json(path);
  }
}

JSONApiDictionary::JSONApiDictionary(const YAML::Node & exports) : data(new Data())
{
  data->load_on_demand = false;
  load_json(exports);
}

namespace {
inline std::string normalize_dll(const std::string &dll) {
  std::string name = to_lower(dll);
  if (dll.size() >= 4 && name.compare(dll.size() - 4, 4, ".dll") == 0) {
    name.erase(dll.size() - 4);
  }
  return name;
}
} // unnamed namespace


bool APIDictionary::handle_node(MultiApiDictionary & db, const YAML::Node & node,
                                bool top, handle_error_t handle)
{
  auto add = [&db](std::unique_ptr<APIDictionary> && dict) {
    auto complain = make_unique<ReportDictionary>(std::move(dict), dict->describe());
    complain->dll_error_log(mlog[Sawyer::Message::WHERE])
      .fn_error_log(mlog[Sawyer::Message::WHERE])
      .fn_success_log(mlog[Sawyer::Message::TRACE])
      .fn_detail_log(mlog[Sawyer::Message::DEBUG]);
    db.add(std::move(complain));
  };

  switch (node.Type()) {
   case YAML::NodeType::Scalar:
    // Interpret a simple string as a path to api information.
    {
      auto path = bf::path(node.Scalar());
      if (!path.has_root_directory()) {
        // Relative paths will be considered relative to the library path.
        path = get_library_path() / path;
      }
      if (is_directory(path)) {
        // Assume the directory contains per-DLL json files
        auto jsondb = make_unique<JSONApiDictionary>(path.native());
        assert(jsondb);
        add(std::move(jsondb));
        return true;
      }
      try {
        // Determine whether this is a sqlite file or a json file
        std::ifstream file(path.native());
        if (!file) {
          throw std::runtime_error("Could not open for read");
        }

        // Read the first few bytes to see of the file match the SQLite magic prologue
        static constexpr char sqlite_magic[] = "SQLite";
        constexpr auto len = sizeof(sqlite_magic) - 1;
        char prologue[len];
        file.read(prologue, len);
        bool correct_size = file.gcount() == len;
        file.close();
        if (!(correct_size && std::equal(prologue, prologue + len, sqlite_magic))) {
          // Assume json
          auto jsondb = make_unique<JSONApiDictionary>(path.native());
          assert(jsondb);
          add(std::move(jsondb));
        } else {
          // SQLite
          auto sql = make_unique<SQLLiteApiDictionary>(path.native());
          assert(sql);
          auto cached_sql = make_unique<DLLStateCacheDict>(std::move(sql));
          assert(cached_sql);
          add(std::move(cached_sql));
        }
        return true;
      } catch (const std::runtime_error & e) {
        std::ostringstream os;
        os << "Unable to load API database: " << path << '\n'
           << "Reason: " << e.what();
        switch (handle) {
         case IGNORE:
          break;
         case LOG_WARN:
          MWARN << os.str() << LEND;
          break;
         case LOG_ERROR:
          MERROR << os.str() << LEND;
          break;
         case THROW:
          throw std::runtime_error(os.str());
        }
        return false;
      }
    }
   case YAML::NodeType::Sequence:
    // A sequence is a list of API db locations as long as this is a top-level sequence
    if (top) {
      bool all_success = true;
      for (auto item : node) {
        all_success &= handle_node(db, item, false, handle);
      }
      return all_success;
    }
    // falls through
    // becomes [[fallthrough]]; in c++17
   case YAML::NodeType::Map:
    try {
      // A map or sequence is an inline set of API information
      auto jsondb = make_unique<JSONApiDictionary>(node);
      add(std::move(jsondb));
      return true;
    } catch (const std::runtime_error & e) {
      switch (handle) {
       case IGNORE:
        break;
       case LOG_WARN:
       case LOG_ERROR:
        {
          auto & err = mlog[(handle == LOG_WARN)
                            ? Sawyer::Message::WARN : Sawyer::Message::ERROR];
          err && err << "Error in API database\n"
                     << "Reason: " << e.what() << LEND;
        }
        break;
       case THROW:
        throw;
      }
      return false;
    }
   default:
    throw std::runtime_error("Illegal type of node in pharos.apidb parsing");
  }
}

boost::optional<std::string> APIDictionary::verify_args(const ProgOptVarMap & vm) {
  if (vm.count("apidb")) {
    for (auto const & path : vm["apidb"].as<std::vector<bf::path>>()) {
      auto loc = weakly_canonical(path);
      if (!loc.has_root_directory()) {
        loc = get_library_path() / path;
      }
      if (is_directory(loc)) {
        // XXX: Well, the directory exists.  We should maybe walk through and make sure the
        // files are readable?
      } else {
        try {
          // Open the file to make sure we can.
          bf::ifstream file;
          file.exceptions(bf::ifstream::failbit |
                          bf::ifstream::badbit);
          file.open(loc);
          file.close();
        } catch (const std::ios_base::failure &e) {
          // Maybe we should return the exception too, but they generally don't have useful
          // messages.
          return loc.native ();
        }
      }
    }
  }

  return boost::none;
}

std::unique_ptr<APIDictionary> APIDictionary::create_standard(
  const ProgOptVarMap &vm,
  handle_error_t handle)
{
  auto multidb = make_unique<MultiApiDictionary>();
  assert(multidb);

  if (vm.count("apidb")) {
    // If it's listed on the command line, use that.
    for (auto & filename : vm["apidb"].as<std::vector<bf::path>>()) {
      // Try to resolve with respect to CWD
      auto loc = weakly_canonical(filename).native();
      handle_node(*multidb, YAML::Node(loc), false, THROW);
    }
  }

  auto db_path = vm.config().path_get("pharos.apidb");
  if (!db_path) {
    // For backwards compatibility
    db_path = vm.config().path_get("pharos.sqlite_apidb");
  }
  if (db_path) {
    // A config.yaml entry exists
    handle_node(*multidb, db_path.as_node(), true, handle);
  }

  // Add decorated name fallback
  auto decorated = make_unique<DecoratedDictionary>();
  assert(decorated);
  auto cdecorated = make_unique<ReportDictionary>(std::move(decorated), decorated->describe());
  assert(cdecorated);
  cdecorated->dll_error_log(mlog[Sawyer::Message::WHERE])
    .fn_error_log(mlog[Sawyer::Message::WHERE])
    .fn_success_log(mlog[Sawyer::Message::TRACE])
    .fn_detail_log(mlog[Sawyer::Message::DEBUG]);
  multidb->add(std::move(cdecorated));

  // Add a failure logging layer
  auto complainer = make_unique<ReportDictionary>(std::move(multidb));
  assert(complainer);
  complainer->dll_error_log(mlog[Sawyer::Message::WARN])
    .fn_error_log(mlog[Sawyer::Message::WARN])
    .fn_request_log(mlog[Sawyer::Message::TRACE]);
  return complainer;
}

void JSONApiDictionary::load_json(const std::string &filename) const
{
  auto json = YAML::LoadFile(filename);
  if (json.IsSequence()) {
    // If this is a sequence, assume that is the API data
    load_json(json);
  } else if (json.IsMap()) {
    // If this is a map, the data should be under config.exports
    auto exports = json["config"]["exports"];
    if (exports) {
      load_json(exports);
    }
  } else {
    throw std::runtime_error("File is not a sequence or map: " + filename);
  }
}

void JSONApiDictionary::load_json(const YAML::Node & exports) const
{
  // loop over each entry
  bool is_map = exports.Type() == YAML::NodeType::Map;
  for (auto node : exports) {
    auto fd = std::make_shared<APIDefinition>(*this);
    decltype(node) fn_node;

    if (is_map) {
      // Use the name of the key as the function's name information
      const std::string &conjoined_name = node.first.Scalar();
      size_t colon = conjoined_name.find(':');
      if (colon != std::string::npos) {
        fd->dll_name = normalize_dll(conjoined_name.substr(0, colon));
        fd->export_name = conjoined_name.substr(colon + 1);
      } else {
        fd->export_name = conjoined_name;
      }
      fn_node.reset(node.second);
    } else {
      fn_node.reset(node);
    }

    // mwd TODO: What should we do if the following assert fails?
    // assert(fn_node.Type() == YAML::NodeType::Map);

    // Collapse anything in "function" into the main map
    auto function_block = fn_node["function"];
    if (function_block && function_block.Type() == YAML::NodeType::Map) {
      for (auto n : function_block) {
        fn_node[n.first] = n.second;
      }
    }

    // Handle the primary key values
    auto dll = fn_node["dll"];
    if (dll) {
      fd->dll_name = normalize_dll(dll.Scalar());
    }
    auto export_name = fn_node["export_name"];
    if (export_name) {
      fd->export_name = export_name.Scalar();
    }
    auto display_name = fn_node["display_name"];
    if (display_name) {
      fd->display_name = display_name.Scalar();
    }
    auto relative_address = fn_node["relative_address"];
    if (relative_address) {
      fd->relative_address = relative_address.as<rose_addr_t>();
    }

    // Calling convention
    auto convention = fn_node["convention"];
    if (convention) {
      fd->calling_convention = convention.Scalar();
    }

    // Parameters and stackdeltas
    auto params = fn_node["parameters"];
    if (params) {
      // When given a parameter list, use this
      for (auto param : params) {
        auto namenode = param["name"];
        auto typenode = param["type"];
        auto inoutnode = param["inout"];
        APIParam val;
        if (namenode) {
          val.name = namenode.Scalar();
        }
        if (typenode) {
          val.type = typenode.Scalar();
        }
        val.direction = APIParam::NONE;
        if (inoutnode) {
          inout_map_t::const_iterator found = inout_map.find(inoutnode.Scalar());
          if (found != inout_map.end()) {
            val.direction = found->second;
          }
        }
        fd->parameters.push_back(std::move(val));
      }
      if (fd->calling_convention == "stdcall") {
        // mwd TODO: handle 64-bit properly
        // Should use get_arch_bytes()!
        fd->stackdelta = fd->parameters.size() * 4;
      }
    } else {
      // No explicit parameter list.  Try to guess.
      auto delta = fn_node["delta"];
      if (delta) {
        fd->stackdelta = delta.as<size_t>();
        assert(fd->stackdelta % 4 == 0);
      }
      // Old-style hack to set number of parameters even when delta is zero
      auto hack_params = fn_node["parameter"];
      if (hack_params) {
        size_t val = hack_params.as<size_t>();
        assert(val % 4 == 0);
        fd->parameters.resize(val / 4);
      } else if (fd->calling_convention == "stdcall") {
        // mwd TODO: handle 64-bit properly
        // Should use get_arch_bytes()!
        assert(fd->stackdelta % 4 == 0);
        fd->parameters.resize(fd->stackdelta / 4);
      }
    }

    // Return type
    auto rettype = fn_node["type"];
    if (rettype) {
      fd->return_type = rettype.Scalar();
    }

    // Ordinal
    auto ordinal = fn_node["ordinal"];
    if (ordinal) {
      fd->ordinal = ordinal.as<size_t>();
    }

    // Ensure there is always a display name
    if (fd->display_name.empty()) {
      if (!fd->export_name.empty()) {
        try {
          auto type = demangle::visual_studio_demangle(fd->export_name);
          if (type) {
            fd->display_name = type->str();
          } else {
            fd->display_name = fd->export_name;
          }
        } catch (const demangle::Error &) {
          fd->display_name = fd->export_name;
        }
      } else if (fd->relative_address != RELATIVE_ADDRESS_MAX) {
        std::ostringstream os;
        os << "sub_" << std::hex << fd->relative_address;
        fd->display_name = os.str();
      } else {
        static uint64_t count = 0;
        std::ostringstream os;
        os << "<anonymous function " << count++ << '<';
        fd->display_name = os.str();
      }
    }

    // Once the APIDefinition has been made, add it to the maps
    std::string dll_name = fd->dll_name;
    defkey_t defkey(dll_name, fd->get_name());
    data->defmap.emplace(std::move(defkey), fd);
    size_t ord = fd->ordinal;
    if (ord) {
      ordkey_t ordkey(std::move(dll_name), ord);
      data->ordmap.emplace(std::move(ordkey), fd);
    }
    if (fd->relative_address != RELATIVE_ADDRESS_MAX) {
      data->addrmap.emplace(fd->relative_address, fd);
    }

  } // for (auto node : exports)
}

bool JSONApiDictionary::handles_dll(std::string const & dll_name_) const
{
  auto dll_name = normalize_dll(dll_name_);
  if (data->load_on_demand) {
    return known_dll(dll_name);
  }

  auto rdef = keys(data->defmap);
  auto rord = keys(data->ordmap);
  return (std::any_of(begin(rdef), end(rdef),
                      [&dll_name](defkey_t const & x) {return x.first == dll_name;})
          || std::any_of(begin(rord), end(rord),
                         [&dll_name](ordkey_t const & x) {return x.first == dll_name;}));
}

std::string JSONApiDictionary::describe() const
{
  if (data->load_on_demand) {
    return "JSON API database directory " + path;
  } else {
    return "JSON API database " + path;
  }
}

// pre-condition: dll_name is normalized
bool JSONApiDictionary::known_dll(const std::string & dll_name) const
{
  if (!data->load_on_demand) {
    return true;
  }

  auto found = data->loaded_files.find(dll_name);
  if (found != data->loaded_files.end()) {
    return found->second;
  }

  // Load the json file
  std::string filename = path + "/" + dll_name + ".json";
  bool succeeded = false;
  try {
    load_json(filename);
    succeeded = true;
    MINFO << "Loaded API database json file: " << filename << LEND;
  } catch (...) {
    MDEBUG << "Unable to load API database json file: " << filename << LEND;
  }
  data->loaded_files[dll_name] = succeeded;
  return succeeded;
}

APIDefinitionList
JSONApiDictionary::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  defkey_t key(normalize_dll(dll_name), func_name);
  if (!known_dll(key.first)) {
    return APIDefinitionList();
  }
  auto found = values(data->defmap.equal_range(key));
  return APIDefinitionList(begin(found), end(found));
}

APIDefinitionList
JSONApiDictionary::get_api_definition(
  const regex & func_name) const
{
  APIDefinitionList list;
  if (!data->load_on_demand) {
    for (auto & entry : data->defmap) {
      if (std::regex_search(entry.first.second, func_name, std::regex_constants::match_any)) {
        list.emplace_back(entry.second);
      }
    }
  }
  return list;
}

APIDefinitionList
JSONApiDictionary::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  ordkey_t key(normalize_dll(dll_name), ordinal);
  if (!known_dll(key.first)) {
    return APIDefinitionList();
  }
  auto found = values(data->ordmap.equal_range(key));
  return APIDefinitionList(begin(found), end(found));
}

APIDefinitionList
JSONApiDictionary::get_api_definition(rose_addr_t addr) const
{
  auto found = values(data->addrmap.equal_range(addr));
  return APIDefinitionList(begin(found), end(found));
}

struct SQLLiteApiDictionary::Data {
  mutable std::recursive_mutex mutex;
  using lock_guard = std::lock_guard<decltype(mutex)>;

  static Sawyer::Message::Facility mlog;
  static Sawyer::Message::Facility & initDiagnostics();
#if SQLITE_TRACE_V2_EXISTS
  static int log_sql(unsigned typ, void *, void *p, void *) {
    if (typ == SQLITE_TRACE_STMT && mlog[Sawyer::Message::DEBUG]) {
      sqlite3_stmt *stm = reinterpret_cast<sqlite3_stmt *>(p);
      char *stmt = sqlite3_expanded_sql(stm);
      if (stmt) {
        mlog[Sawyer::Message::DEBUG] << stmt << std::endl;
        sqlite3_free(stmt);
      }
    }
    return 0;
  }
#else
  static void log_sql(void *, char const *stmt) {
    if (mlog[Sawyer::Message::DEBUG]) {
      mlog[Sawyer::Message::DEBUG] << stmt << std::endl;
    }
  }
#endif

  void enable_trace() {
    if (mlog[Sawyer::Message::DEBUG]) {
#if SQLITE_TRACE_V2_EXISTS
      sqlite3_trace_v2(db, SQLITE_TRACE_STMT, log_sql, nullptr);
#else
      sqlite3_trace(db, log_sql, nullptr);
#endif
    }
  }

  static std::int64_t next_regex_index;
  static std_mutex regex_mutex;
  static std::map<int, regex const *> regex_map;
  static void regexp(sqlite3_context * ctx, int, sqlite3_value **args);

  enum version_t {
    V0, V1, V2, V4, V5, VERSION_COUNT
  };

  enum query_type_t {
    NAME_TYPE, ORDINAL_TYPE, QUERY_TYPE_COUNT
  };

  static constexpr int ROWID = 0;
  static constexpr int ORDINAL = 1;
  static constexpr int EXPORT_NAME = 2;
  static constexpr int DISPLAY_NAME = 3;
  static constexpr int CALLING_CONVENTION = 4;
  static constexpr int RETURN_TYPE = 5;
  static constexpr int PARAMS_KNOWN = 6;
  static constexpr int ALIAS_ID = 7;
  static constexpr int DLL_NAME = 8;
  static constexpr int VERSION = 9;
  static constexpr int STAMP = 10;

  // Which columns to fetch during function lookup
  static constexpr char const * select_function_columns[VERSION_COUNT] = {
    ("rowId, ordinal, name, canonical, callingConvention, returnType, 1, NULL, NULL, NULL, "
     "NULL"),
    ("rowId, ordinal, name, canonical, callingConvention, returnType, paramsKnown, NULL, "
     "NULL, NULL, NULL"),
    ("f.rowId, o.ordinal, f.exportName, f.displayName, f.callingConvention, "
     "f.returnType, f.paramsKnown, f.aliasId, s.displayName, NULL, NULL"),
    ("DISTINCT f.rowId, o.ordinal, n.exportName, n.displayName, f.callingConvention, "
     "f.returnType, f.paramsKnown, NULL, s.displayName, NULL, sm.timeStamp"),
    ("DISTINCT f.rowId, o.ordinal, n.exportName, n.displayName, f.callingConvention, "
     "f.returnType, f.paramsKnown, NULL, s.displayName, sm.version, sm.timeStamp"),
  };

  // Which tables to look through during function lookup
  static constexpr char const * FT_a = "FROM function";
  static constexpr char const * select_function_tables[VERSION_COUNT][QUERY_TYPE_COUNT] = {
    {FT_a, FT_a},
    {FT_a, FT_a},
    {("FROM function AS f "
      "LEFT JOIN ordinal AS o ON f.rowId = o.functionId "
      "INNER JOIN source AS s ON f.sourceId = s.rowId"),
     ("FROM function AS f "
      "INNER JOIN ordinal AS o ON f.rowId = o.functionId "
      "INNER JOIN source AS s ON f.sourceId = s.rowId")},
    {("FROM name AS n "
      "INNER JOIN function AS f ON f.rowId = n.functionId "
      "INNER JOIN sourcedll AS s ON s.rowId = n.dllId "
      "INNER JOIN sourcemeta AS sm ON sm.sourceId = s.rowId "
      "LEFT JOIN ordinal AS o ON o.functionId = f.rowId AND o.sourceMetaId = sm.rowId"),
     ("FROM ordinal AS o "
      "INNER JOIN function AS f ON f.rowId = o.functionId "
      "INNER JOIN sourcemeta AS sm ON sm.rowId = o.sourceMetaId "
      "INNER JOIN sourcedll AS s ON s.rowId = sm.sourceId "
      "LEFT JOIN name AS n ON f.rowId = n.functionId")},
    {("FROM apiname AS n "
      "INNER JOIN apifunction AS f ON f.rowId = n.apiFunctionId "
      "INNER JOIN dllname AS s ON s.rowId = n.dllNameId "
      "INNER JOIN dllmeta AS sm ON sm.dllNameId = s.rowId "
      "LEFT JOIN apiordinal AS o ON o.apiFunctionId = f.rowId AND o.dllMetaId = sm.rowId"),
     ("FROM apiordinal AS o "
      "INNER JOIN apifunction AS f ON f.rowId = o.apiFunctionId "
      "INNER JOIN dllmeta AS sm ON sm.rowId = o.dllMetaId "
      "INNER JOIN dllname AS s ON s.rowId = sm.dllNameId "
      "LEFT JOIN apiname AS n ON f.rowId = n.apiFunctionId")
    }
  };


  // Select by name SQL condition
  static constexpr char const * SN_a = "dll = ?1 AND name = ?2";
  static constexpr char const * SN_b = "s.normalizedName = ?1 AND n.exportName = ?2";
  static constexpr char const * select_by_name_condition[VERSION_COUNT] = {
    SN_a, SN_a,
    "s.normalizedName = ?1 AND f.exportName = ?2",
    SN_b, SN_b
  };

  // Select by ordinal SQL condition
  static constexpr char const * ON_a = "dll = ?1 AND ordinal = ?2";
  static constexpr char const * ON_b = "s.normalizedName = ?1 AND o.ordinal = ?2";
  static constexpr char const * select_by_ordinal_condition[VERSION_COUNT] = {
    ON_a, ON_a, ON_b, ON_b, ON_b
  };

  // Select by name only SQL condition
  static constexpr char const * NO_a = "name = ?1";
  static constexpr char const * NO_b = "n.exportName = ?1";
  static constexpr char const * select_by_name_only_condition[VERSION_COUNT] = {
    NO_a, NO_a,
    "f.exportName = ?1",
    NO_b, NO_b
  };

  // Select by name regexp SQL condition
  static constexpr char const * NR_a = "match(?1, name)";
  static constexpr char const * NR_b = "match(?1, n.exportName)";
  static constexpr char const * select_by_name_regexp_condition[VERSION_COUNT] = {
    NR_a, NR_a,
    "match(?1, f.exportName)",
    NR_b, NR_b
  };

  // Select by row condition
  static constexpr char const * RC = "f.rowId = ?1";
  static constexpr char const * select_by_row_condition[VERSION_COUNT] = {
    &RC[2], &RC[2], RC, RC, RC
  };

  // DLL exists query
  static constexpr char const * DLLE_a = "SELECT 1 FROM function WHERE dll = ?1 LIMIT 1";
  static constexpr char const * select_dll_exists[VERSION_COUNT] = {
    DLLE_a, DLLE_a,
    "SELECT 1 FROM source WHERE normalizedName = ?1 LIMIT 1",
    "SELECT 1 FROM sourcedll WHERE normalizedName = ?1 LIMIT 1",
    "SELECT 1 FROM dllname WHERE normalizedName = ?1 LIMIT 1"
  };

  static constexpr int PARAM_NAME = 0;
  static constexpr int PARAM_TYPE = 1;
  static constexpr int PARAM_INOUT = 2;
  static constexpr int PARAM_POSITION = 3;

  // Select statement to look up a function's parameters.  Ordered descending to get the count
  // of params up front from the position parameter
  static constexpr char const * SP_a =
    "SELECT name, type, inOut, position FROM parameter"
    " WHERE functionId = ?1 ORDER BY position DESC";
  static constexpr char const * select_params[VERSION_COUNT] = {
    SP_a, SP_a, SP_a, SP_a,
    ("SELECT name, type, inOut, position FROM apiparameter"
     " WHERE apiFunctionId = ?1 ORDER BY position DESC")
  };

  static constexpr char const select_version[] =
    "SELECT dbVer FROM metadata";

  // Throw an error based on an error code
  [[noreturn]] static void throw_error(int code);
  // Throw an error based on the state of the db
  [[noreturn]] void throw_error() const;

  std::string build_function_query(query_type_t qt, char const * const * condition) {
    int idx = static_cast<int>(version);
    return build_function_query(qt, condition[idx]);
  }

  std::string build_function_query(query_type_t qt, char const * condition) {
    int v_idx = static_cast<int>(version);
    int t_idx = static_cast<int>(qt);
    return (std::string("SELECT ") + select_function_columns[v_idx] + " "
            + select_function_tables[v_idx][t_idx] + " WHERE " + condition);
  }

  // Throw an error based on the code if the code isn't OK
  static void maybe_throw_code(int code);
  // Throw an error based on the db if the code isn't OK
  void maybe_throw(int code) const;

  // Load the db at filename
  Data(APIDictionary const & parent, const std::string & filename);
  ~Data();

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, const std::string & func_name) const;

  APIDefinitionList
  get_api_definition(
    const std::string & func_name) const;

  APIDefinitionList
  get_api_definition(
    const regex & func_name) const;

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, size_t ordinal) const;

  APIDefinitionList
  get_db_function(
    sqlite3_stmt * lookup) const;

  bool handles_dll(std::string const & dll_name) const;


  sqlite3 * db = nullptr;
  sqlite3_stmt * lookup_by_id = nullptr;
  sqlite3_stmt * lookup_by_name = nullptr;
  sqlite3_stmt * lookup_by_name_only = nullptr;
  sqlite3_stmt * lookup_all_names = nullptr;
  sqlite3_stmt * lookup_by_row = nullptr;
  sqlite3_stmt * lookup_params = nullptr;
  sqlite3_stmt * lookup_dll_exists = nullptr;
  mutable defmap_t defmap;
  mutable ordmap_t ordmap;
  version_t version;
  APIDictionary const & parent;
};

Sawyer::Message::Facility SQLLiteApiDictionary::Data::mlog;

Sawyer::Message::Facility & SQLLiteApiDictionary::Data::initDiagnostics()
{
  static bool initialized = false;
  if (!initialized) {
    mlog.initialize("APSQ");
    mlog.initStreams(get_logging_destination());
    Sawyer::Message::mfacilities.insert(mlog);
    initialized = true;
  }
  return mlog;
}

void SQLLiteApiDictionary::Data::regexp(sqlite3_context * ctx, int, sqlite3_value **args)
{
  assert(sqlite3_value_type(args[0]) == SQLITE_INTEGER);
  assert(sqlite3_value_type(args[1]) == SQLITE3_TEXT);
  auto str = reinterpret_cast<const char *>(sqlite3_value_text(args[1]));
  auto pattern_idx = sqlite3_value_int64(args[0]);
  regex const *pattern;
  {
    write_guard<decltype(regex_mutex)> guard(regex_mutex);
    pattern = regex_map.at(pattern_idx);
  }
  int result = std::regex_search(str, *pattern);
  sqlite3_result_int(ctx, result);
}

// The definitions of these have to exist, per the standard.
constexpr char const * SQLLiteApiDictionary::Data::select_function_columns[];
constexpr char const * SQLLiteApiDictionary::Data::select_function_tables[][QUERY_TYPE_COUNT];
constexpr char const * SQLLiteApiDictionary::Data::select_by_name_condition[];
constexpr char const * SQLLiteApiDictionary::Data::select_by_name_only_condition[];
constexpr char const * SQLLiteApiDictionary::Data::select_by_name_regexp_condition[];
constexpr char const * SQLLiteApiDictionary::Data::select_by_ordinal_condition[];
constexpr char const * SQLLiteApiDictionary::Data::select_by_row_condition[];
constexpr char const * SQLLiteApiDictionary::Data::select_dll_exists[];
constexpr char const * SQLLiteApiDictionary::Data::select_params[];
constexpr char const SQLLiteApiDictionary::Data::select_version[];
std::int64_t SQLLiteApiDictionary::Data::next_regex_index = 0;
std_mutex SQLLiteApiDictionary::Data::regex_mutex;
std::map<int, regex const *> SQLLiteApiDictionary::Data::regex_map;


inline void SQLLiteApiDictionary::Data::throw_error(int code)
{
  throw SQLError(sqlite3_errstr(code));
}

inline void SQLLiteApiDictionary::Data::throw_error() const
{
  throw SQLError(sqlite3_errmsg(db));
}

inline void SQLLiteApiDictionary::Data::maybe_throw_code(int code)
{
  if (code != SQLITE_OK) {
    throw_error(code);
  }
}

inline void SQLLiteApiDictionary::Data::maybe_throw(int code) const
{
  switch (code) {
   case SQLITE_OK:
    break;
   case SQLITE_MISUSE:
    // If the call was misused, we can't count on the db.  Use only the code.
    throw_error(code);
    break;
   default:
    throw_error();
  }
}

SQLLiteApiDictionary::Data::Data(APIDictionary const & p, const std::string & filename) :
  parent(p)
{
  // Open the db
  try {
    constexpr auto flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX;
    maybe_throw_code(sqlite3_open_v2(filename.c_str(), &db, flags, nullptr));
    enable_trace();
  } catch (const SQLError &) {
    GERROR << "Unable to read API Database \"" << filename << '\"' << LEND;
    throw;
  }

  // Install the regexp routine
  maybe_throw(sqlite3_create_function_v2(db, "match", 2, SQLITE_UTF8, nullptr,
                                         regexp, nullptr, nullptr, nullptr));

  // query preparation helper
  auto prepare = [this](std::string const & query, sqlite3_stmt *& stmt) {
    MDEBUG << "Preparing query: " << query << std::endl;
    maybe_throw(sqlite3_prepare_v2(db, query.c_str(), query.size(), &stmt, nullptr));
  };

  // Determine the version
  sqlite3_stmt * lookup_version = nullptr;
  prepare(select_version, lookup_version);
  auto deleter = [](sqlite3_stmt *s) { sqlite3_finalize(s); };
  std::unique_ptr<sqlite3_stmt, decltype(deleter)> version_guard(lookup_version, deleter);
  int rv;
  do {
    rv = sqlite3_step(lookup_version);
    switch (rv) {
     case SQLITE_BUSY:
      break;
     case SQLITE_ROW:
      {
        const char * raw_version = reinterpret_cast<const char *>(
          sqlite3_column_text(lookup_version, 0));
        if (!raw_version) {
          throw SQLError("Database does not contain version");
        }
        Version v(raw_version);
        if (v < Version{1}) {
          throw SQLError("Database does not contain known version");
        } else if (v < Version{1,1}) {
          version = V0;
        } else if (v < Version{2}) {
          // Version 1.1 added the paramsKnown field
          version = V1;
        } else if (v < Version{4}) {
          // Version 2.0 added the aliasId field and renamed the canonical and name fields
          version = V2;
        } else if (v < Version{5}) {
          // Version 4.0 changed the way aliases are handled and added source tables
          version = V4;
        } else {
          // Version 5.0 added dll version information
          version = V5;
        }
      }
      break;
     case SQLITE_DONE:
      // Original database was often missing the version information
      version = V0;
      break;
     default:
      throw_error();
    }
  } while (rv == SQLITE_BUSY);

  // Prepare the select statements
  std::string name_query = build_function_query(NAME_TYPE, select_by_name_condition);
  std::string name_only_query = build_function_query(NAME_TYPE, select_by_name_only_condition);
  std::string all_names_query = build_function_query(
    NAME_TYPE, select_by_name_regexp_condition);
  std::string ordinal_query = build_function_query(ORDINAL_TYPE, select_by_ordinal_condition);
  std::string dll_exists_query = select_dll_exists[static_cast<int>(version)];
  std::string row_query = build_function_query(NAME_TYPE, select_by_row_condition);
  std::string params_query = select_params[static_cast<int>(version)];
  prepare(name_query, lookup_by_name);
  prepare(name_only_query, lookup_by_name_only);
  prepare(all_names_query, lookup_all_names);
  prepare(ordinal_query, lookup_by_id);
  prepare(row_query, lookup_by_row);
  prepare(params_query, lookup_params);
  prepare(dll_exists_query, lookup_dll_exists);
}

SQLLiteApiDictionary::Data::~Data()
{
  // All statments must be finalized before closing the db
  auto cleanup = [](sqlite3_stmt * & stmt) {
    UNUSED int rv = sqlite3_finalize(stmt);
    assert(rv == SQLITE_OK);
    stmt = nullptr;
  };
  cleanup(lookup_by_id);
  cleanup(lookup_by_name);
  cleanup(lookup_by_name_only);
  cleanup(lookup_all_names);
  cleanup(lookup_by_row);
  cleanup(lookup_params);
  cleanup(lookup_dll_exists);

  // Close the db
  UNUSED int rv = sqlite3_close_v2(db);
  assert(rv == SQLITE_OK);
  db = nullptr;
}

APIDefinitionList
SQLLiteApiDictionary::Data::get_db_function(
  sqlite3_stmt * lookup) const
{
  int rv;

  // Generate a function for a statement that extracts text strings from that statement,
  // accounting for possible NULLs
  auto create_textval = [this](sqlite3_stmt * stm) {
    return [this, stm](int col) {
      if (sqlite3_column_type(stm, col) == SQLITE_NULL) {
        return std::string();
      } else {
        // cast converts from const unsigned char * to const char *
        const char *text = reinterpret_cast<const char *>(sqlite3_column_text(stm, col));
        if (text == nullptr) {
          // Unexpected nullptr, check for error
          maybe_throw_code(sqlite3_errcode(db));
          // No error found
          return std::string();
        }
        return std::string(text, sqlite3_column_bytes(stm, col));
      }
    };
  };

  std::string export_name;
  std::string display_name;
  sqlite3_stmt * current_lookup = lookup;

  APIDefinitionList list;
  while (true) {
    // Look the function up in the db
    bool done = false;
    do {
      rv = sqlite3_step(current_lookup);
      switch (rv) {
       case SQLITE_BUSY:
       case SQLITE_ROW:
        // Continue if we found it, or are busy
        break;
       case SQLITE_DONE:
        if (current_lookup == lookup) {
          done = true;
        } else {
          current_lookup = lookup;
        }
        break;
       default:
        // Otherwise, error
        throw_error();
      }
    } while (rv == SQLITE_BUSY);

    if (done) {
      break;
    }

    if (current_lookup == lookup) {
      // Take the names from the first look-up, not from any alias look-ups
      auto id_textval = create_textval(lookup);
      export_name = id_textval(EXPORT_NAME);
      display_name = id_textval(DISPLAY_NAME);
    }
    if (sqlite3_column_type(current_lookup, ALIAS_ID) == SQLITE_NULL) {
      // Don't return a definition if we don't have useful parameter information
      if (sqlite3_column_int(lookup, PARAMS_KNOWN)) {
        // Create a definition
        auto fd = std::make_shared<APIDefinition>(parent);
        auto &def = *fd;
        auto textval = create_textval(current_lookup);
        auto rowid = sqlite3_column_int64(current_lookup, ROWID);
        def.ordinal = sqlite3_column_int64(current_lookup, ORDINAL);
        def.calling_convention = textval(CALLING_CONVENTION);
        def.return_type = textval(RETURN_TYPE);
        def.dll_name = textval(DLL_NAME);
        static const char dll_suffix[] = {'l', 'l', 'd', '.'};
        if (def.dll_name.size() > sizeof(dll_suffix)) {
          auto e = dll_suffix + sizeof(dll_suffix);
          if (std::equal(dll_suffix, e, def.dll_name.rbegin(),
                         [](char a, char b) { return a == std::tolower(b); }))
          {
            def.dll_name.resize(def.dll_name.size() - sizeof(dll_suffix));
          }
        }
        def.dll_version = textval(VERSION);
        def.dll_stamp = textval(STAMP);
        def.export_name = std::move(export_name);
        if (display_name.empty()) {
          def.display_name = def.export_name;
        } else {
          def.display_name = std::move(display_name);
        }

        // Lookup the parameters by function rowid
        maybe_throw(sqlite3_reset(lookup_params));
        maybe_throw(sqlite3_bind_int64(lookup_params, 1, rowid));
        auto param_txtval = create_textval(lookup_params);
        do {
          rv = sqlite3_step(lookup_params);
          switch (rv) {
           case SQLITE_DONE:
           case SQLITE_BUSY:
            break;
           case SQLITE_ROW:
            {
              // Get the data from the row
              auto param_name = param_txtval(PARAM_NAME);
              auto type_name = param_txtval(PARAM_TYPE);
              auto inout = param_txtval(PARAM_INOUT);
              auto pos = size_t(sqlite3_column_int(lookup_params, PARAM_POSITION));

              // Resize the array as necessary
              if (pos + 1 > def.parameters.size()) {
                def.parameters.resize(pos + 1);
              }

              // Fill this parameter from the array
              auto & param = def.parameters[pos];
              param.name = std::move(param_name);
              param.type = std::move(type_name);
              auto inout_loc = inout_map.find(inout);
              if (inout_loc != inout_map.end()) {
                param.direction = inout_loc->second;
              }
            }
            break;
           default:
            throw_error();
          }
        } while (rv != SQLITE_DONE);

        // Set up the stackdelta
        if (def.calling_convention.empty() || def.calling_convention == "stdcall"
            || def.calling_convention == "thiscall")
        {
          def.stackdelta = def.parameters.size() * 4;
        }

        auto defkey = defkey_t(def.dll_name, def.export_name);
        defmap.emplace(std::move(defkey), fd);
        if (fd->ordinal) {
          auto ordkey = ordkey_t(def.dll_name, fd->ordinal);
          ordmap.emplace(std::move(ordkey), fd);
        }
        list.push_back(fd);
      } // if (sqlite3_column_int(lookup, PARAMS_KNOWN))
      current_lookup = lookup;
    } else {
      auto follow = sqlite3_column_int64(current_lookup, ALIAS_ID);
      current_lookup = lookup_by_row;
      maybe_throw(sqlite3_reset(current_lookup));
      maybe_throw(sqlite3_bind_int64(current_lookup, 1, sqlite3_int64(follow)));
    }
  } // while (true)


  return list;
}

APIDefinitionList
SQLLiteApiDictionary::Data::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  lock_guard lock{mutex};
  auto key = ordkey_t(normalize_dll(dll_name), ordinal);
  auto loc = values(ordmap.equal_range(key));
  if (begin(loc) != end(loc)) {
    return APIDefinitionList(begin(loc), end(loc));
  }

  // Not cached.  Look it up in the db
  auto name = key.first + ".dll";
  maybe_throw(sqlite3_reset(lookup_by_id));
  maybe_throw(sqlite3_bind_text(lookup_by_id, 1, name.c_str(), name.size(), SQLITE_TRANSIENT));
  maybe_throw(sqlite3_bind_int64(lookup_by_id, 2, sqlite3_int64(ordinal)));

  return get_db_function(lookup_by_id);
}

APIDefinitionList
SQLLiteApiDictionary::Data::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  lock_guard lock{mutex};
  auto key = defkey_t(normalize_dll(dll_name), func_name);
  auto loc = values(defmap.equal_range(key));
  if (begin(loc) != end(loc)) {
    return APIDefinitionList(begin(loc), end(loc));
  }

  // Not cached.  Look it up in the db
  auto name = key.first + ".dll";
  maybe_throw(sqlite3_reset(lookup_by_name));
  maybe_throw(sqlite3_bind_text(lookup_by_name, 1, name.c_str(), name.size(),
                                SQLITE_TRANSIENT));
  maybe_throw(sqlite3_bind_text(lookup_by_name, 2, key.second.c_str(), key.second.size(),
                                SQLITE_TRANSIENT));

  return get_db_function(lookup_by_name);
}

APIDefinitionList
SQLLiteApiDictionary::Data::get_api_definition(
  const std::string & func_name) const
{
  lock_guard lock{mutex};
  maybe_throw(sqlite3_reset(lookup_by_name_only));
  maybe_throw(sqlite3_bind_text(lookup_by_name_only, 1, func_name.c_str(), func_name.size(),
                                SQLITE_TRANSIENT));
  return get_db_function(lookup_by_name_only);
}

APIDefinitionList
SQLLiteApiDictionary::Data::get_api_definition(
  const regex & func_name) const
{
  lock_guard lock{mutex};
  std::int64_t idx;
  {
    write_guard<decltype(regex_mutex)> guard(regex_mutex);
    idx = next_regex_index++;
    regex_map[idx] = &func_name;
  }
  auto cleanup = make_finalizer([idx]() {
    write_guard<decltype(regex_mutex)> guard(regex_mutex);
    regex_map.erase(idx);
  });
  maybe_throw(sqlite3_reset(lookup_all_names));
  maybe_throw(sqlite3_bind_int64(lookup_all_names, 1, idx));
  return get_db_function(lookup_all_names);
}

bool
SQLLiteApiDictionary::Data::handles_dll(std::string const & dll_name_) const
{
  lock_guard lock{mutex};
  auto dll_name = normalize_dll(dll_name_) + ".dll";
  maybe_throw(sqlite3_reset(lookup_dll_exists));
  maybe_throw(sqlite3_bind_text(lookup_dll_exists, 1, dll_name.c_str(),
                                dll_name.size(), SQLITE_TRANSIENT));
  int rv;
  while (true) {
    rv = sqlite3_step(lookup_dll_exists);
    switch (rv) {
     case SQLITE_DONE:
      return false;
     case SQLITE_BUSY:
      break;
     case SQLITE_ROW:
      return true;
     default:
      throw_error();
    }
  }
}

SQLLiteApiDictionary::SQLLiteApiDictionary(const std::string & file) :
  data(new Data(*this, file)), path(file) {}
SQLLiteApiDictionary::~SQLLiteApiDictionary() = default;
SQLLiteApiDictionary::SQLLiteApiDictionary(SQLLiteApiDictionary &&) noexcept = default;
SQLLiteApiDictionary &SQLLiteApiDictionary::operator=(SQLLiteApiDictionary &&) = default;

APIDefinitionList
SQLLiteApiDictionary::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  return data->get_api_definition(dll_name, ordinal);
}

APIDefinitionList
SQLLiteApiDictionary::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  return data->get_api_definition(dll_name, func_name);
}

APIDefinitionList
SQLLiteApiDictionary::get_api_definition(
  const std::string & func_name) const
{
  return data->get_api_definition(func_name);
}

APIDefinitionList
SQLLiteApiDictionary::get_api_definition(
  const regex & func_name) const
{
  return data->get_api_definition(func_name);
}

APIDefinitionList
SQLLiteApiDictionary::get_api_definition(rose_addr_t) const
{
  return APIDefinitionList();
}

bool
SQLLiteApiDictionary::handles_dll(std::string const & dll_name) const
{
  return data->handles_dll(dll_name);
}

std::string SQLLiteApiDictionary::describe() const
{
  return "SQLite API database " + path;
}

bool
DLLStateCacheDict::handles_dll(std::string const & dll_name_) const
{
  auto dll_name = normalize_dll(dll_name_);
  auto found = cache.find(dll_name);
  if (found != cache.end()) {
    return found->second;
  }
  auto result = PassThroughDictionary::handles_dll(dll_name);
  cache.emplace(std::move(dll_name), result);
  return result;
}

APIDefinitionList
DLLStateCacheDict::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  APIDefinitionList result;

  if (!handles_dll(dll_name)) {
    return result;
  }

  return PassThroughDictionary::get_api_definition(dll_name, ordinal);
}

APIDefinitionList
DLLStateCacheDict::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  APIDefinitionList result;

  if (!handles_dll(dll_name)) {
    return result;
  }

  return PassThroughDictionary::get_api_definition(dll_name, func_name);
}

bool
ReportDictionary::check_dll(std::string const & dll_name_) const
{
  auto dll_name = normalize_dll(dll_name_);
  auto found = dll_cache.find(dll_name);
  if (found != dll_cache.end()) {
    if (found->second) {
      ++found->second;
      return false;
    }
    return true;
  }
  bool result = handles_dll(dll_name);
  if (result) {
    dll_cache.emplace(dll_name, 0);
  } else {
    dll_cache.emplace(dll_name, 1);
    if (dll_error_log_ && *dll_error_log_) {
      (*dll_error_log_) << name << " has no data for DLL: " << dll_name_ << std::endl;
    }
  }
  return result;
}

template <typename T>
APIDefinitionList
ReportDictionary::get_definition(
  const char * tname, const std::string & dll_name, const T & value) const
{
  APIDefinitionList result;

  if (fn_request_log_ && *fn_request_log_) {
    *fn_request_log_ << "API Lookup: " << dll_name << ":" << std::dec << value << std::endl;
  }

  result = PassThroughDictionary::get_api_definition(dll_name, value);
  if (result.empty()) {
    if (fn_error_log_ && check_dll(dll_name) && *fn_error_log_) {
      *fn_error_log_ << name << " could not find " << tname << ' '
                     << std::dec << value << " in " << dll_name << std::endl;
    }
  } else {
    if (fn_success_log_ && *fn_success_log_) {
      *fn_success_log_ << name << " found " << tname << ' '
                       << std::dec << value << " for " << dll_name << std::endl;
    }
    log_detail(result);
  }
  return result;
}

APIDefinitionList
ReportDictionary::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  return get_definition("ordinal", dll_name, ordinal);
}

APIDefinitionList
ReportDictionary::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  return get_definition("function", dll_name, func_name);
}

template <typename T>
APIDefinitionList
ReportDictionary::get_api_definition(
  const T & func_name) const
{
  APIDefinitionList result;

  if (fn_request_log_ && *fn_request_log_) {
    *fn_request_log_ << "API Lookup: " << func_name << std::endl;
  }

  result = PassThroughDictionary::get_api_definition(func_name);
  if (result.empty()) {
    if (fn_error_log_ && *fn_error_log_) {
      *fn_error_log_ << name << " could not find function " << func_name << std::endl;
    }
  } else {
    if (fn_success_log_ && *fn_success_log_) {
      *fn_success_log_ << name << " found function " << func_name << std::endl;
    }
    log_detail(result);
  }
  return result;
}

APIDefinitionList
ReportDictionary::get_api_definition(
  const std::string & func_name) const
{
  return get_api_definition<std::string>(func_name);
}

APIDefinitionList
ReportDictionary::get_api_definition(
  const regex & func_name) const
{
  return get_api_definition<regex>(func_name);
}

APIDefinitionList
ReportDictionary::get_api_definition(
  rose_addr_t addr) const
{
  if (fn_request_log_ && *fn_request_log_) {
    *fn_request_log_ << "API Lookup: " << addr_str(addr) << std::endl;
  }
  auto result = PassThroughDictionary::get_api_definition(addr);
  if (fn_request_log_ && *fn_request_log_) {
    if (result.empty()) {
      *fn_request_log_ << "API Lookup failed to find " << addr_str(addr) << std::endl;
    } else {
      *fn_request_log_ << "API Lookup found " << addr_str(addr) << std::endl;
    }
  }
  return result;
}

void
ReportDictionary::log_detail(APIDefinitionList const & result) const
{
  if (!fn_detail_log_ || !*fn_detail_log_) {
    return;
  }
  auto & log = *fn_detail_log_;
  for (auto const & def : result) {
    if (!def) {
      continue;
    }
    log << def->dll_name << '|'
        << def->dll_stamp << '|'
        << def->dll_version << '|'
        << def->export_name << '|'
        << def->display_name << '|';
    if (def->ordinal) {
      log << std::dec << def->ordinal;
    }
    log << '|';
    if (def->relative_address != RELATIVE_ADDRESS_MAX) {
      log << std::hex << def->relative_address;
    }
    log << '|'
        << def->calling_convention << '|'
        << def->return_type << '|';
    if (def->stackdelta != STACKDELTA_MAX) {
      log << std::dec << def->stackdelta;
    }
    log << "|(";
    bool first = true;
    for (auto const & param : def->parameters) {
      if (first) {
        first = false;
      } else {
        log << ", ";
      }
      if (!param.type.empty()) {
        log << param.type;
      }
      if (!param.name.empty()) {
        log << ' ' << param.name;
      }
      switch (param.direction) {
       case APIParam::NONE:
        break;
       case APIParam::IN:
        log << " {in}";
        break;
       case APIParam::OUT:
        log << " {out}";
        break;
       case APIParam::INOUT:
        log << " {in/out}";
        break;
      }
    }
    log << ')' << std::endl;
  }
}

std::ostream & ReportDictionary::report_dll_failures(std::ostream & s) const
{
  for (auto & val : dll_cache) {
    s << name << " failed " << val.second << " times to look up functions in DLL "
      << val.first << std::endl;
  }
  return s;
}

Sawyer::Message::Facility & APIDictionary::initDiagnostics()
{
  static bool initialized = false;
  if (!initialized) {
    mlog.initialize("APID");
    mlog.initStreams(get_logging_destination());
    Sawyer::Message::mfacilities.insert(mlog);
    initialized = true;
  }

  SQLLiteApiDictionary::Data::initDiagnostics();

  return mlog;
}

APIDefinitionList
DecoratedDictionary::get_api_definition(
  const std::string & dll_name,
  const std::string & func_name) const
{
  APIDefinitionList list;
  demangle::DemangledTypePtr type;
  try {
    type = demangle::visual_studio_demangle(func_name);
  } catch (demangle::Error &) {
    type = nullptr;
  }
  if (!type) {
    try {
      char c = func_name.at(0);
      if (c == '_' || c== '@') {
        std::size_t at = func_name.rfind('@');
        if (at != std::string::npos && at > 0 ) {
          std::string name(func_name.substr(1, at));
          ++at;
          int delta = stoi(func_name, &at);
          if (at == func_name.size()) {
            auto def = std::make_shared<APIDefinition>(*this);
            def->export_name = func_name;
            def->display_name = std::move(name);
            def->dll_name = normalize_dll(dll_name);
            def->calling_convention = (c == '_') ? "stdcall" : "fastcall";
            def->stackdelta = delta;
            int nparams = delta / 4; // TODO: FIXME!
            def->parameters.resize(nparams);
            list.push_back(std::move(def));
          }
        } else {
          auto def = std::make_shared<APIDefinition>(*this);
          def->export_name = func_name;
          def->display_name = func_name.substr(1);
          def->dll_name = normalize_dll(dll_name);
          def->calling_convention = "cdecl";
          list.push_back(std::move(def));
        }
      }
    }
    catch (std::invalid_argument&) { /* Fall through */ }
    catch (std::out_of_range&) { /* Fall through */ }

    return list;
  }

  auto def = std::make_shared<APIDefinition>(*this);

  def->export_name = func_name;
  def->display_name = type->str();
  def->dll_name = normalize_dll(dll_name);
  if (!type->calling_convention.empty()) {
    def->calling_convention = type->calling_convention.substr(2);
  }
  if (type->retval) {
    def->return_type = type->retval->str();
  }
  for (auto & arg : type->args) {
    std::string argstr;
    if (arg) {
      argstr = arg->str();
    }
    if (argstr != "void") {
      def->parameters.emplace_back();
      if (arg) {
        auto & param = def->parameters.back();
        param.type = arg->str();
      }
    }
  }
  if (def->calling_convention == "stdcall" || def->calling_convention == "thiscall") {
    def->stackdelta = def->parameters.size() * 4;
  }

  list.push_back(std::move(def));
  return list;
}

APIDefinitionList
DecoratedDictionary::get_api_definition(
  const std::string & func_name) const
{
  return get_api_definition("<unknown>", func_name);
}


} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
