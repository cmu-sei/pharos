// Copyright 2015, 2016, 2017 Carnegie Mellon University.  See LICENSE file for terms.

#include <unordered_map>
#include <limits>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop
#include "util.hpp"
#include "misc.hpp"
#include "apidb.hpp"
#include "descriptors.hpp"
#include "demangle.hpp"
#include <sqlite3.h>
#include <boost/range/adaptor/reversed.hpp>

namespace pharos {

namespace {

using Path = boost::filesystem::path;
using boost::filesystem::is_directory;

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
using defmap_t = std::unordered_map<defkey_t, APIDefinitionPtr, defhash>;
using ordmap_t = std::unordered_map<ordkey_t, APIDefinitionPtr, ordhash>;
using addrmap_t = std::unordered_map<rose_addr_t, APIDefinitionPtr>;

constexpr auto STACKDELTA_MAX =
  std::numeric_limits<decltype(APIDefinition::stackdelta)>::max();
constexpr auto RELATIVE_ADDRESS_MAX =
  std::numeric_limits<decltype(APIDefinition::relative_address)>::max();

} // unnamed namespace

APIDefinition::APIDefinition() :
  relative_address(RELATIVE_ADDRESS_MAX),
  stackdelta(STACKDELTA_MAX),
  ordinal(0)
{}

// This is essentially a macro used by all the MultiApiDictionary::get_api_definition
// definitions
template <typename... T>
APIDefinitionPtr MultiApiDictionary::_get_api_definition(T &&... args) const
{
  for (auto & dict : dicts) {
    auto result = dict->get_api_definition(std::forward<T>(args)...);
    if (result) {
      return result;
    }
  }
  return nullptr;
}

APIDefinitionPtr MultiApiDictionary::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  return _get_api_definition(dll_name, func_name);
}

APIDefinitionPtr MultiApiDictionary::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  return _get_api_definition(dll_name, ordinal);
}

APIDefinitionPtr MultiApiDictionary::get_api_definition(rose_addr_t addr) const
{
  return _get_api_definition(addr);
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

JSONApiDictionary::JSONApiDictionary(const std::string &path) : data(new Data())
{
  data->load_on_demand = is_directory(path);
  if (data->load_on_demand) {
    directory = path;
  } else {
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
  switch (node.Type()) {
   case YAML::NodeType::Scalar:
    // Interpret a simple string as a path to api information.
    {
      auto path = Path(node.Scalar());
      if (!path.has_root_directory()) {
        // Relative paths will be considered relative to the library path.
        path = global_descriptor_set->get_library_path() / path;
      }
      if (is_directory(path)) {
        // Assume the directory contains per-DLL json files
        auto jsondb = make_unique<JSONApiDictionary>(path.native());
        assert(jsondb);
        db.add(make_unique<WinAWLookupPlan>(std::move(jsondb)));
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
          db.add(make_unique<WinAWLookupPlan>(std::move(jsondb)));
        } else {
          // SQLite
          auto sql = make_unique<SQLLiteApiDictionary>(path.native());
          assert(sql);
          db.add(make_unique<WinAWLookupPlan>(std::move(sql)));
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
          GWARN << os.str() << LEND;
          break;
         case LOG_ERROR:
          GERROR << os.str() << LEND;
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
    // [[fallthrough]];
   case YAML::NodeType::Map:
    try {
      // A map or sequence is an inline set of API information
      auto jsondb = make_unique<JSONApiDictionary>(node);
      db.add(make_unique<WinAWLookupPlan>(std::move(jsondb)));
      return true;
    } catch (const std::runtime_error & e) {
      switch (handle) {
       case IGNORE:
        break;
       case LOG_WARN:
       case LOG_ERROR:
        {
          auto & err = glog[(handle == LOG_WARN)
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

std::unique_ptr<APIDictionary> APIDictionary::create_standard(
  const ProgOptVarMap &vm,
  handle_error_t handle)
{
  auto multidb = make_unique<MultiApiDictionary>();
  assert(multidb);

  if (vm.count("apidb")) {
    // If it's listed on the command line, use that.  Command line options should be applied in
    // reverse order, so the last --apidb option takes priority
    for (auto & filename :
           boost::adaptors::reverse(vm["apidb"].as<std::vector<std::string>>()))
    {
      handle_node(*multidb, YAML::Node(filename), false, THROW);
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
  return std::move(multidb);
}

void JSONApiDictionary::load_json(const std::string &filename) const
{
  auto json = YAML::LoadFile(filename);
  if (!json.IsMap()) {
    throw std::runtime_error("File is not a map: " + filename);
  }
  auto exports = json["config"]["exports"];
  if (exports) {
    load_json(exports);
  }
}

void JSONApiDictionary::load_json(const YAML::Node & exports) const
{
  // loop over each entry
  bool is_map = exports.Type() == YAML::NodeType::Map;
  for (auto node : exports) {
    auto fd = std::make_shared<APIDefinition>();
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
          auto type = visual_studio_demangle(fd->export_name);
          if (type) {
            fd->display_name = type->str();
          }
        } catch (const DemanglerError &) {
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
    defkey_t defkey(dll_name, to_lower(fd->get_name()));
    auto & value = data->defmap[std::move(defkey)];
    size_t ord = fd->ordinal;
    value = std::move(fd);
    if (ord) {
      ordkey_t ordkey(std::move(dll_name), ord);
      data->ordmap.emplace(std::move(ordkey), value);
    }
    if (value->relative_address != RELATIVE_ADDRESS_MAX) {
      data->addrmap.emplace(value->relative_address, value);
    }

  } // for (auto node : exports)
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
  std::string filename = directory + "/" + dll_name + ".json";
  bool succeeded = false;
  try {
    load_json(filename);
    succeeded = true;
    GINFO << "Loaded API database: " << filename << LEND;
  } catch (...) {
    GERROR << "Unable to load API database: " << filename << LEND;
  }
  data->loaded_files[dll_name] = succeeded;
  return succeeded;
}

APIDefinitionPtr
JSONApiDictionary::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  defkey_t key(normalize_dll(dll_name), to_lower(func_name));
  if (!known_dll(key.first)) {
    return nullptr;
  }
  auto found = data->defmap.find(key);
  return (found == data->defmap.end()) ? nullptr : found->second;
}

APIDefinitionPtr
JSONApiDictionary::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  ordkey_t key(normalize_dll(dll_name), ordinal);
  if (!known_dll(key.first)) {
    return nullptr;
  }
  auto found = data->ordmap.find(key);
  return (found == data->ordmap.end()) ? nullptr : found->second;
}

APIDefinitionPtr
JSONApiDictionary::get_api_definition(rose_addr_t addr) const
{
  auto found = data->addrmap.find(addr);
  return (found == data->addrmap.end()) ? nullptr : found->second;
}

struct SQLLiteApiDictionary::Data {
  // Select statement to look up functions by dll and name
  static constexpr char select_by_name[] =
    "SELECT rowId, ordinal, name, canonical, callingConvention, returnType FROM function"
    " WHERE dll = ?1 AND name = ?2";

  // Select statement to look up functions by dll and ordinal
  static constexpr char select_by_ordinal[] =
    "SELECT rowId, ordinal, name, canonical, callingConvention, returnType FROM function"
    " WHERE dll = ?1 AND ordinal = ?2";

  // Select statement to look up a function's parameters.  Ordered descending to get the count
  // of params up front from the position parameter
  static constexpr char select_params[] =
    "SELECT name, type, inOut, position FROM parameter"
    " WHERE functionId = ?1 ORDER BY position DESC";

  // Throw an error based on an error code
  [[noreturn]] static void throw_error(int code);
  // Throw an error based on the state of the db
  [[noreturn]] void throw_error() const;

  // Throw an error based on the code if the code isn't OK
  static void maybe_throw_code(int code);
  // Throw an error based on the db if the code isn't OK
  void maybe_throw(int code) const;

  // Load the db at filename
  Data(const std::string & filename);
  ~Data();

  APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, const std::string & func_name) const;

  APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, size_t ordinal) const;

  APIDefinitionPtr
  get_db_function(
    sqlite3_stmt * lookup, const std::string & dll_name) const;

  sqlite3 * db = nullptr;
  sqlite3_stmt * lookup_by_id = nullptr;
  sqlite3_stmt * lookup_by_name = nullptr;
  sqlite3_stmt * lookup_params = nullptr;
  mutable defmap_t defmap;
  mutable ordmap_t ordmap;
};

// The definitions of these have to exist, per the standard.
constexpr char SQLLiteApiDictionary::Data::select_by_name[];
constexpr char SQLLiteApiDictionary::Data::select_by_ordinal[];
constexpr char SQLLiteApiDictionary::Data::select_params[];

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

SQLLiteApiDictionary::Data::Data(const std::string & filename)
{
  // Open the db
  try {
    constexpr auto flags = SQLITE_OPEN_READONLY;
    maybe_throw_code(sqlite3_open_v2(filename.c_str(), &db, flags, nullptr));
  } catch (const SQLError &) {
    GERROR << "Unable to read API Database \"" << filename << '\"' << LEND;
    throw;
  }

  // Prepare the select statements
  maybe_throw(sqlite3_prepare_v2(db, select_by_name, sizeof(select_by_name),
                                 &lookup_by_name, nullptr));
  maybe_throw(sqlite3_prepare_v2(db, select_by_ordinal, sizeof(select_by_ordinal),
                                 &lookup_by_id, nullptr));
  maybe_throw(sqlite3_prepare_v2(db, select_params, sizeof(select_params),
                                 &lookup_params, nullptr));
}

SQLLiteApiDictionary::Data::~Data()
{
  // All statments must be finalized before closing the db

  int rv;
  rv = sqlite3_finalize(lookup_by_id);
  assert(rv == SQLITE_OK);
  rv = sqlite3_finalize(lookup_by_name);
  assert(rv == SQLITE_OK);
  rv = sqlite3_finalize(lookup_params);
  assert(rv == SQLITE_OK);
  rv = sqlite3_close_v2(db);
  assert(rv == SQLITE_OK);
}

APIDefinitionPtr
SQLLiteApiDictionary::Data::get_db_function(
  sqlite3_stmt * lookup, const std::string & dll_name) const
{
  int rv;

  // Look up the function in the db
  do {
    rv = sqlite3_step(lookup);
    switch (rv) {
     case SQLITE_BUSY:
     case SQLITE_ROW:
      // Continue if we found it, or are busy
      break;
     case SQLITE_DONE:
      // Return null if we didn't find it
      return nullptr;
     default:
      // Otherwise, error
      throw_error();
    }
  } while (rv == SQLITE_BUSY);

  // Generate a function for a statement that extracts text strings from that statement,
  // accounting fo possible NULLs
  auto create_textval = [](sqlite3_stmt * stm) {
    return [stm](int col) {
      if (sqlite3_column_type(stm, col) == SQLITE_NULL) {
        return std::string();
      } else {
        return std::string(reinterpret_cast<const char *>(sqlite3_column_text(stm, col)));
      }
    };
  };

  // Generate a textval for the lookup statement
  auto id_textval = create_textval(lookup);

  // Get the data from the row
  auto rowid = sqlite3_column_int64(lookup, 0);
  auto func_ordinal = sqlite3_column_int64(lookup, 1);
  auto func_name = id_textval(2);
  auto canonical = id_textval(3);
  auto convention = id_textval(4);
  auto return_type = id_textval(5);

  do {
    // Check to see if there are more
    rv = sqlite3_step(lookup);
    switch (rv) {
     case SQLITE_DONE:
     case SQLITE_BUSY:
      // If no more, or busy, fine
      break;
     case SQLITE_ROW:
      // If more, there are duplicate answers
      throw std::runtime_error("Found more than one match for function");
     default:
      // Otherwise, error
      throw_error();
    }
  } while (rv == SQLITE_BUSY);

  auto fd = std::make_shared<APIDefinition>();
  fd->dll_name = dll_name;

  // Fill the definition
  fd->ordinal = func_ordinal;
  fd->export_name = std::move(canonical);
  fd->display_name = std::move(func_name);
  fd->calling_convention = std::move(convention);
  fd->return_type = std::move(return_type);

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
        auto param_name = param_txtval(0);
        auto type_name = param_txtval(1);
        auto inout = param_txtval(2);
        auto pos = size_t(sqlite3_column_int(lookup_params, 3));

        // Resize the array as necessary
        if (pos + 1 > fd->parameters.size()) {
          fd->parameters.resize(pos + 1);
        }

        // Fill this parameter from the array
        auto & param = fd->parameters[pos];
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
  if (fd->calling_convention.empty() || fd->calling_convention == "stdcall") {
    fd->stackdelta = fd->parameters.size() * 4;
  } else {
    fd->stackdelta = 0;
  }

  // Add to cache
  auto defkey = defkey_t(fd->dll_name, to_lower(fd->export_name));
  auto & value = defmap[std::move(defkey)];
  value = std::move(fd);
  if (func_ordinal) {
    auto ordkey = ordkey_t(value->dll_name, func_ordinal);
    ordmap.emplace(std::move(ordkey), value);
  }

  return value;
}


APIDefinitionPtr
SQLLiteApiDictionary::Data::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  auto key = ordkey_t(normalize_dll(dll_name), ordinal);
  auto loc = ordmap.find(key);
  if (loc != ordmap.end()) {
    return loc->second;
  }

  // Not cached.  Look it up in the db
  auto name = key.first + ".dll";
  maybe_throw(sqlite3_reset(lookup_by_id));
  maybe_throw(sqlite3_bind_text(lookup_by_id, 1, name.c_str(), name.size(), SQLITE_TRANSIENT));
  maybe_throw(sqlite3_bind_int64(lookup_by_id, 2, sqlite3_int64(ordinal)));

  return get_db_function(lookup_by_id, key.first);
}

APIDefinitionPtr
SQLLiteApiDictionary::Data::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  auto key = defkey_t(normalize_dll(dll_name), to_lower(func_name));
  auto loc = defmap.find(key);
  if (loc != defmap.end()) {
    return loc->second;
  }

  // Not cached.  Look it up in the db
  auto name = key.first + ".dll";
  maybe_throw(sqlite3_reset(lookup_by_name));
  maybe_throw(sqlite3_bind_text(lookup_by_name, 1, name.c_str(), name.size(),
                                SQLITE_TRANSIENT));
  maybe_throw(sqlite3_bind_text(lookup_by_name, 2, key.second.c_str(), key.second.size(),
                                SQLITE_TRANSIENT));

  return get_db_function(lookup_by_name, key.first);
}

SQLLiteApiDictionary::SQLLiteApiDictionary(const std::string &lp) :
  data(new Data(lp)), lib_path(lp) {}
SQLLiteApiDictionary::~SQLLiteApiDictionary() = default;
SQLLiteApiDictionary::SQLLiteApiDictionary(SQLLiteApiDictionary &&) noexcept = default;
SQLLiteApiDictionary &SQLLiteApiDictionary::operator=(SQLLiteApiDictionary &&) = default;

APIDefinitionPtr
SQLLiteApiDictionary::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  return data->get_api_definition(dll_name, ordinal);
}

APIDefinitionPtr
SQLLiteApiDictionary::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  return data->get_api_definition(dll_name, func_name);
}

APIDefinitionPtr
SQLLiteApiDictionary::get_api_definition(rose_addr_t) const
{
  return nullptr;
}

APIDefinitionPtr
WinAWLookupPlan::get_api_definition(
  const std::string & dll_name, size_t ordinal) const
{
  return subdict->get_api_definition(dll_name, ordinal);
}

APIDefinitionPtr
WinAWLookupPlan::get_api_definition(
  const std::string & dll_name, const std::string & func_name) const
{
  if (func_name.empty()) {
    return NULL;
  }
  auto result = subdict->get_api_definition(dll_name, func_name);
  if (result == NULL) {
    auto size = func_name.size() - 1;
    char c = std::toupper(func_name[size]);
    if (c == 'A' || c == 'W') {
      auto basename = func_name.substr(0, size);
      return subdict->get_api_definition(dll_name, std::move(basename));
    }
  }
  return result;
}

APIDefinitionPtr
WinAWLookupPlan::get_api_definition(rose_addr_t addr) const
{
  return subdict->get_api_definition(addr);
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
