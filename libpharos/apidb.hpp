// Copyright 2015-2018 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Dllapi_H
#define Pharos_Dllapi_H

// This file contains a prototype version of a dll api query mechanism

#include <string>
#include <vector>
#include <memory>
#include <yaml-cpp/yaml.h>
#include "misc.hpp"

namespace pharos {

typedef std::string type_t;
typedef std::string calling_convention_t;


struct APIParam {
  typedef enum inout_en { NONE, IN, OUT, INOUT } inout_t;
  std::string name;
  type_t      type;
  inout_t     direction;
};

struct APIDefinition {
  APIDefinition();

  std::string           export_name;  // empty if unknown
  std::string           display_name; // Should never be empty
  std::string           dll_name;     // empty if unknown
  std::string           md5;          // dll md5 (empty if unknown)
  rose_addr_t           relative_address; // -1 if unknown
  calling_convention_t  calling_convention;
  type_t                return_type;
  std::vector<APIParam> parameters;
  size_t                stackdelta;   // SIZE_MAX if unknown
  size_t                ordinal;      // 0 if unknown

  const std::string & get_name() const {
    return export_name.empty() ? display_name : export_name;
  }
};

using APIDefinitionPtr = std::shared_ptr<const APIDefinition>;
using APIDefinitionList = std::vector<APIDefinitionPtr>;

class MultiApiDictionary;

class APIDictionary {
 public:
  static Sawyer::Message::Facility mlog;

  static Sawyer::Message::Facility & initDiagnostics();

  enum handle_error_t { IGNORE, LOG_WARN, LOG_ERROR, THROW };

  static std::unique_ptr<APIDictionary> create_standard(
    const ProgOptVarMap & vm, handle_error_t handle = LOG_WARN);

  // Return the function information for the given DLL name and function name.  Return nullptr
  // if the function cannot be found.
  virtual APIDefinitionList
  get_api_definition(
    const std::string & dll_name, const std::string & func_name) const = 0;

  // Return the function information for the given DLL name and function name.  Return nullptr
  // if the function cannot be found.
  virtual APIDefinitionList
  get_api_definition(
    const std::string & dll_name, size_t ordinal) const = 0;

  // Return the function information for the given address.  Return nullptr if the function
  // cannot be found.
  virtual APIDefinitionList
  get_api_definition(rose_addr_t addr) const = 0;

  virtual ~APIDictionary() = default;

  virtual bool handles_dll(std::string const & dll_name) const = 0;

  virtual std::string describe() const = 0;

 private:
  static bool handle_node(MultiApiDictionary & db, const YAML::Node & node,
                          bool top, handle_error_t handle);
};

class PassThroughDictionary : public APIDictionary {
 protected:
  PassThroughDictionary(std::unique_ptr<APIDictionary> subdict_)
    : sd(std::move(subdict_))
  {}

  APIDictionary const & subdict() const {
    return *sd;
  }

 public:
  APIDefinitionList
  get_api_definition(const std::string & dll_name, const std::string & func_name) const {
    return subdict().get_api_definition(dll_name, func_name);
  }

  APIDefinitionList
  get_api_definition(const std::string & dll_name, size_t ordinal) const {
    return subdict().get_api_definition(dll_name, ordinal);
  }

  APIDefinitionList
  get_api_definition(rose_addr_t addr) const {
    return subdict().get_api_definition(addr);
  }

  bool handles_dll(std::string const & dll_name) const {
    return subdict().handles_dll(dll_name);
  }

  std::string describe() const {
    return subdict().describe();
  }

 private:
  std::unique_ptr<APIDictionary> sd;
};

class MultiApiDictionary : public APIDictionary {
 public:
  virtual APIDefinitionList
  get_api_definition(
    const std::string & dll_name, const std::string & func_name)
    const override;

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, size_t ordinal)
    const override;

  APIDefinitionList
  get_api_definition(rose_addr_t addr) const override;

  void add(std::unique_ptr<APIDictionary> dict) {
    dicts.push_back(std::move(dict));
  }

  bool handles_dll(std::string const & dll_name) const override;

  std::string describe() const override;

 private:
  template <typename... T>
  APIDefinitionList _get_api_definition(T &&... args) const;

  std::vector<std::unique_ptr<APIDictionary>> dicts;
};

class JSONApiDictionary : public APIDictionary {
 public:
  JSONApiDictionary(const std::string & path);
  JSONApiDictionary(const YAML::Node & exports);
  ~JSONApiDictionary() override;
  JSONApiDictionary(JSONApiDictionary &&) noexcept;
  JSONApiDictionary &operator=(JSONApiDictionary &&);

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, const std::string & func_name)
    const override;

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, size_t ordinal)
    const override;

  APIDefinitionList
  get_api_definition(rose_addr_t addr) const override;

  bool handles_dll(std::string const & dll_name) const override;

  std::string describe() const override;

 private:
  bool known_dll(const std::string & dll_name) const;
  void load_json(const std::string & filename) const;
  void load_json(const YAML::Node & exports) const;

  struct Data;
  std::unique_ptr<Data> data;
  std::string path;
};

class SQLLiteApiDictionary : public APIDictionary {
 public:
  class SQLError : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
  };

  SQLLiteApiDictionary(const std::string & sqlite_file);
  ~SQLLiteApiDictionary() override;
  SQLLiteApiDictionary(SQLLiteApiDictionary &&) noexcept;
  SQLLiteApiDictionary &operator=(SQLLiteApiDictionary &&);

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, const std::string & func_name)
    const override;

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, size_t ordinal)
    const override;

  APIDefinitionList
  get_api_definition(rose_addr_t addr) const override;

  bool handles_dll(std::string const & dll_name) const override;

  std::string describe() const override;

 private:
  friend Sawyer::Message::Facility & APIDictionary::initDiagnostics();
  struct Data;
  std::unique_ptr<Data> data;
  std::string path;
};

class DLLStateCacheDict : public PassThroughDictionary {
 public:
  DLLStateCacheDict(std::unique_ptr<APIDictionary> d)
    : PassThroughDictionary(std::move(d))
  {}

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, const std::string & func_name) const override;

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, size_t ordinal) const override;

  bool handles_dll(std::string const & dll_name) const override;

 private:
  std::unique_ptr<APIDictionary> subdict;
  mutable std::unordered_map<std::string, bool> cache;
};

class ReportDictionary : public PassThroughDictionary {
 public:
  ReportDictionary(
    std::unique_ptr<APIDictionary> subdict_,
    std::string const & name_)
    : PassThroughDictionary(std::move(subdict_)),
      name(name_)
  {}

  ReportDictionary(
    std::unique_ptr<APIDictionary> subdict_)
    : ReportDictionary(std::move(subdict_), "API database")
  {}

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, const std::string & func_name) const override;

  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, size_t ordinal) const override;

  APIDefinitionList
  get_api_definition(rose_addr_t addr) const override;

  ReportDictionary & dll_error_log(std::ostream * s) {
    dll_error_log_ = s;
    return *this;
  }

  ReportDictionary & dll_error_log(std::ostream & s) {
    return dll_error_log(&s);
  }

  ReportDictionary & fn_error_log(std::ostream * s) {
    fn_error_log_ = s;
    return *this;
  }

  ReportDictionary & fn_error_log(std::ostream & s) {
    return fn_error_log(&s);
  }

  ReportDictionary & fn_success_log(std::ostream * s) {
    fn_success_log_ = s;
    return *this;
  }

  ReportDictionary & fn_success_log(std::ostream & s) {
    return fn_success_log(&s);
  }

  ReportDictionary & fn_detail_log(std::ostream * s) {
    fn_detail_log_ = s;
    return *this;
  }

  ReportDictionary & fn_detail_log(std::ostream & s) {
    return fn_detail_log(&s);
  }

  ReportDictionary & fn_request_log(std::ostream * s) {
    fn_request_log_ = s;
    return *this;
  }

  ReportDictionary & fn_request_log(std::ostream & s) {
    return fn_request_log(&s);
  }

  std::ostream & report_dll_failures(std::ostream & s) const;

 private:
  bool check_dll(std::string const & dll_name) const;

  template <typename T>
  APIDefinitionList get_definition(
    const char * tname, const std::string & dll_name, const T & value) const;

  std::string name;
  std::ostream * dll_error_log_ = nullptr;
  std::ostream * fn_error_log_ = nullptr;
  std::ostream * fn_success_log_ = nullptr;
  std::ostream * fn_detail_log_ = nullptr;
  std::ostream * fn_request_log_ = nullptr;

  void log_detail(APIDefinitionList const & result) const;

  mutable std::unordered_map<std::string, unsigned> dll_cache;
};

class DecoratedDictionary : public APIDictionary {
 public:
  APIDefinitionList
  get_api_definition(
    const std::string & dll_name, const std::string & func_name) const override;

  APIDefinitionList
  get_api_definition(const std::string &, size_t) const override {
    return APIDefinitionList();
  }

  APIDefinitionList
  get_api_definition(rose_addr_t) const override {
    return APIDefinitionList();
  }

  bool handles_dll(std::string const &) const override {
    return false;
  }

  virtual std::string describe() const override {
    return "Decorated name parser";
  }
};

} // namespace pharos

#endif // Pharos_Dllapi_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
