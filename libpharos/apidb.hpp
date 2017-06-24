// Copyright 2015, 2016, 2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Dllapi_H
#define Pharos_Dllapi_H

// This file contains a prototype version of a dll api query mechanism

#include <string>
#include <vector>
#include <memory>
#include <yaml-cpp/yaml.h>

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

class MultiApiDictionary;

class APIDictionary {
 public:
  enum handle_error_t { IGNORE, LOG_WARN, LOG_ERROR, THROW };

  static std::unique_ptr<APIDictionary> create_standard(
    const ProgOptVarMap & vm, handle_error_t handle = LOG_WARN);

  // Return the function information for the given DLL name and function name.  Return nullptr
  // if the function cannot be found.
  virtual APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, const std::string & func_name) const = 0;

  // Return the function information for the given DLL name and function name.  Return nullptr
  // if the function cannot be found.
  virtual APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, size_t ordinal) const = 0;

  // Return the function information for the given address.  Return nullptr if the function
  // cannot be found.
  virtual APIDefinitionPtr
  get_api_definition(rose_addr_t addr) const = 0;

  virtual ~APIDictionary() = default;

 private:
  static bool handle_node(MultiApiDictionary & db, const YAML::Node & node,
                          bool top, handle_error_t handle);
};

class MultiApiDictionary : public APIDictionary {
 public:
  virtual APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, const std::string & func_name)
    const override;

  APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, size_t ordinal)
    const override;

  APIDefinitionPtr
  get_api_definition(rose_addr_t addr) const override;

  void add(std::unique_ptr<APIDictionary> dict) {
    dicts.push_back(std::move(dict));
  }

 private:
  template <typename... T>
  APIDefinitionPtr _get_api_definition(T &&... args) const;

  std::vector<std::unique_ptr<APIDictionary>> dicts;
};

class JSONApiDictionary : public APIDictionary {
 public:
  JSONApiDictionary(const std::string & path);
  JSONApiDictionary(const YAML::Node & exports);
  ~JSONApiDictionary() override;
  JSONApiDictionary(JSONApiDictionary &&) noexcept;
  JSONApiDictionary &operator=(JSONApiDictionary &&);

  APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, const std::string & func_name)
    const override;

  APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, size_t ordinal)
    const override;

  APIDefinitionPtr
  get_api_definition(rose_addr_t addr) const override;

 private:
  bool known_dll(const std::string &dll_name) const;
  void load_json(const std::string & filename) const;
  void load_json(const YAML::Node & exports) const;

  struct Data;
  std::unique_ptr<Data> data;
  std::string directory;
};

class SQLLiteApiDictionary : public APIDictionary {
 public:
  class SQLError : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
  };

  SQLLiteApiDictionary(const std::string & lib_path);
  ~SQLLiteApiDictionary() override;
  SQLLiteApiDictionary(SQLLiteApiDictionary &&) noexcept;
  SQLLiteApiDictionary &operator=(SQLLiteApiDictionary &&);

  APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, const std::string & func_name)
    const override;

  APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, size_t ordinal)
    const override;

  APIDefinitionPtr
  get_api_definition(rose_addr_t addr) const override;

 private:
  struct Data;
  std::unique_ptr<Data> data;
  std::string lib_path;
};

class WinAWLookupPlan : public APIDictionary {
 public:
  WinAWLookupPlan(std::unique_ptr<APIDictionary> _subdict) : subdict(std::move(_subdict))
  {}

  APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, const std::string & func_name) const override;

  APIDefinitionPtr
  get_api_definition(
    const std::string & dll_name, size_t ordinal) const override;

  APIDefinitionPtr
  get_api_definition(rose_addr_t addr) const override;

 private:
  std::unique_ptr<APIDictionary> subdict;
};


} // namespace pharos

#endif // Pharos_Dllapi_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
