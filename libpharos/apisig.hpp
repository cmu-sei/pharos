// Copyright 2015-2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_APISIG_H_
#define Pharos_APISIG_H_

#include <iostream>
#include <fstream>

// Define to an annoying warning in later versions of Boost that results from including the
// property_tree stuff.
#define BOOST_BIND_GLOBAL_PLACEHOLDERS 1

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_map/property_map.hpp>

namespace pharos {

const size_t INVALID_INDEX = UINT_MAX;

// this structure represents an API parameter taken from a signature
struct ApiSigParam {

  enum ApiParamType {
    UNKN, RET, IN, OUT
  };

  ApiSigParam() : name(""), type(UNKN) { }

  ApiSigParam(std::string n, ApiParamType t) {
    name = n;
    boost::to_upper(name);
    type = t;
  }

  bool operator==(const ApiSigParam& other);
  void Clear();
  bool Validate() const;
  std::string ToString() const;
  std::string name;
  ApiParamType type;
};

// A parameter passed to a function has an index
struct ApiSigFuncParam : public ApiSigParam {

  ApiSigFuncParam() : index(INVALID_INDEX) { }

  ApiSigFuncParam(std::string n, ApiParamType t, size_t i)
    : ApiSigParam(n,t), index(i) { }

  ~ApiSigFuncParam() = default;

  bool operator==(const ApiSigFuncParam& other);

  std::string ToString() const;

  bool Validate() const;

  void Clear();

  size_t index;
};

using ApiSigFuncParamVector = std::vector<ApiSigFuncParam>;

// An Api function contains a name, set of parameters and possibly a return value
struct ApiSigFunc {

  ApiSigFunc() : name(""), has_params(false), has_retval(false) {
    retval.Clear();
    params.clear();
  }

  ApiSigFunc(std::string a);

  bool operator==(const ApiSigFunc& other);

  void Clear();

  bool Validate() const;

  std::string ToString() const;

  std::string name;

  bool has_params;
  ApiSigFuncParamVector params;

  bool has_retval;
  ApiSigParam retval;

};

using ApiSigFuncVector = std::vector<ApiSigFunc>;

// A complete API signature
struct ApiSig {

  ApiSig() : api_count(0), name(""), description("") { }

  // The set of API calls for this signature
  ApiSigFuncVector api_calls;

  // The number of API calls in this signature
  size_t api_count;
  std::string name;
  std::string description;
  std::string category;
  std::string ToString() const;
  bool IsValid();

};

using ApiSigVector = std::vector<ApiSig>;

using sig_iterator = ApiSigVector::iterator;

// this is the partial interface that signature parsers must implement
class ApiSigParser {
 public:
  // A signature parser must implement this method
  virtual bool Parse(const std::string &sig_file, ApiSigVector& sigs, size_t *valid_sigs, size_t *error_sigs)=0;
  virtual ~ApiSigParser() { /* Nothing to do */ }
};

using ApiSigParserPtr = std::shared_ptr<ApiSigParser>;

class ApiSigManager {
 private:

  ApiSigVector sigs_;

  ApiSigParserPtr parser_;

  std::vector<std::string>filters_;

  size_t valid_sigs_, error_sigs_;

 public:

  ApiSigManager() : parser_(nullptr), valid_sigs_(0), error_sigs_(0) { }

  ApiSigManager(ApiSigParserPtr p) : parser_(p), valid_sigs_(0), error_sigs_(0) { }

  ~ApiSigManager();

  void SetParser(ApiSigParserPtr p);

  bool LoadSigFile(const std::string &sig_file);

  size_t NumValidSigs();

  size_t NumErrorSigs();

  void SetCategoryFilter(std::vector<std::string> f);

  void GetSigs(ApiSigVector& sig_list);

  size_t GetSigCount();
};

// A class to parse API signatures
class ApiJsonSigParser : public ApiSigParser {

 private:

  void ParseApiPattern(boost::property_tree::ptree pattern,
                       ApiSig& sig);

  bool Validate(ApiSig& sig) const;

  void ParseSigRetn(boost::property_tree::ptree ret_tree, ApiSigFunc& api);

  void ParseSigParams(boost::property_tree::ptree arg_tree, ApiSigFunc& api);

 public:

  virtual ~ApiJsonSigParser() { }

  virtual bool Parse(const std::string &sig_file,
                     ApiSigVector& sigs,
                     size_t *valid_sigs,
                     size_t *error_sigs);
};

// A class to parse API signatures
class ApiTextSigParser : public ApiSigParser {

 private:

  bool ParseSigLine(const std::string sig_str, ApiSigVector& sigs);

 public:

  virtual ~ApiTextSigParser() { }

  virtual bool Parse(const std::string &sig_file, ApiSigVector& sigs,
                     size_t *valid_sigs, size_t *error_sigs);

  ApiTextSigParser() { }

  bool Load(std::string &sig_file);

};

} // namespace pharos

#endif  // Pharos_APISIG_H_
