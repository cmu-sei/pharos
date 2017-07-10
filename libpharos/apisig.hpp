// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_APISIG_H_
#define Pharos_APISIG_H_

#include <iostream>
#include <fstream>
#include <boost/ptr_container/ptr_vector.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_map/property_map.hpp>

namespace pharos {

enum ApiParamType {
  UNKN, RET, IN, OUT
};

const size_t INVALID_INDEX = UINT_MAX;

// this structure represents an API parameter taken from a signature
struct ApiSigParam {

  ApiSigParam() : name(""), type(UNKN) { }

  ApiSigParam(std::string n, ApiParamType t) {
    name = n;
    boost::to_upper(name);

    type = t;
  }

  ApiSigParam & operator=(const ApiSigParam & other);

  bool operator==(const ApiSigParam& other);

  ApiSigParam(const ApiSigParam &copy);

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

  ApiSigFuncParam(const ApiSigFuncParam &copy) : ApiSigParam(copy) {
    index = copy.index;
  }

  ApiSigFuncParam & operator=(const ApiSigFuncParam &other);

  bool operator==(const ApiSigFuncParam& other);

  std::string ToString() const;

  bool Validate() const;

  void Clear();

  size_t index;
};

typedef boost::ptr_vector<ApiSigFuncParam> ApiSigFuncParamsPtrVector;

// An Api function contains a name, set of parameters and possibly a return value
struct ApiSigFunc {

  ApiSigFunc() : name(""), has_params(false), has_retval(false) {
    retval.Clear();
    params.clear();
  }

  ApiSigFunc(const ApiSigFunc &copy);

  ApiSigFunc(std::string a) {

    name = a;
    boost::to_upper(name);

    has_params = false;
    params.clear();

    has_retval = false;
    retval.Clear();
  }

  ApiSigFunc & operator=(const ApiSigFunc & other);

  bool operator==(const ApiSigFunc& other);

  void Clear();

  bool Validate() const;

  std::string ToString() const;

  std::string name;

  bool has_params;
  ApiSigFuncParamsPtrVector params;

  bool has_retval;
  ApiSigParam retval;

};

typedef boost::ptr_vector<ApiSigFunc> ApiSigFuncPtrVector;

// A complete API signature
struct ApiSig {

  ApiSig & operator=(const ApiSig & other);

  // Copy constructor creates a deep, distinct copy of the ApiCfgComponent
  ApiSig(const ApiSig &copy);

  ApiSig() : api_count(0), name(""), description("") { }

  // The set of API calls
  ApiSigFuncPtrVector api_calls;

  // The number of API calls in this signature
  size_t api_count;

  // The name of the signature
  std::string name;

  // signature description
  std::string description;

  std::string category;

  std::string ToString() const;

};

typedef boost::ptr_vector<ApiSig> SigPtrVector;

typedef boost::ptr_vector<ApiSig>::iterator sig_iterator;

// this is the partial interface that signature parsers must implement
class ApiSigParser {
public:

  // A signature parser must implement this method
  virtual bool Parse(const std::string &sig_file, SigPtrVector *sigs, size_t *valid_sigs, size_t *error_sigs)=0;

  virtual ~ApiSigParser() { /* Nothing to do */ }
};

class ApiSigManager {

private:

  SigPtrVector sigs_;

  ApiSigParser *parser_;

  std::vector<std::string>filters_;

  size_t valid_sigs_, error_sigs_;

public:

  ApiSigManager() : parser_(NULL),valid_sigs_(0),error_sigs_(0) { }

  ApiSigManager(ApiSigParser *p) : parser_(p),valid_sigs_(0),error_sigs_(0) { }

  ~ApiSigManager();

  void SetParser(ApiSigParser *p);

  bool LoadSigFile(const std::string &sig_file);

  size_t NumValidSigs();

  size_t NumErrorSigs();

  void SetCategoryFilter(std::vector<std::string> f);

  void GetSigs(SigPtrVector *sig_list);

  size_t GetSigCount();
};

// A class to parse API signatures
class ApiJsonSigParser : public ApiSigParser {

private:

  void ParseApiPattern(boost::property_tree::ptree pattern, ApiSig *sig);

  bool Validate(ApiSig *sig) const;

  void ParseSigRetn(boost::property_tree::ptree ret_tree, ApiSigFunc *api);

  void ParseSigParams(boost::property_tree::ptree arg_tree, ApiSigFunc *api);

public:

  virtual ~ApiJsonSigParser() { }

  virtual bool Parse(const std::string &sig_file, SigPtrVector *sigs, size_t *valid_sigs, size_t *error_sigs);

};

// A class to parse API signatures
class ApiTextSigParser : public ApiSigParser {

private:

  bool ParseSigLine(const std::string sig_str, SigPtrVector *sigs);

public:

  virtual ~ApiTextSigParser() { }

  virtual bool Parse(const std::string &sig_file, SigPtrVector *sigs, size_t *valid_sigs, size_t *error_sigs);

  ApiTextSigParser() { }

  bool Load(std::string &sig_file);

};

} // namespace pharos

#endif  // Pharos_APISIG_H_
