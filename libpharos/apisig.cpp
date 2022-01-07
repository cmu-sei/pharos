// Copyright 2015-2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <algorithm>    // std::copy
#include <iterator>

#include <boost/algorithm/string/erase.hpp>
#include <boost/optional/optional.hpp>
#include <boost/lexical_cast.hpp>
#include "apisig.hpp"

namespace pharos {

// ********************************************************************************************
// * Start of ApiSigParam methods
// ********************************************************************************************

bool ApiSigParam::operator==(const ApiSigParam& other) {
  return (name == other.name && type == other.type);
}

void ApiSigParam::Clear() {
  name = "";
  type = UNKN;
}

bool ApiSigParam::Validate() const {
  return (name!="" && type!=UNKN);
}

std::string ApiSigParam::ToString() const {
  std::ostringstream out_stream;
  out_stream << "Name: " << name << ", Type: " << ((type==ApiParamType::IN) ? "IN" : "OUT");
  return out_stream.str();
}

// ********************************************************************************************
// * Start of ApiSigFuncParam methods
// ********************************************************************************************

bool ApiSigFuncParam::operator==(const ApiSigFuncParam& other) {
  return (ApiSigParam::operator==(other) && index == other.index);
}

std::string ApiSigFuncParam::ToString() const {
  std::ostringstream out_stream;
  out_stream << ApiSigParam::ToString() << ", Index: " << index;

  return out_stream.str();
}

bool ApiSigFuncParam::Validate() const {
  return (ApiSigParam::Validate() && index!=INVALID_INDEX);
}
void ApiSigFuncParam::Clear() {
  ApiSigParam::Clear();
  index = INVALID_INDEX;
}

// ********************************************************************************************
// * Start of ApiSigFunc methods
// ********************************************************************************************

ApiSigFunc::ApiSigFunc(std::string a) {

  name = a;
  boost::to_upper(name);

  has_params = false;
  params.clear();

  has_retval = false;
  retval.Clear();
}

bool ApiSigFunc::Validate() const {

  if (has_params == true && params.size()==0) {
    return false;
  }

  if (has_params == false && params.size()>0) {
    return false;
  }

  for (const ApiSigFuncParam & p : params)  {
    if (!p.Validate()) {
      return false;
    }
  }

  if (has_retval) {
    if (retval.Validate() == false) {
      return false;
    }
  }
  return true;
}

void ApiSigFunc::Clear() {
  name = "";
  has_params = false;
  has_retval = false;
  params.clear();
  retval.Clear();
}

bool ApiSigFunc::operator==(const ApiSigFunc& other) {
  return (name == other.name);
}

std::string ApiSigFunc::ToString() const {

  std::ostringstream out_stream;

  out_stream << "Name: " << name << std::endl;

  if (has_retval) {
    out_stream << "Ret val: " << retval.ToString() << std::endl;
  }
  if (has_params) {
    out_stream << "Params: " << std::endl;

    for (ApiSigFuncParam p : params)  {
      out_stream << "   " << p.ToString() << std::endl;
    }
  }
  return out_stream.str();
}

// ********************************************************************************************
// * Start of ApiSig methods
// ********************************************************************************************

bool ApiSig::IsValid() {
  return (name != "" && api_count>0);
}

std::string ApiSig::ToString() const {

  std::ostringstream out_stream;

  out_stream << "Name: " << name << "\n"
             << "Description: " << description << "\n"
             << "Category: " << category << "\n"
             << "APIS:\n";

  for (const ApiSigFunc& f : api_calls) {
    out_stream << f.ToString() << "\n";
  }

  return out_stream.str();
}

// ********************************************************************************************
// * Start of ApiTextSigParser methods
// ********************************************************************************************

bool ApiTextSigParser::ParseSigLine(const std::string sig_str, ApiSigVector& sigs) {

  std::vector<std::string> sig_entry;

  boost::split(sig_entry, sig_str,boost::is_any_of(":"));

  if (sig_entry.size() == 2) {

    ApiSig sig;
    sig.name = sig_entry[0];

    std::string pattern = sig_entry[1];
    boost::to_upper(pattern);

    std::vector<std::string>sig_body;
    boost::split(sig_body, pattern, boost::is_any_of(","));

    sig.api_count = sig_body.size();


    for (std::string s : sig_body) {
      sig.api_calls.push_back(s);
    }

    sig.api_calls.resize(sig.api_count);

    sigs.push_back(sig);
    return true;
  }
  return false;
}

bool ApiTextSigParser::Parse(const std::string &sig_file, ApiSigVector& sigs,
                             size_t *valid_sigs, size_t *error_sigs) {

  std::ifstream in(sig_file.c_str());

  if (!in.is_open()) {
    return false;
  }

  std::string line;

  while (getline(in,line)) {

    // remove spaces
    boost::algorithm::erase_all(line, " ");
    boost::trim(line);

    if (line.empty() == true) {
      continue;
    }

    // check for comments
    if (line.at(0) == '#') {
      // skip comment lines
      continue;
    }

    // truncate in-line comments
    size_t found = line.find('#');
    if (found != std::string::npos) {
      line.resize(found);
    }

    if (ParseSigLine(line,sigs)) {
      (*valid_sigs)++;
    }
    else {
      (*error_sigs)++;
    }
  }

  return true;
}

// ********************************************************************************************
// * Start of ApiJsonSigParser methods
// ********************************************************************************************

void ApiJsonSigParser::ParseSigRetn(boost::property_tree::ptree ret_tree, ApiSigFunc& api) {

  api.retval.name = ret_tree.get<std::string>("Name","");
  api.retval.type = ApiSigFuncParam::ApiParamType::RET;

}

void ApiJsonSigParser::ParseSigParams(boost::property_tree::ptree arg_tree, ApiSigFunc& api) {

  for (boost::property_tree::ptree::value_type const& args : arg_tree) {

    ApiSigFuncParam param;

    boost::property_tree::ptree arg_list = args.second;

    param.name = arg_list.get<std::string>("Name","");
    param.index = boost::lexical_cast<size_t>(arg_list.get<std::string>("Index",""));

    std::string t = arg_list.get<std::string>("Type","");
    if (boost::iequals(t,"In") == true) {
      param.type = ApiSigFuncParam::ApiParamType::IN;
    }
    else if (boost::iequals(t,"OUT") == true) {
      param.type = ApiSigFuncParam::ApiParamType::OUT;
    }
    api.params.push_back(param);
  }
}

void ApiJsonSigParser::ParseApiPattern(boost::property_tree::ptree pattern, ApiSig& sig) {

  for (boost::property_tree::ptree::value_type const& seq : pattern) {

    boost::property_tree::ptree api_tree = seq.second;

    std::string a = api_tree.get<std::string>("API","");
    if (a != "") {

      ApiSigFunc api_entry(a);

      for (boost::property_tree::ptree::value_type const& entry : api_tree) {

        if (entry.first == "Args") {
          ParseSigParams(entry.second, api_entry);
          if (!api_entry.has_params) api_entry.has_params = true;
        }
        else if (entry.first == "Retn") {
          ParseSigRetn(entry.second, api_entry);
          if (!api_entry.has_retval) api_entry.has_retval = true;
        }
      }
      sig.api_calls.push_back(api_entry);
      sig.api_count++;
    }
  }
}

bool ApiJsonSigParser::Validate(ApiSig& sig) const {
  return (sig.api_count != 0 && sig.name != "");
}

bool ApiJsonSigParser::Parse(const std::string &sig_file,
                             ApiSigVector& sigs,
                             size_t *valid_sigs,
                             size_t *error_sigs) {

  boost::property_tree::ptree sigs_tree;
  boost::property_tree::read_json(sig_file, sigs_tree);

  for (boost::property_tree::ptree::value_type & sig_entry : sigs_tree) {

    if (boost::iequals(sig_entry.first,"Sig")) {

      ApiSig sig;
      for (boost::property_tree::ptree::value_type &entry : sig_entry.second) {

        if (true == boost::iequals(entry.first,"Name") && sig.name.empty()) {
          sig.name.assign(entry.second.get_value<std::string>());
        }
        else if (true == boost::iequals(entry.first,"Description") && sig.description.empty()) {
          sig.description = entry.second.get_value<std::string>();
        }
        else if (true == boost::iequals(entry.first,"Category") && sig.category.empty()) {
          sig.category = entry.second.get_value<std::string>();
        }
        else if (boost::iequals(entry.first,"Pattern")) {
          // parse the pattern if it exists
          ParseApiPattern(entry.second, sig);
        }
      }

      if (Validate(sig) == true) {
        sigs.push_back(sig);
        (*valid_sigs)++;
      }
      else {
        (*error_sigs)++;
      }
    }
  }
  return true;
}

// ********************************************************************************************
// * Start of ApiSigManager methods
// ********************************************************************************************

ApiSigManager::~ApiSigManager() {
  sigs_.clear();
}

void ApiSigManager::SetCategoryFilter(std::vector<std::string> f) {
  filters_ = f;
}

bool ApiSigManager::LoadSigFile(const std::string &sig_file) {

  if (parser_ != nullptr) {
    parser_->Parse(sig_file, sigs_, &valid_sigs_, &error_sigs_);
    return (valid_sigs_ > 0);
  }
  return false;
}

void ApiSigManager::SetParser(ApiSigParserPtr p) {
  parser_ = p;
}

size_t ApiSigManager::NumValidSigs() {
  return valid_sigs_;
}

size_t ApiSigManager::NumErrorSigs() {
  return error_sigs_;
}

void ApiSigManager::GetSigs(ApiSigVector& sig_list) {

  if (filters_.empty()) {
    sig_list = sigs_;
    return;
  }

  for (sig_iterator si=sigs_.begin(), end=sigs_.end(); si!=end; si++) {
    ApiSig sig = *si;
    for (const std::string& s : filters_) {
      if (boost::iequals(sig.category, s) == true) {
        sig_list.push_back(sig);
      }
    }
  }
}

size_t ApiSigManager::GetSigCount() {
  return sigs_.size();
}

} // namespace pharos

