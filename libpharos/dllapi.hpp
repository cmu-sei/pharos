// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Dllapi_H
#define Pharos_Dllapi_H

#include "config.hpp"

// This file contains a prototype version of a dll api query mechanism

typedef std::string type_t;
typedef std::string calling_convertion_t;

struct APIParam {
  typedef enum inout_en { NONE, IN, OUT, INOUT } inout_t;
  std::string name;
  type_t      type;
  inout_t     direction;
};

struct FunctionDefinition {
  calling_convertion_t  calling_convention;
  type_t                return_type;
  std::vector<APIParam> parameters;

  void clear();
};

class APIDictionary {
 public:
  //  Fill out the function information for the given DLL name and function name.  Return false
  // if the function cannot be found, true otherwise.
  virtual bool
  get_function_definition(
    FunctionDefinition &function_definition,
    const std::string & dll_name, const std::string & func_name) const = 0;
};


class JSONApiDictionary : public APIDictionary {
 public:
  JSONApiDictionary() {}

  bool
  get_function_definition(
    FunctionDefinition &function_definition,
    const std::string & dll_name, const std::string & func_name)
    const override;

  void
  load_json_file(const std::string & filename) {
    data.merge(filename);
  }

 private:
  pharos::Config data;
};


#endif // Pharos_Dllapi_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
