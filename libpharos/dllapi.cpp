// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/foreach.hpp>
#include "dllapi.hpp"

typedef std::map<std::string, APIParam::inout_t> inout_map_t;

static inout_map_t create_inout_map()
{
  inout_map_t map;
  map["none"]  = APIParam::NONE;
  map["in"]    = APIParam::IN;
  map["out"]   = APIParam::OUT;
  map["inout"] = APIParam::INOUT;
  return map;
}

static inout_map_t inout_map = create_inout_map();

using pharos::ConfigNode;

void
FunctionDefinition::clear()
{
  calling_convention = calling_convertion_t();
  return_type = type_t();
  parameters.clear();
}

bool
JSONApiDictionary::get_function_definition(
  FunctionDefinition &fd, const std::string & dll_name, const std::string & func_name) const
{
  fd.clear();
  std::string name = dll_name;
  name.push_back(':');
  name.append(func_name);
  const ConfigNode fn_node = data["config"]["exports"][name]["function"];
  if (!fn_node) {
    return false;
  }
  const ConfigNode params = fn_node["parameters"];
  if (params) {
    for (ConfigNode::iterator i = params.begin(); i != params.end(); ++i) {
      const ConfigNode param = i->second;
      const ConfigNode namenode = param["name"];
      const ConfigNode typenode = param["type"];
      const ConfigNode inoutnode = param["inout"];
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
      fd.parameters.push_back(val);
    }
  }
  const ConfigNode rettype = fn_node["return"];
  if (rettype) {
    fd.return_type = rettype.Scalar();
  }
  const ConfigNode convention = fn_node["convention"];
  if (convention) {
    fd.calling_convention = convention.Scalar();
  }
  return true;
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
