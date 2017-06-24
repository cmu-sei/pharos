// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_JSON_OO_H
#define Pharos_JSON_OO_H

#include <rose.h>

#include <boost/property_map/property_map.hpp>

#include "misc.hpp"
#include "class.hpp"

namespace pharos {

// This class creates a JSON output file for the class specification. The created JSON file is
// compatible with the JSON Importer IDA Plugin.
class ObjdiggerJsonExporter {
private:

  // the name of the JSON output file. Currently, the name of the file is
  // [Orignal executable].json
  std::string json_filename;

  //top-level property trees for the JSON output
  boost::property_tree::ptree structs;
  boost::property_tree::ptree cls_usages;
  boost::property_tree::ptree object_instances;

  // Used for counting the number of unique methods that we associated with classes.  This
  // doesn't have to be in the JSON exporter, but it's convenient here.
  AddrSet methods_associated;
  size_t vcalls_resolved;
  size_t usages_found;

public:

  // create a new JSON exporter with the JSON output filename.
  ObjdiggerJsonExporter(ProgOptVarMap& vm);

  // default constructor for when there is no filename
  ObjdiggerJsonExporter();

  // this function exports the JSON to a file.
  void export_json(void);

  void set_json_filename(std::string fn) {
     json_filename = fn;
  }

  // C++11 was picky about auto-converting const char[] to string and to boost::property_tree
  // simultaneously, so we had to make a helper function that was a little more explicit.
  std::pair<const std::string, boost::property_tree::ptree>
  make_ptree(const std::string s1, const std::string s2) {
    return std::make_pair(s1, boost::property_tree::ptree(s2));
  }

  void generate_object_instances();

  // Generate the appropriate JSON data structure from the set of objects and
  // function calls.
  void generate_json(const ClassDescriptorMap &objects);

  boost::property_tree::ptree get_json();

};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
