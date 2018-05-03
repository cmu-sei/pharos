// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_OOJSONEXPORTER_H
#define Pharos_OOJSONEXPORTER_H

#include <rose.h>

#include <boost/property_map/property_map.hpp>

#include "misc.hpp"
#include "ooclass.hpp"

namespace pharos {

// This class creates a JSON output file for the class specification. The created JSON file is
// compatible with the JSON Importer IDA Plugin.
class OOJsonExporter {
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

  std::string demangle_class_name(std::string mangled_name);
  std::string demangle_method_name(std::string mangled_name);

public:

  // create a new JSON exporter with the JSON output filename.
  OOJsonExporter(ProgOptVarMap& vm);

  // default constructor for when there is no filename
  OOJsonExporter();

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

  // JSG isn't sure what to do with the object instances in OOAnalyzer? It remains commented
  // out for now
  // void generate_object_instances();

  // Generate the appropriate JSON data structure from the set of objects and
  // function calls.
  void generate_json(const std::vector<OOClassDescriptorPtr>& classes);

  boost::property_tree::ptree get_json();

};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
