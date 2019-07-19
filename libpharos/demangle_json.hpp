// Copyright 2017-2018 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_demangle_json
#define Pharos_demangle_json

#include "demangle.hpp"
#include "json.hpp"

namespace demangle {

class JsonOutput {
 public:
  using Builder   = pharos::json::Builder;
  using Object    = pharos::json::Object;
  using ObjectRef = pharos::json::ObjectRef;
  using NodeRef   = pharos::json::NodeRef;

 public:
  JsonOutput(Builder const & b) : builder(b) {}
  void set_windows(bool b = true) {
    match = b;
  }
  ObjectRef convert(DemangledType const & sym) const;
  ObjectRef operator()(DemangledType const & sym) const {
    return convert(sym);
  }
  ObjectRef raw(DemangledType const & sym) const;

 private:
  Builder const & builder;
  bool match = false;

  void handle_symbol_type(Object & obj, DemangledType const & sym) const;
  void handle_scope(Object & obj, DemangledType const & sym) const;
  void handle_distance(Object & obj, DemangledType const & sym) const;
  void handle_method_property(Object & obj, DemangledType const & sym) const;
  void handle_namespace(Object & obj, DemangledType const & sym) const;
};

} // namespace demangle

#endif // Pharos_demangle_json

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
