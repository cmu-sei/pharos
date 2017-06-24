#ifndef PHAROS_TOOL
#define PHAROS_TOOL

#include <rose.h>
#include <vector>
#include <boost/property_map/property_map.hpp>

#include "pdg.hpp"
#include "misc.hpp"
#include "descriptors.hpp"
#include "masm.hpp"
#include "defuse.hpp"
#include "sptrack.hpp"
#include "options.hpp"

namespace pharos {

// This is the interface for all pharos analysis tools.
class IPharosTool {

public:

   virtual void AddOptions(ProgOptDesc &opt)=0;

   virtual bool RunTool(ProgOptVarMap &vm,
   std::vector<boost::property_tree::ptree> &json_results)=0;

   virtual ~IPharosTool() { /* Nothing to do */ }
};

} // namespace pharos

#endif
