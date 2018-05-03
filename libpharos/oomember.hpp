#ifndef Pharos_OOMember_H
#define Pharos_OOMember_H

#include <rose.h>

#include "ooelement.hpp"

// finalMember(Class, Offset, Sizes, certain)
//
//   The finalMember() result documents the existence of the definition of a member on a specific
//   class.  This fact is intended to only report the members defined on the class from a C++
//   source code perspective.
//
//   The Class is specified with a class identifier.  Offset is the positive offset into the
//   specified class (and not it's base or embedded classes).  Sizes is a list of all the
//   different sizes through which the member has been accessed anywhere in the program.
//
//   Embedded object and inherited bases are not listed again as finalMembers.  Instead they are
//   list in the finalEmbeddedObject and finalInheritance results.
//
//   The final field is garbage and should be removed.
//
// finalMemberAccess(Class, Offset, Size, EvidenceList)
//
//   The member at Offset in Class was accessed using the given Size by the list of evidence
//   instructions provided. The list of evidence instructions only contains instructions from the
//   methods assigned to the class.  Other accesses of base class members will appear in the
//   accesses for their respective classes.
//
//   Note that that presentation does not present knowledge about the class and subclass
//   relationships particularly clearly.  For those observations refer to finalMember() instead. which simplifies debugging as as duplicative of the RTTIAddress field.

namespace pharos {

class OOMember : public OOElement {

 private:

  void assess_type_from_size();

  virtual void generate_name();

 public:

  OOMember() = default;

  virtual ~OOMember() = default;

  OOMember(size_t s);

  OOMember(size_t s, size_t o);

  OOMember(size_t s, size_t o, InsnSet e);

  OOMember& operator=(const OOMember &other) = default;
};

} // end namespace pharos

#endif
