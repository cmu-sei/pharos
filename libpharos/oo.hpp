// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_OO_Forward_Declarations_H
#define Pharos_OO_Forward_Declarations_H

#include <rose.h>

// This header is intended to simplify some of the forward declaration circular include
// problems in the complicated OO analysis infrastructure.  It should only include declarations
// that require no additional include.  For clarity is should try to avoid definiing things
// that are not required.

namespace pharos {

// Forward declaration of Member because class defintions contain methods, and members
// reference the class description for
class ThisCallMethod;

// This is to keep members in the ThisCallMethodSet in a consistent address order.
struct ThisCallMethodCompare {
  bool operator()(const ThisCallMethod *x, const ThisCallMethod *y) const;
};

// Specifically, the class description needs a set of methods associate with the class.
typedef std::set<ThisCallMethod*, ThisCallMethodCompare> ThisCallMethodSet;

// Maps the call instructions to the methods they call.  This is another way of representing
// the method set above, but is needed (at least temporarily) for dominance analysis.
typedef std::map<SgAsmInstruction* , ThisCallMethodSet> MethodEvidenceMap;

// For recording inherited methods...
typedef std::map<ThisCallMethod*, int> InheritedMethodMap;

// Forward declaration of class descriptors so that members can reference the type of the
// embedded object (currently unimplemented).
class ClassDescriptor;

// Methods and object uses both need a list of the classes that call them.
struct ClassDescriptorCompare {
  bool operator()(const ClassDescriptor* x, const ClassDescriptor* y) const;
};
typedef std::set<ClassDescriptor*, ClassDescriptorCompare> ClassDescriptorSet;

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
