#ifndef Pharos_OOMethod_H
#define Pharos_OOMethod_H

#include "ooelement.hpp"
#include "funcs.hpp"

namespace pharos {

enum class OOMethodType {
  UNKN,
  CTOR,
  DTOR,
  DELDTOR
};

// The OOMethod class is based on the folloing prolog query:
//
// finalMethodProperty(Method, constructor, certain)
//
//   This result marks that a Method is a constructor.
//   The 'certain' field is garbage and should be removed.
//
// finalMethodProperty(Method, deletingDestructor, certain)
//
//   This result marks that a method is a deleting destructor.
//   The 'certain' field is garbage and should be removed.
//
// finalMethodProperty(Method, realDestructor, certain)
//
//   This result marks that a method is a real destructor.
//   The 'certain' field is garbage and should be removed.
//
//   This is duplicative of the field in the finalClass result but it was more convenient to have
//   it reported consistently with otehr properties for debugging, so at present we're emitting
//   this result as well, but it may be eliminated in the future.
//
// finalMethodProperty(Method, virtual, certain)
//
//   This result marks that a method is declared virtual.
//   The 'certain' field is garbage and should be removed.
//
// Under the covers there is a FunctionDescriptor that backs the method up.
class OOMethod {

 private:

  // The address of the function
  rose_addr_t address_;

  // Method name
  std::string name_;

  // The function descriptor for this method
  const FunctionDescriptor* function_;

  // If the method is an import, this will be the proper descriptor
  const ImportDescriptor* import_;

  bool is_virtual_;

  OOMethodType type_;

  void set_descriptors();

  void generate_name();

 public:

  OOMethod()
    : address_(INVALID),
      name_(""),
      function_(nullptr),
      import_(nullptr),
      is_virtual_(false),
      type_(OOMethodType::UNKN) { }

  OOMethod(rose_addr_t a, OOMethodType t, bool v);

  OOMethod(rose_addr_t a);

  OOMethod(const FunctionDescriptor* fd);

  ~OOMethod() = default;

  OOMethod& operator=(const OOMethod& other) = default;

  rose_addr_t get_address() const;

  void set_type(OOMethodType new_type);

  bool is_constructor() const;

  bool is_destructor() const;

  bool is_deleting_destructor() const;

  bool is_virtual() const;

  void set_virtual(bool is_virt);

  void set_function_descriptor(const FunctionDescriptor* fd);

  const FunctionDescriptor* get_function_descriptor();

  void set_import_descriptor(const ImportDescriptor* id);

  const ImportDescriptor* get_import_descriptor();

  bool is_import() const;

  void set_name(std::string n);

  std::string get_name();

};

} // end namespace pharos

#endif
