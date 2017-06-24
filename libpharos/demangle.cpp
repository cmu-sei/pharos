#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <boost/format.hpp>

#include "demangle.hpp"

// Perhaps we should eliminated the unused parameters (basically all match booleans to the
// str_xxx functions).  Right now it's easier fo rthem all to match though...
#define UNUSED __attribute__((unused))

// An alias to make it easier to construct namespace types.
class Namespace : public DemangledType {
 public:
  Namespace(std::string n) : DemangledType() {
    is_namespace = true; simple_type = n;
  }
};

class VisualStudioDemangler
{
 private:
  const std::string & mangled;
  bool debug;
  size_t offset;
  std::string error;

  // These are pointers because we need to swap them out when we enter and leave templates.
  ReferenceStack name_stack;
  ReferenceStack type_stack;

  char get_next_char();
  char get_current_char();
  void advance_to_next_char();

  void bad_code_msg(char c, std::string desc);
  void general_error(std::string e);

  // Given a stack and a position character, safely resolve and return the reference.
  DemangledTypePtr resolve_reference(ReferenceStack & stack, char poschar);

  DemangledTypePtr get_type(DemangledTypePtr t = DemangledTypePtr(), bool push = true);
  DemangledTypePtr & get_pointer_type(DemangledTypePtr & t, bool push = true);
  DemangledTypePtr & get_templated_type(DemangledTypePtr & t);
  DemangledTypePtr & get_templated_function_arg(DemangledTypePtr & t);
  DemangledTypePtr & get_return_type(DemangledTypePtr & t);
  DemangledTypePtr & get_fully_qualified_name(DemangledTypePtr & t, bool push = true);
  DemangledTypePtr & get_symbol_type(DemangledTypePtr & t);
  DemangledTypePtr & get_function(DemangledTypePtr & t);
  DemangledTypePtr & get_storage_class(DemangledTypePtr & t);
  DemangledTypePtr & get_storage_class_modifiers(DemangledTypePtr & t);
  DemangledTypePtr & get_real_enum_type(DemangledTypePtr & t);
  DemangledTypePtr & get_rtti(DemangledTypePtr & t);
  DemangledTypePtr & process_return_storage_class(DemangledTypePtr & t);
  DemangledTypePtr & process_calling_convention(DemangledTypePtr & t);
  DemangledTypePtr & process_method_storage_class(DemangledTypePtr & t);
  DemangledTypePtr & get_special_name_code(DemangledTypePtr & t);
  DemangledTypePtr get_anonymous_namespace();

  // Get symbol always allocates a new DemangledType.
  DemangledTypePtr get_symbol();

  // This is a mocked up helper for basic types.   More work is needed.
  DemangledTypePtr & update_simple_type(DemangledTypePtr & t, const std::string & name);
  DemangledTypePtr & update_method(DemangledTypePtr & t, Scope scope,
                                   MethodProperty property, Distance distance);
  DemangledTypePtr & update_member(DemangledTypePtr & t, Scope scope, MethodProperty property);
  DemangledTypePtr & update_storage_class(DemangledTypePtr & t, Distance distance,
                                          bool is_const, bool is_volatile,
                                          bool is_func, bool is_based, bool is_member);

  std::string get_literal();
  void get_symbol_start();
  int64_t get_number();

  // Some helper functions to make debugging a little prettier.
  void progress(std::string msg);
  void stack_debug(ReferenceStack & stack, size_t position, const std::string & msg);

 public:

  VisualStudioDemangler(const std::string & mangled, bool debug = false);

  DemangledTypePtr analyze();
};

DemangledTypePtr visual_studio_demangle(const std::string & mangled, bool debug)
{
  VisualStudioDemangler demangler(mangled, debug);
  return demangler.analyze();
}

DemangledType::DemangledType() {
  is_const = false;
  is_volatile = false;
  is_reference = false;
  is_pointer = false;
  is_namespace = false;
  is_func = false;
  is_embedded = false;
  is_refref = false;
  is_anonymous = false;
  is_based = false;
  is_member = false;
  symbol_type = SymbolType::Unspecified;
  distance = Distance::Unspecified;
  pointer_base = 0;
  inner_type = NULL;
  com_interface = NULL;

  // Properties from function.
  scope = Scope::Unspecified;
  method_property = MethodProperty::Unspecified;
  is_exported = false;
  is_ctor = false;
  is_dtor = false;
}

void DemangledType::debug_type(bool match, size_t indent, std::string label) const {
  size_t x = 0;
  while (x < indent) {
    std::cout << "  ";
    x++;
  }

  std::cout << "(ST=" << (int)symbol_type << ") "
            << "(isFunc=" << is_func << ") " << label << ": ";
  std::cout << str(match) << std::endl;

  if (is_pointer || is_reference) {
    if (inner_type) inner_type->debug_type(match, indent + 1, "PtrT");
  }

  if (retval) retval->debug_type(match, indent + 1, "RVal");

  size_t i = 0;
  for (const auto & n : name) {
    n->debug_type(match, indent + 1, boost::str(boost::format("Name %d") % i));
    i++;
  }


  i = 0;
  for (const auto & p : template_parameters) {
    if (p->type != NULL) {
      p->type->debug_type(match, indent + 1, boost::str(boost::format("TPar %d") % i));
    }
    else {
      x = 0;
      while (x++ < indent + 1) std::cout << "  ";
      std::cout << boost::str(boost::format("TPar %d") % i) << std::endl;
    }
    i++;
  }

  i = 0;
  for (const auto & a : args) {
    a->debug_type(match, indent + 1, boost::str(boost::format("FArg %d") % i));
    i++;
  }
}

// If this Type a pointer or a reference to a function? (Which requires special formatting)
// Should it include is_refref?  Should is_func be merged with SymbolType?
bool DemangledType::is_func_ptr() const {
  if (is_pointer || is_reference) {
    if (inner_type && inner_type->is_func) {
      return true;
    }
  }
  return false;
}

std::string DemangledType::str_class_properties(bool match) const {
  std::ostringstream stream;

  // I should convert these enums to use the enum stringifier...
  if (scope == Scope::Private) stream << "private: ";
  if (scope == Scope::Protected) stream << "protected: ";
  if (scope == Scope::Public) stream << "public: ";

  if (method_property == MethodProperty::Static) stream << "static ";
  if (method_property == MethodProperty::Virtual) stream << "virtual ";
  // The formatting of thunks is not correct.
  if (match && method_property == MethodProperty::Thunk) stream << "thunk ";
  return stream.str();
}

std::string DemangledType::str_distance(bool match) const {
  std::ostringstream stream;

  if (!match && distance == Distance::Near) stream << "near ";
  if (distance == Distance::Far) stream << "far ";
  if (distance == Distance::Huge) stream << "huge ";

  return stream.str();
}

std::string
DemangledType::str_storage_properties(bool match, bool is_retval) const
{
  // The MSVC standard is to discard the const and volatile qualifiers on return values that
  // are pointers, references or rvalue references...  Or something like that.  This is
  // obviously a bit of a special case.  The source is allowed to have this qualifier, and the
  // mangled name codes it correctly as P/Q/R/S, so when we're not trying to match Visual
  // Studio, it's probably better to retain the qualifier.
  if (match && (is_pointer || is_reference || is_refref) && is_retval) {
    if (pointer_base == 1) return "__ptr64 ";
    return "";
  }

  if (pointer_base == 0 && !is_const && !is_volatile) return "";

  std::ostringstream stream;
  if (is_const) stream << "const ";
  if (is_volatile) stream << "volatile ";
  if (pointer_base == 1) stream << " __ptr64 ";
  return stream.str();
}

std::string
DemangledType::str_function_arguments(bool match) const
{
  std::ostringstream stream;

  stream << "(";
  // And now the arguments, as usual...
  for (FunctionArgs::const_iterator ait = args.begin(); ait != args.end(); ait++) {
    stream << (*ait)->str(match);
    if ((ait+1) != args.end()) {
      stream << ",";
      if (!match) stream << " ";
    }
  }

  stream << ")";
  if (!match) stream << " ";
  return stream.str();
}

std::string
DemangledType::str_template_parameters(bool match) const
{
  std::ostringstream stream;

  if (template_parameters.size() != 0) {
    std::string tpstr;
    stream << "<";
    DemangledTemplate::const_iterator pit;
    for (pit = template_parameters.begin(); pit != template_parameters.end(); pit++) {
      auto tp = *pit;
      if (!tp) {
        std::cerr << "Unexpectedly NULL template parameter!" << std::endl;
      }
      else {
        tpstr = tp->str(match);
        stream << tpstr;
      }
      if ((pit+1) != template_parameters.end()) {
        if (!match) stream << ", ";
        else stream << ",";
      }
    }

    if (tpstr.size() > 0 && tpstr.back() == '>') {
      stream << " ";
    }

    stream << ">";
  }

  return stream.str();
}

std::string
DemangledType::str_name_qualifiers(const FullyQualifiedName& the_name, bool match) const
{
  std::ostringstream stream;

  FullyQualifiedName::const_iterator nit;
  for (nit = the_name.begin(); nit != the_name.end(); nit++) {
    auto & ndt = *nit;
    // Some names have things that require extra quotations...
    if (ndt->is_embedded) {
      stream << "`";
      std::string rendered = ndt->str(match);
      // Some nasty whitespace kludging here.  If the last character is a space, remove it.
      // There's almost certainly a better way to do this.  Perhaps all types ought to remove
      // their own trailing spaces?
      if (rendered.size() > 1 && rendered.back() == ' ') {
        rendered = rendered.substr(0, rendered.size() - 1);
      }
      stream << rendered;
      stream << "'";
    }
    else {
      stream << ndt->str(match);
    }
    if ((nit+1) != the_name.end()) stream << "::";
  }

  return stream.str();
}

// This should eventually me merged with str_name_qualifiers().  The code should also get
// shared between functions and non-functions, since there's a lot of similarity.  In summary,
// there's a lot of cleanup needed here, but it's not related to my immediate problem.
std::string
DemangledType::str_class_name(bool match) const
{
  std::ostringstream stream;

  const DemangledType* clsname = this;
  if (is_ctor || is_dtor) {
    stream << "::";
    if (is_dtor) stream << "~";
    if (template_parameters.size() != 0) {
      clsname = &*template_parameters[template_parameters.size() - 1]->type;
    }

    size_t name_size = clsname->name.size();
    if (name_size != 0) {
      stream << clsname->name[name_size-1]->str(match);
    }
    else {
      stream << "ERRORNOCLASS";
    }
  }
  else if (method_name.size() != 0) {
    // Some methods don't have class names (e.g. new and delete)...
    if (clsname->name.size() > 0) {
      stream << "::";
    }
    stream << method_name;

    // And since we deferred outputting the return type for "operator <type>" earlier, we need
    // to do it here...
    if (method_name == "operator " && retval) {
      stream << retval->str(match);
    }
  }

  return stream.str();
}

// Public API to get the method name used by the OOAnalzyer.  This should get cleaned up so
// that it just returns the method_name member.  It's very similar to str_class_name, but lacks
// extra '::'s in the output.
std::string
DemangledType::get_method_name() const
{
  std::ostringstream stream;

  bool match = false;
  const DemangledType* clsname = this;
  if (is_ctor || is_dtor) {
    if (is_dtor) stream << "~";
    if (template_parameters.size() != 0) {
      clsname = &*template_parameters[template_parameters.size() - 1]->type;
    }

    size_t name_size = clsname->name.size();
    if (name_size != 0) {
      stream << clsname->name[name_size-1]->str(match);
    }
    else {
      stream << "ERRORNOCLASS";
    }
  }
  else if (method_name.size() != 0) {
    stream << method_name;
  }
  else {
    size_t name_size = clsname->name.size();
    if (name_size != 0) {
      stream << clsname->name[name_size-1]->str(match);
    }
  }

  return stream.str();
}

// Public API to get class name used by the OOAnalzyer.  This has sort-of turned into a 'do
// what oosolver needs' method. :-(
std::string
DemangledType::get_class_name() const
{
  std::ostringstream stream;

  bool match = false;

  // This is now largely a copy of str_name_qualifiers(), so it's the third version of that
  // function. :-( This version needs to exclude the method name when it's a non-standard name.
  size_t name_size = name.size();
  if (name_size != 0) {
    size_t pos = 0;
    FullyQualifiedName::const_iterator nit;
    for (nit = name.begin(); nit != name.end(); nit++) {
      auto & ndt = *nit;
      // Some names have things that require extra quotations...
      if (ndt->is_embedded) {
        stream << "`";
        std::string rendered = ndt->str(match);
        // Some nasty whitespace kludging here.  If the last character is a space, remove it.
        // There's almost certainly a better way to do this.  Perhaps all types ought to remove
        // their own trailing spaces?
        if (rendered.size() > 1 && rendered.back() == ' ') {
          rendered = rendered.substr(0, rendered.size() - 1);
        }
        stream << rendered;
        // This quote is mismatched because Cory didn't want to cause problems for Prolog.
        stream << "`";
      }
      else {
        stream << ndt->str(match);
      }
      pos++;

      // This is very confusing. :-( Currently the method name is in the fully qualified name
      // if it's user-supplied name, and it's in method name if it's any of the special names
      // except for constructors and destructors.  We didn't put the name in the method_name
      // field for contructors and destructors because we didn't know the class name yet!
      bool has_fake_name = (method_name.size() != 0 || is_ctor || is_dtor);
      if ((pos+1) == name_size && !has_fake_name) break;

      if ((nit+1) != name.end()) stream << "::";
    }
  }

  return stream.str();
}

std::string
DemangledType::str_pointer_punctuation(UNUSED bool match) const
{
  if (is_refref) return "&&";
  if (is_pointer) return "*";
  if (is_reference) return "&";
  return "";
}

std::string
DemangledType::str_simple_type(UNUSED bool match) const
{
  std::ostringstream stream;
  // A simple type.
  if (simple_type.size() != 0) {
    stream << simple_type;
    // Add a space after union, struct, class and enum?
    if (name.size() != 0) stream << " ";
  }
  return stream.str();
}

std::string
DemangledType::str(bool match, bool is_retval) const
{
  // If we're a namespace just return our simple_type name (hackish) and we're done.
  if (is_namespace) {
    if (is_anonymous) {
      if (!match) return "'anonymous namespace " + simple_type + "'";
      else return std::string("`anonymous namespace'");
    }
    else {
      return simple_type;
    }
  }

  std::ostringstream stream;
  stream << str_class_properties(match);

  // Partially conversion from old code and partially simplification of this method.
  if (symbol_type == SymbolType::GlobalFunction || symbol_type == SymbolType::ClassMethod) {

    stream << str_distance(match);
    // Guessing at formatting..
    if (is_exported) stream << "__declspec(dllexport)";

    // Annoying, but we currently have a retval for non-existent return values, which causes
    // use to emit an extra space.  Perhaps there's a cleaner way to do this?  Another very
    // annoying special case is that for "operator <type>", the return code becomes part of the
    // method name, but is _NOT_ explicitly part of the type... :-( Increasingly it looks like
    // we should precompute where we want the retval to be rendered, and then emit it only
    // where we decided.
    if (retval && method_name != "operator ") {
      std::string retstr;
      if (retval->is_func_ptr()) {
        retstr = retval->str(match, true);
        //stream << "!";
        if (retstr.size() > 0) stream << retstr;
        //stream << "!";
      }
      else {
        retstr = retval->str(match, true);
        //stream << "!";
        if (retstr.size() > 0) stream << retstr << " ";
        //stream << "!";
      }
    }

    stream << calling_convention << " ";
    stream << str_name_qualifiers(name, match);
    // str_class_name() currently includes the fixes for moving the retval on "operator ".
    stream << str_class_name(match);
    stream << str_function_arguments(match);
    stream << str_storage_properties(match);

    if (retval && retval->is_func_ptr()) {
      //stream << "|";
      stream << ")";
      // The name of the function is not present...
      stream << retval->inner_type->str_function_arguments(match);
      stream << retval->inner_type->str_storage_properties(match);
      //stream << "|";
    }

    return stream.str();
  }

  if (is_pointer || is_reference) {
    if (inner_type == NULL) {
      std::cerr << "Unparse error: Inner type is not set for pointer or reference!" << std::endl;
    }
    else {
      if (inner_type->is_func) {
        // Less drama is required for non-existent return values because you can't pass constructors,
        // destructors, and opertator overloads?
        stream << inner_type->retval->str(match, true);
        // The calling convention is formatted differently...
        stream << " (" << inner_type->calling_convention;
      }
      else {
        stream << inner_type->str(match) << " ";
      }

      stream << str_pointer_punctuation(match);
    }
  }

  stream << str_distance(match);
  stream << str_simple_type(match);
  stream << str_name_qualifiers(name, match);
  stream << str_template_parameters(match);

  // Ugly. :-( Move the space from after the storage keywords to before the keywords.
  std::string spstr = str_storage_properties(match, is_retval);
  if (spstr.size() > 0) stream << " " << spstr.substr(0, spstr.size() - 1);

  // If the symbol is a global object or a static class member, the name of the object (not the
  // type) will be in the instance_name and not the ordinary name field.
  if (symbol_type == SymbolType::GlobalObject || symbol_type == SymbolType::StaticClassMember ||
      symbol_type == SymbolType::GlobalThing1 || symbol_type == SymbolType::GlobalThing2) {
    stream << " ";
    stream << str_name_qualifiers(instance_name, match);
    if (symbol_type == SymbolType::GlobalThing1 || symbol_type == SymbolType::GlobalThing2) {
      // This logic is messy.  GlobalThing1 sometimes has no method name, and therefore neeeds no
      // ::, but is it really the case the GlobalThing1 _never_ has a method name?  Also related
      // to str_class_name().
      if (method_name.size() > 0) {
        stream << "::" << method_name;
      }
    }
  }

  // This is kind of ugly and hackish...  It's the second half of the pointer to function
  // logic.  There's probably a cleaner way to do this using a different kind of recursion.
  if (!is_retval && is_func_ptr()) {
    //stream << "|";
    stream << ")";
    // The name of the function is not present...
    stream << inner_type->str_function_arguments(match);
    stream << inner_type->str_storage_properties(match);
    //stream << "|";
  }

  if (com_interface != NULL) {
    stream << "{for `" << com_interface->str(match) << "'}";
  }

  return stream.str();
}

DemangledTemplateParameter::DemangledTemplateParameter(DemangledTypePtr t)
  : type(t), constant_value(0)
{}

DemangledTemplateParameter::DemangledTemplateParameter(int64_t c)
  : type(nullptr), constant_value(c)
{}

std::string DemangledTemplateParameter::str(bool match) const {
  if (type == NULL) {
    return boost::str(boost::format("%d") % constant_value);
  }
  else if (pointer) {
    return boost::str(boost::format("std::addressof(%s)") % type->str(match));
  } else {
    return type->str(match);
  }
}


VisualStudioDemangler::VisualStudioDemangler(const std::string & m, bool d)
  : mangled(m), debug(d), offset(0)
{}

char VisualStudioDemangler::get_next_char()
{
  // Check bounds and all that...
  offset++;
  return get_current_char();
}

void VisualStudioDemangler::advance_to_next_char()
{
  offset++;
}

char VisualStudioDemangler::get_current_char()
{
  if (offset >= mangled.size()) {
    error = "Attempt to read past end of mangled string.";
    throw DemanglerError(error);
  }
  return mangled[offset];
}

void VisualStudioDemangler::bad_code_msg(char c, std::string desc)
{
  error = boost::str(boost::format("Unrecognized %s code '%c' at offset %d") % desc % c % offset);
  std::cerr << error << std::endl;
}

void VisualStudioDemangler::general_error(std::string e)
{
  error = e;
  std::cerr << error << std::endl;
  throw DemanglerError(error);
}

void VisualStudioDemangler::progress(std::string msg)
{
  if (debug) {
    std::cout << "Parsing " << msg << " at character '" << get_current_char()
              << "' at offset " << offset << std::endl;
  }
}

void VisualStudioDemangler::stack_debug(
  ReferenceStack & stack, size_t position, const std::string & msg)
{
  std::string address = boost::str(boost::format("%p") % &stack);
  std::string entry;

  if (!debug) return;

  if (stack.size() >= position + 1) {
    entry = stack.at(position)->str();
  }
  else {
    entry = boost::str(boost::format("INVALID") % position);
  }

  std::cout << "Pushing " << msg << " position " << position << " in stack at address "
            << address << " refers to " << entry << std::endl;

  if (true) {
    std::cout << "The full " << msg << " stack currently contains:" << std::endl;
    size_t p = 0;
    for (auto & t : stack) {
      std::cout << "  " << p << " : " << t->str() << std::endl;
      p++;
    }
  }
}

DemangledTypePtr & VisualStudioDemangler::process_calling_convention(DemangledTypePtr & t)
{
  progress("calling convention");
  char c = get_current_char();
  switch(c) {
   case 'A': t->is_exported = false; t->calling_convention = "__cdecl"; break;
   case 'B': t->is_exported = true;  t->calling_convention = "__cdecl"; break;
   case 'C': t->is_exported = false; t->calling_convention = "__pascal"; break;
   case 'D': t->is_exported = true;  t->calling_convention = "__pascal"; break;
   case 'E': t->is_exported = false; t->calling_convention = "__thiscall"; break;
   case 'F': t->is_exported = true;  t->calling_convention = "__thiscall"; break;
   case 'G': t->is_exported = false; t->calling_convention = "__stdcall"; break;
   case 'H': t->is_exported = true;  t->calling_convention = "__stdcall"; break;
   case 'I': t->is_exported = false; t->calling_convention = "__fastcall"; break;
   case 'J': t->is_exported = true;  t->calling_convention = "__fastcall"; break;
   case 'K': t->is_exported = false; t->calling_convention = "__unknown"; break;
   case 'L': t->is_exported = true;  t->calling_convention = "__unknown"; break;
   case 'M': t->is_exported = false; t->calling_convention = "__clrcall"; break;
   default:
    bad_code_msg(c, "calling convention");
    throw DemanglerError(error);
  }

  advance_to_next_char();
  return t;
}

DemangledTypePtr &
VisualStudioDemangler::update_simple_type(DemangledTypePtr & t, const std::string & name)
{
  t->simple_type = name;
  advance_to_next_char();
  return t;
}

DemangledTypePtr &
VisualStudioDemangler::get_storage_class_modifiers(DemangledTypePtr & t)
{
  char c = get_current_char();

  // Type storage class modifiers.  These letters are currently non-overlapping with the
  // storage class and can occur zero or more times.  Technically it's probably invalid for
  // them to occur more than once each however.
  while (c == 'E' || c == 'F' || c == 'I') {
    progress("pointer storage class modifier");
    if (c == 'E') t->pointer_base = 1; // <type> __ptr64
    else if (c == 'F') {} // __unaligned <type>   BUG!!! Unimplemented!
    else if (c == 'I') {} // <type> __restrict    BUG!!! Unimplemented!
    c = get_next_char();
  }

  return t;
}

// Pointer base codes.  Agner Fog's Table 13.
DemangledTypePtr &
VisualStudioDemangler::get_pointer_type(DemangledTypePtr & t, bool push)
{
  advance_to_next_char();
  get_storage_class_modifiers(t);

  progress("pointer storage class");
  // Const and volatile for the thing being pointed to (or referenced).
  t->inner_type = std::make_shared<DemangledType>();
  get_storage_class(t->inner_type);

  // Hack (like undname).
  if (t->inner_type->is_func) {
    progress("function pointed to");
    get_function(t->inner_type);
  }
  else {
    progress("type pointed to");
    t->inner_type = get_type(t->inner_type, false);
  }
  if (debug) {
    std::cout << "Inner type was: " << t->inner_type->str() << std::endl;
  }

  // Add the type to the type stack.
  if (push) {
    type_stack.push_back(t);
    stack_debug(type_stack, type_stack.size()-1, "type");
  }
  return t;
}

DemangledTypePtr & VisualStudioDemangler::get_real_enum_type(DemangledTypePtr & t) {
  char c = get_current_char();
  progress("enum real type");
  auto & rt = t->enum_real_type = std::make_shared<DemangledType>();
  switch(c) {
   case '0': update_simple_type(rt, "signed char"); break;
   case '1': update_simple_type(rt, "unsigned char"); break;
   case '2': update_simple_type(rt, "short"); break;
   case '3': update_simple_type(rt, "unsigned short"); break;
   case '4': update_simple_type(rt, "int"); break;
   case '5': update_simple_type(rt, "unsigned int"); break;
   case '6': update_simple_type(rt, "long"); break;
   case '7': update_simple_type(rt, "unsigned long"); break;
   default:
    bad_code_msg(c, "enum real type");
    throw DemanglerError(error);
  }

  return t;
}

// Return a demangled type, for a global variables, a return code, or a function argument.
// This function may require a optional argument saying whether we're in function args or not.

// Presently, the push boolean indicates whether the conplex type should be pushed onto the
// stack or not.  The default is true (push the value onto
DemangledTypePtr VisualStudioDemangler::get_type(DemangledTypePtr t, bool push) {
  if (!t) {
    t = std::make_shared<DemangledType>();
  }

  char c = get_current_char();
  progress("type");
  switch(c) {
   case 'A': // X&
    t->is_reference = true;
    return get_pointer_type(t, push);
   case 'B': // X& volatile
    t->is_reference = true;
    t->is_volatile = true;
    return get_pointer_type(t, push);
   case 'C': return update_simple_type(t, "signed char");
   case 'D': return update_simple_type(t, "char");
   case 'E': return update_simple_type(t, "unsigned char");
   case 'F': return update_simple_type(t, "short");
   case 'G': return update_simple_type(t, "unsigned short");
   case 'H': return update_simple_type(t, "int");
   case 'I': return update_simple_type(t, "unsigned int");
   case 'J': return update_simple_type(t, "long");
   case 'K': return update_simple_type(t, "unsigned long");
   case 'M': return update_simple_type(t, "float");
   case 'N': return update_simple_type(t, "double");
   case 'O': return update_simple_type(t, "long double");
   case 'P': // X*
    t->is_pointer = true; return get_pointer_type(t, push);
   case 'Q': // X* const
    t->is_pointer = true; t->is_const = true; return get_pointer_type(t, push);
   case 'R': // X* volatile
    t->is_pointer = true; t->is_volatile = true; return get_pointer_type(t, push);
   case 'S': // X* const volatile
    t->is_pointer = true; t->is_const = true; t->is_volatile = true; return get_pointer_type(t);
   case 'T':
    update_simple_type(t, "union");
    get_fully_qualified_name(t);
    if (push) {
      type_stack.push_back(t);
      stack_debug(type_stack, type_stack.size()-1, "type");
    }
    return t;
   case 'U':
    update_simple_type(t, "struct");
    get_fully_qualified_name(t);
    if (push) {
      type_stack.push_back(t);
      stack_debug(type_stack, type_stack.size()-1, "type");
    }
    return t;
   case 'V':
    update_simple_type(t, "class");
    get_fully_qualified_name(t);
    if (push) {
      type_stack.push_back(t);
      stack_debug(type_stack, type_stack.size()-1, "type");
    }
    return t;
   case 'W':
    update_simple_type(t, "enum");
    get_real_enum_type(t);
    get_fully_qualified_name(t);
    if (push) {
      type_stack.push_back(t);
      stack_debug(type_stack, type_stack.size()-1, "type");
    }
    return t;
   case 'X': return update_simple_type(t, "void");
   case 'Y': // cointerface
    advance_to_next_char();
    // BUG unhandled!
    return t;
   case 'Z': return update_simple_type(t, "...");
   case '0': case '1': case '2': case '3': case '4':
   case '5': case '6': case '7': case '8': case '9':
    // Consume the reference character...
    advance_to_next_char();
    return resolve_reference(type_stack, c);
   case '_': // Extended simple types.
    c = get_next_char();
    switch(c) {
     case '$': bad_code_msg(c, "_w64 prefix"); throw DemanglerError(error);
     case 'D': update_simple_type(t, "__int8"); break;
     case 'E': update_simple_type(t, "unsigned __int8"); break;
     case 'F': update_simple_type(t, "__int16"); break;
     case 'G': update_simple_type(t, "unsigned __int16"); break;
     case 'H': update_simple_type(t, "__int32"); break;
     case 'I': update_simple_type(t, "unsigned __int32"); break;
     case 'J': update_simple_type(t, "__int64"); break;
     case 'K': update_simple_type(t, "unsigned __int64"); break;
     case 'L': update_simple_type(t, "__int128"); break;
     case 'M': update_simple_type(t, "unsigned __int128"); break;
     case 'N': update_simple_type(t, "bool"); break;
     case 'O': bad_code_msg(c, "unhandled array"); throw DemanglerError(error);
     case 'W': update_simple_type(t, "wchar_t"); break;
     case 'X': bad_code_msg(c, "coclass"); throw DemanglerError(error);
     case 'Y': bad_code_msg(c, "cointerface"); throw DemanglerError(error);
     default:
      bad_code_msg(c, "extended '_' type");
      throw DemanglerError(error);
    }
    // Apparently _X is a two character type, and two character types get pushed onto the stack.
    if (push) {
      type_stack.push_back(t);
      stack_debug(type_stack, type_stack.size()-1, "type");
    }
    return t;
   case '?': // Documented at wikiversity as "type modifier, template parameter"
    c = get_next_char();
    bad_code_msg(c, "type? thing");
    throw DemanglerError(error);
    break;
   // Documented at wikiversity as "type modifier, template parameter"
   case '$':
    c = get_next_char();
    // A second '$' (two in a row)...
    if (c == '$') {
      c = get_next_char();
      switch (c) {
       case 'Q':
        t->is_reference = true;
        t->is_refref = true;
        return get_pointer_type(t, push);
       case 'R':
        // Untested against undname
        t->is_reference = true;
        t->is_volatile = true;
        t->is_refref = true;
        return get_pointer_type(t, push);
       case 'C':
        advance_to_next_char();
        get_storage_class(t);
        return get_type(t, push);
       default:
        bad_code_msg(c, "extended '$$' type");
        throw DemanglerError(error);
      }
    }
    // All characters after a single '$' are template parameters.
    else {
      return get_templated_function_arg(t);
    }
   default:
    bad_code_msg(c, "type");
    throw DemanglerError(error);
  }
}

// This should return a compiler independent enum.  We don't know the class name yet, which
// makes turning the ctor and dtor into strings.  Besides, they're not really different (just
// more important) than the others in this list.  Then there can be different methods for
// turning the enum values into strings depdening on the human readable presentation that's
// desired.
DemangledTypePtr & VisualStudioDemangler::get_special_name_code(DemangledTypePtr & t)
{
  char c = get_current_char();
  progress("special name");
  switch(c) {
   case '0': t->is_ctor = true; break;
   case '1': t->is_dtor = true; break;
   case '2': t->method_name = "operator new"; break;
   case '3': t->method_name = "operator delete"; break;
   case '4': t->method_name = "operator="; break;
   case '5': t->method_name = "operator>>"; break;
   case '6': t->method_name = "operator<<"; break;
   case '7': t->method_name = "operator!"; break;
   case '8': t->method_name = "operator=="; break;
   case '9': t->method_name = "operator!="; break;
   case 'A': t->method_name = "operator[]"; break;
   case 'B': t->method_name = "operator "; break; // missing logic?
   case 'C': t->method_name = "operator->"; break;
   case 'D': t->method_name = "operator*"; break;
   case 'E': t->method_name = "operator++"; break;
   case 'F': t->method_name = "operator--"; break;
   case 'G': t->method_name = "operator-"; break;
   case 'H': t->method_name = "operator+"; break;
   case 'I': t->method_name = "operator&"; break;
   case 'J': t->method_name = "operator->*"; break;
   case 'K': t->method_name = "operator/"; break;
   case 'L': t->method_name = "operator%"; break;
   case 'M': t->method_name = "operator<"; break;
   case 'N': t->method_name = "operator<="; break;
   case 'O': t->method_name = "operator>"; break;
   case 'P': t->method_name = "operator>="; break;
   case 'Q': t->method_name = "operator,"; break;
   case 'R': t->method_name = "operator()"; break;
   case 'S': t->method_name = "operator~"; break;
   case 'T': t->method_name = "operator^"; break;
   case 'U': t->method_name = "operator|"; break;
   case 'V': t->method_name = "operator&&"; break;
   case 'W': t->method_name = "operator||"; break;
   case 'X': t->method_name = "operator*="; break;
   case 'Y': t->method_name = "operator+="; break;
   case 'Z': t->method_name = "operator-="; break;
   case '?': {
     // I'm not certain that this code is actually begin used.  I should check once we're passing.
     auto embedded = get_symbol();
     embedded->is_embedded = true;
     if (debug) std::cout << "The fully embedded type was:" << embedded->str() << std::endl;
     t->name.insert(t->name.begin(), std::move(embedded));
     return t;
   }
   case '_':
    c = get_next_char();
    switch(c) {
     case '0': t->method_name = "operator/="; break;
     case '1': t->method_name = "operator%="; break;
     case '2': t->method_name = "operator>>="; break;
     case '3': t->method_name = "operator<<="; break;
     case '4': t->method_name = "operator&="; break;
     case '5': t->method_name = "operator|="; break;
     case '6': t->method_name = "operator^="; break;
     case '7': t->method_name = "`vftable'"; break;
     case '8': t->method_name = "`vbtable'"; break;
     case '9': t->method_name = "`vcall'"; break;
     case 'A': t->method_name = "`typeof'"; break;
     case 'B': t->method_name = "`local static guard'"; break;
     case 'C': t->method_name = "`string'"; break; // missing logic?
     case 'D': t->method_name = "`vbase destructor'"; break;
     case 'E': t->method_name = "`vector deleting destructor'"; break;
     case 'F': t->method_name = "`default constructor closure'"; break;
     case 'G': t->method_name = "`scalar deleting destructor'"; break;
     case 'H': t->method_name = "`vector constructor iterator'"; break;
     case 'I': t->method_name = "`vector destructor iterator'"; break;
     case 'J': t->method_name = "`vector vbase constructor iterator'"; break;
     case 'K': t->method_name = "`virtual displacement map'"; break;
     case 'L': t->method_name = "`eh vector constructor iterator'"; break;
     case 'M': t->method_name = "`eh vector destructor iterator'"; break;
     case 'N': t->method_name = "`eh vector vbase constructor iterator'"; break;
     case 'O': t->method_name = "`copy constructor closure'"; break;
     case 'P': t->method_name = "`udt returning'"; break;
     case 'R': return get_rtti(t);
     case 'S': t->method_name = "`local vftable'"; break;
     case 'T': t->method_name = "`local vftable constructor closure'"; break;
     case 'U': t->method_name = "operator new[]"; break;
     case 'V': t->method_name = "operator delete[]"; break;
     case 'X': t->method_name = "`placement delete closure'"; break;
     case 'Y': t->method_name = "`placement delete[] closure'"; break;
     case '_':
      c = get_next_char();
      switch(c) {
       case 'A': t->method_name = "`managed vector constructor iterator'"; break;
       case 'B': t->method_name = "`managed vector destructor iterator'"; break;
       case 'C': t->method_name = "`eh vector copy constructor iterator'"; break;
       case 'D': t->method_name = "`eh vector vbase copy constructor iterator'"; break;
       case 'E': t->method_name = "`dynamic initializer'"; break;
       case 'F': t->method_name = "`dynamic atexit destructor'"; break;
       case 'G': t->method_name = "`vector copy constructor iterator'"; break;
       case 'H': t->method_name = "`vector vbase copy constructor iterator'"; break;
       case 'I': t->method_name = "`managed vector copy constructor iterator'"; break;
       case 'J': t->method_name = "`local static thread guard'"; break;
       default:
        bad_code_msg(c, "special name '__')");
        throw DemanglerError(error);
      }
     default:
      bad_code_msg(c, "special name '_'");
      throw DemanglerError(error);
    }
    break;
   default:
    bad_code_msg(c, "special name");
    throw DemanglerError(error);
  }

  advance_to_next_char();
  return t;
}

// It's still a little unclear what this returns.   Maybe a custom RTTI object?
DemangledTypePtr & VisualStudioDemangler::get_rtti(DemangledTypePtr & t) {
  // UNDNAME sets a flag to  prevent later processing of return values?

  // Character advancement is confusing and ugly here...  get_special_name_code() currently
  // expects us to leave a character to be advanced past. :-(

  char c = get_next_char();
  switch(c) {
   case '0':
    advance_to_next_char();
    // Why there's a return type for RTTI descriptor is a little unclear to me...
    get_return_type(t);
    t->method_name = "`RTTI Type Descriptor'";
    break;
   case '1': {
     advance_to_next_char();
     // These should be stored in the result...
     t->n1 = get_number();
     t->n2 = get_number();
     t->n3 = get_number();
     t->n4 = get_number();
     std::string location = boost::str(boost::format("(%d, %d, %d, %d)'") % t->n1 % t->n2 % t->n3 % t->n4);
     t->method_name = "`RTTI Base Class Descriptor at " + location;
     break;
   }
   case '2':
    advance_to_next_char();
    t->method_name = "`RTTI Base Class Array'"; break;
   case '3':
    advance_to_next_char();
    t->method_name = "`RTTI Class Hierarchy Descriptor'"; break;
   case '4':
    advance_to_next_char();
    t->method_name = "`RTTI Complete Object Locator'"; break;
   default:
    bad_code_msg(c, "RTTI");
    throw DemanglerError(error);
  }

  return t;
}

DemangledTypePtr &
VisualStudioDemangler::update_storage_class(DemangledTypePtr & t, Distance distance,
                                            bool is_const, bool is_volatile,
                                            bool is_func, bool is_based, bool is_member)
{
  t->distance = distance;
  t->is_const = is_const;
  t->is_volatile = is_volatile;
  t->is_func = is_func;

  // Unused currently...
  t->is_based = is_based;
  t->is_member = is_member;

  // Successfully consume this character code.
  advance_to_next_char();
  return t;
}

// Storage class codes.  Agner Fog's Table 10.
DemangledTypePtr & VisualStudioDemangler::get_storage_class(DemangledTypePtr & t) {
  char c = get_current_char();
  switch(c) {

    // Ordinary variables?
    //                                      distance        const  volat  func   based  member
   case 'A': return update_storage_class(t, Distance::Near, false, false, false, false, false);
   case 'B': return update_storage_class(t, Distance::Near, true,  false, false, false, false);
   case 'C': return update_storage_class(t, Distance::Near, false, true,  false, false, false);
   case 'D': return update_storage_class(t, Distance::Near, true,  true,  false, false, false);

   // E & F are not valid on their own in this context.

   case 'G': return update_storage_class(t, Distance::Near, false,  true,  false, false, false);
   case 'H': return update_storage_class(t, Distance::Near, true,   true,  false, false, false);

   // I is not valid on it's own in this context.

   case 'J': return update_storage_class(t, Distance::Near, true,   false, false, false, false);
   case 'K': return update_storage_class(t, Distance::Near, false,  true,  false, false, false);
   case 'L': return update_storage_class(t, Distance::Near, true,   true,  false, false, false);

   // __based() variables, distance presumed to be near.
   case 'M': return update_storage_class(t, Distance::Near, false, false, false, true,  false);
   case 'N': return update_storage_class(t, Distance::Near, true,  false, false, true,  false);
   case 'O': return update_storage_class(t, Distance::Near, false, true,  false, true,  false);
   case 'P': return update_storage_class(t, Distance::Near, true,  true,  false, true,  false);

    // Ordinary members?, distance presumed to be near.
   case 'Q': return update_storage_class(t, Distance::Near, false, false, false, false, true);
   case 'R': return update_storage_class(t, Distance::Near, true,  false, false, false, true);
   case 'S': return update_storage_class(t, Distance::Near, false, true,  false, false, true);
   case 'T': return update_storage_class(t, Distance::Near, true,  true,  false, false, true);

    // Ordinary members?, distance wildly guessed to be far to distinguish from Q,R,S,T.
   case 'U': return update_storage_class(t, Distance::Far,  false, false, false, false, true);
   case 'V': return update_storage_class(t, Distance::Far,  true,  false, false, false, true);
   case 'W': return update_storage_class(t, Distance::Far,  false, true,  false, false, true);
   case 'X': return update_storage_class(t, Distance::Far,  true,  true,  false, false, true);

    // Ordinary members?, distance wildly guessed to be huge to distinguish from U,V,W,X.
   case 'Y': return update_storage_class(t, Distance::Far,  false, false, false, false, true);
   case 'Z': return update_storage_class(t, Distance::Far,  true,  false, false, false, true);
   case '0': return update_storage_class(t, Distance::Far,  false, true,  false, false, true);
   case '1': return update_storage_class(t, Distance::Far,  true,  true,  false, false, true);

    // __based() members, distance presumed to be near
   case '2': return update_storage_class(t, Distance::Near, false, false, false, true,  true);
   case '3': return update_storage_class(t, Distance::Near, true,  false, false, true,  true);
   case '4': return update_storage_class(t, Distance::Near, false, true,  false, true,  true);
   case '5': return update_storage_class(t, Distance::Near, true,  true,  false, true,  true);

    // Functions (no const/volatile), near/far arbitrary to create a distinction.
   case '6': return update_storage_class(t, Distance::Near, false, false, true,  false, false);
   case '7': return update_storage_class(t, Distance::Far,  false, false, true,  false, false);
   case '8': return update_storage_class(t, Distance::Near, false, false, true,  false, true);
   case '9': return update_storage_class(t, Distance::Far,  false, false, true,  false, true);

    // Extended storage class modifiers.
   case '_':
    c = get_next_char();
    switch(c) {
     case 'A': return update_storage_class(t, Distance::Near, false, false, true,  true, false);
     case 'B': return update_storage_class(t, Distance::Far,  false, false, true,  true, false);
     case 'C': return update_storage_class(t, Distance::Near, false, false, true,  true, true);
     case 'D': return update_storage_class(t, Distance::Far,  false, false, true,  true, true);
     default:
      bad_code_msg(c, "extended storage class");
      throw DemanglerError(error);
    }
    break;
   default:
    bad_code_msg(c, "storage class");
    throw DemanglerError(error);
  }

  advance_to_next_char();
  return t;
}

// It looks like these two should be combined, but I'm waiting for further evidence before
// changing all of the code.
DemangledTypePtr & VisualStudioDemangler::get_return_type(DemangledTypePtr & t) {
  char c = get_current_char();

  // The return type of constructors and destructors are simply coded as an '@'.
  if (c == '@') {
    // There's nothing to actually do except skip the '@'?  Perhaps in a post-fixup step we
    // should create a return type that is the type of the class?
    advance_to_next_char();
    return t;
  }

  progress("return value storage class");
  process_return_storage_class(t);
  progress("return value type");
  get_type(t, false);
  return t;
}

// Storage class codes for return values.  Agner Fog's Table 12.
// A lot of overlap with tables 10 & 15, but apparently distinct...
DemangledTypePtr & VisualStudioDemangler::process_return_storage_class(DemangledTypePtr & t) {
  char c = get_current_char();

  // If there's no question mark, we're the default storage class?
  // There are special rules according
  if (c != '?') {
    t->is_const = false;
    t->is_volatile = false;
    return t;
  }
  c = get_next_char();

  switch(c) {
   case 'A':
    t->is_const = false;
    t->is_volatile = false;
    break;
   case 'B':
    t->is_const = true;
    t->is_volatile = false;
    break;
   case 'C':
    t->is_const = false;
    t->is_volatile = true;
    break;
   case 'D':
    t->is_const = true;
    t->is_volatile = true;
    break;
   default:
    bad_code_msg(c, "return storage class");
    throw DemanglerError(error);
  }

  advance_to_next_char();
  return t;
}

DemangledTypePtr &
VisualStudioDemangler::update_method(DemangledTypePtr & t, Scope scope,
                                     MethodProperty prop, Distance distance)
{
  t->symbol_type = SymbolType::ClassMethod;
  t->scope = scope;
  t->method_property = prop;
  t->distance = distance;
  return t;
}

DemangledTypePtr &
VisualStudioDemangler::update_member(DemangledTypePtr & t, Scope scope, MethodProperty prop)
{
  t->symbol_type = SymbolType::StaticClassMember;
  t->scope = scope;
  t->method_property = prop;
  return t;
}

// Agner Fog's Table 14.
// Could be three methods that read the same byte and return individual values.
DemangledTypePtr & VisualStudioDemangler::get_symbol_type(DemangledTypePtr & t)
{
  // This is the symbol type character code.
  progress("symbol type");
  char c = get_current_char();
  // Pre-consume this character code, so we can just return -- BREAKS errors and reporting!
  advance_to_next_char();
  switch(c) {

   case '0': return update_member(t, Scope::Private, MethodProperty::Static);
   case '1': return update_member(t, Scope::Protected, MethodProperty::Static);
   case '2': return update_member(t, Scope::Public, MethodProperty::Static);

   case '3': // ?x@@3HA = int x
   case '4': // ?x@@4HA = int x
    t->symbol_type = SymbolType::GlobalObject;
    return t;

    // Every indication is that 6 and 7 demangle identically in the offical undname tool.
   case '6':
   case '7':
    t->symbol_type = SymbolType::GlobalThing2; return t;

    // Symbol types '8' and '9' are names with no type? e.g. ?X@@8 demangles to simply 'X'
   case '8':
   case '9':
    t->symbol_type = SymbolType::GlobalThing1; return t;

   // Codes A-X are for class methods.
   case 'A': return update_method(t, Scope::Private, MethodProperty::Ordinary, Distance::Near);
   case 'B': return update_method(t, Scope::Private, MethodProperty::Ordinary, Distance::Far);
   case 'C': return update_method(t, Scope::Private, MethodProperty::Static, Distance::Near);
   case 'D': return update_method(t, Scope::Private, MethodProperty::Static, Distance::Far);
   case 'E': return update_method(t, Scope::Private, MethodProperty::Virtual, Distance::Near);
   case 'F': return update_method(t, Scope::Private, MethodProperty::Virtual, Distance::Far);
   case 'G': return update_method(t, Scope::Private, MethodProperty::Thunk, Distance::Near);
   case 'H': return update_method(t, Scope::Private, MethodProperty::Thunk, Distance::Far);

   case 'I': return update_method(t, Scope::Protected, MethodProperty::Ordinary, Distance::Near);
   case 'J': return update_method(t, Scope::Protected, MethodProperty::Ordinary, Distance::Far);
   case 'K': return update_method(t, Scope::Protected, MethodProperty::Static, Distance::Near);
   case 'L': return update_method(t, Scope::Protected, MethodProperty::Static, Distance::Far);
   case 'M': return update_method(t, Scope::Protected, MethodProperty::Virtual, Distance::Near);
   case 'N': return update_method(t, Scope::Protected, MethodProperty::Virtual, Distance::Far);
   case 'O': return update_method(t, Scope::Protected, MethodProperty::Thunk, Distance::Near);
   case 'P': return update_method(t, Scope::Protected, MethodProperty::Thunk, Distance::Far);

   case 'Q': return update_method(t, Scope::Public, MethodProperty::Ordinary, Distance::Near);
   case 'R': return update_method(t, Scope::Public, MethodProperty::Ordinary, Distance::Far);
   case 'S': return update_method(t, Scope::Public, MethodProperty::Static, Distance::Near);
   case 'T': return update_method(t, Scope::Public, MethodProperty::Static, Distance::Far);
   case 'U': return update_method(t, Scope::Public, MethodProperty::Virtual, Distance::Near);
   case 'V': return update_method(t, Scope::Public, MethodProperty::Virtual, Distance::Far);
   case 'W': return update_method(t, Scope::Public, MethodProperty::Thunk, Distance::Near);
   case 'X': return update_method(t, Scope::Public, MethodProperty::Thunk, Distance::Far);

   // Codes Y & Z are for global (non-method) functions.
   case 'Y': t->symbol_type = SymbolType::GlobalFunction; t->distance = Distance::Near; return t;
   case 'Z': t->symbol_type = SymbolType::GlobalFunction; t->distance = Distance::Far; return t;

   default:
    bad_code_msg(c, "symbol type");
    throw DemanglerError(error);
  }
}

// Storage class codes for methods.  Agner Fog's Table 15.
// Nearly identical to Table 12, but needs to update a function and lacks '?' introducer.
DemangledTypePtr & VisualStudioDemangler::process_method_storage_class(DemangledTypePtr & t)
{
  get_storage_class_modifiers(t);

  char c = get_current_char();
  switch(c) {
   case 'A':
    t->is_const = false;
    t->is_volatile = false;
    break;
   case 'B':
    t->is_const = true;
    t->is_volatile = false;
    break;
   case 'C':
    t->is_const = false;
    t->is_volatile = true;
    break;
   case 'D':
    t->is_const = true;
    t->is_volatile = true;
    break;
   default:
    bad_code_msg(c, "method storage class");
    throw DemanglerError(error);
  }

  advance_to_next_char();
  return t;
}

void VisualStudioDemangler::get_symbol_start() {
  char c = get_current_char();
  // Each symbol should begin with a question mark.
  if (c != '?') {
    error = boost::str(boost::format("'%c' at position %d") % c % offset);
    error = "Expected '?' code at start of symbol, instead found character " + error;
    throw DemanglerError(error);
  }
  progress("new symbol");
  advance_to_next_char();
}

DemangledTypePtr VisualStudioDemangler::resolve_reference(
  ReferenceStack & stack, char poschar)
{
  size_t stack_offset = poschar - '0';

  bool fake = false;
  if (stack.size() >= stack_offset + 1) {
    auto & reference = stack.at(stack_offset);
    if (debug) std::cout << "Reference refers to " <<  reference->str() << std::endl;

    // This is the "correct" thing to do.
    if (!fake) return reference;
  }

  // Even if our position was invalid kludge something up for debugging.
  return std::make_shared<Namespace>(boost::str(boost::format("ref#%d") % stack_offset));
}

DemangledTypePtr & VisualStudioDemangler::get_templated_function_arg(DemangledTypePtr & t)
{
  // This routines handles '$' in function args.  It's unclear why they need special treatment.
  // When this method was called, the current character was the '$', so we need to advance to
  // the next character first thing.
  char c = get_next_char();
  progress("templated function argument");
  switch(c) {
   case '0':
   case 'D':
   case 'F':
   case 'G':
   case 'Q':
   default:
    bad_code_msg(c, "templated function arg");
    throw DemanglerError(error);
  }

  // Hack thing to consume 0, D, F, G, & Q.
  advance_to_next_char();
  return t;
}

namespace {
// Wrapper object that saves a reference stack, replacing it with an empty one.  The reference
// stack will be re-replaced when the save_stack object exists scope.
struct save_stack {
  save_stack(ReferenceStack & stack) : original(stack) {
    swap(saved, original);
  }

  ~save_stack() {
    swap(saved, original);
  }

  ReferenceStack saved;
  ReferenceStack & original;
};
} // unnamed namespace


DemangledTypePtr & VisualStudioDemangler::get_templated_type(DemangledTypePtr & t)
{
  // The current character was the '$' when this method was called.
  char c = get_next_char();
  progress("templated symbol");
  auto templated_type = std::make_shared<DemangledType>();

  // Whenever we start a new template, we start a new name stack.
  auto saved_name_stack = save_stack(name_stack);

  // The name can be either a special name or a literal, but not a fully qualified name
  // because there's no '@' after the special name code.
  if (c == '?') {
    c = get_next_char();
    if (c == '$') {
      get_templated_type(templated_type);
      name_stack.push_back(templated_type);
    }
    else {
      get_special_name_code(templated_type);
      // Very ugly and hackish...
      templated_type->simple_type = templated_type->method_name;
    }
  }
  else {
    templated_type->simple_type = get_literal();
    name_stack.emplace_back(std::make_shared<Namespace>(templated_type->simple_type));
  }

  // We also need a new type stack for the template parameters.
  auto saved_type_stack = save_stack(type_stack);

  size_t params = 0;
  c = get_current_char();
  while (c != '@') {
    DemangledTemplateParameterPtr parameter;
    if (get_current_char() == '$') {
      c = get_next_char();
      switch (c) {
       case '0':
        advance_to_next_char();
        progress("constant template parameter");
        parameter = std::make_shared<DemangledTemplateParameter>(get_number());
        break;
       case '1':
        advance_to_next_char();
        progress("constant pointer template parameter");
        parameter = std::make_shared<DemangledTemplateParameter>(get_symbol());
        parameter->pointer = true;
        break;
       case '$':
        offset--;
        parameter = std::make_shared<DemangledTemplateParameter>(get_type());
        break;
       default:
        bad_code_msg(c, "template argument");
        throw DemanglerError(error);
      }
    }
    else {
      parameter = std::make_shared<DemangledTemplateParameter>(get_type());
    }

    templated_type->template_parameters.push_back(std::move(parameter));
    params++;
    c = get_current_char();
  }

  progress("end of template parameters");
  // Advance past the '@' that marked the end of the template parameters.
  advance_to_next_char();

  // Record the templated type in the name of the current type.
  t->name.insert(t->name.begin(), std::move(templated_type));

  return t;
}


DemangledTypePtr & VisualStudioDemangler::get_fully_qualified_name(
  DemangledTypePtr & t, bool push)
{
  char c = get_current_char();
  size_t argno = 0;
  while (c != '@') {
    // Are we the first argument?
    bool first = (argno == 0);
    //bool first = false;
    // Push all names except when we're the first, then use the push parameter.
    bool pushing = (!first || push);

    if (c == '?') {
      c = get_next_char();
      if (c == '$') {
        auto tt = std::make_shared<DemangledType>();
        get_templated_type(tt);
        t->name.insert(t->name.begin(), tt);
        if (pushing) {
          name_stack.push_back(tt);
          stack_debug(name_stack, name_stack.size()-1, "name");
        }
      }
      else {
        // This feels wrong...  If it's the first term in the name it's a special name, but if
        // it's not the first term it's a numbered namespace?  This seems like more evidence
        // that the parsing of the first term is definitely a different routine than the
        // namespace terms in a fully qualified name...   Perhaps some code cleanup is needed?
        if (first) {
          get_special_name_code(t);
        }
        else {
          // ?? inside a namespace is a quoted namespace...
          if (get_current_char() == '?') {
            advance_to_next_char();
            // Yet another question mark...  This makes three in a row.
            if (get_current_char() == '?') {
              bad_code_msg('?', "??? thing");
              throw DemanglerError(error);
            }
            else {
              auto ns = std::make_shared<Namespace>(get_literal());
              ns->is_embedded = true;
              if (debug) std::cout << "Found quoted namespace: " << ns->str() << std::endl;
              t->name.insert(t->name.begin(), std::move(ns));
            }
          }
          else {
            // Wow is this ugly.  But it looks like Microsoft really did it this way, so what
            // else can we do?  A number that starts with 'A' would be a namespace number that
            // has a leading zero digit, which is not required.  Thus it signals a strangely
            // handled "anonymous namespace" with a discarded unqie identifier.
            if (get_current_char() == 'A') {
              t->name.insert(t->name.begin(), get_anonymous_namespace());
            }
            else {
              uint64_t number = get_number();
              std::string numbered_namespace = boost::str(boost::format("`%d'") % number);
              if (debug) std::cout << "Found numbered namespace: "
                                   << numbered_namespace << std::endl;
              auto nns = std::make_shared<Namespace>(numbered_namespace);
              t->name.insert(t->name.begin(), std::move(nns));
            }
          }
        }
      }
    }
    else if (c >= '0' && c <= '9') {
      progress("reference to symbol");
      t->name.insert(t->name.begin(), resolve_reference(name_stack, c));
      advance_to_next_char();
    }
    else {
      auto ns = std::make_shared<Namespace>(get_literal());
      t->name.insert(t->name.begin(), ns);
      name_stack.push_back(std::move(ns));
      stack_debug(name_stack, name_stack.size()-1, "name");
    }
    c = get_current_char();
    argno++;
  }

  progress("end of fully qualified name");
  // Advance past the terminating '@' character.
  advance_to_next_char();
  return t;
}

DemangledTypePtr VisualStudioDemangler::get_anonymous_namespace() {

  progress("anonymous namespace");

  // This should be re-written to just call get_literal() instead, now that we know that it is
  // '@' terminated like a normal literal.

  char c = get_next_char();
  size_t start_offset = offset;
  if (c != '0') {
      error = boost::str(boost::format("Expected '0' in anonymous namespace, found '%c'.") % c);
      throw DemanglerError(error);
  }
  c = get_next_char();
  if (c != 'x') {
      error = boost::str(boost::format("Expected 'x' in anonymous namespace, found '%c'.") % c);
      throw DemanglerError(error);
  }

  size_t digits = 0;
  c = get_next_char();
  progress("anonymous namespace digits");
  while (c != '@') {
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
      // Allowed
    }
    else {
      error = boost::str(boost::format("Disallowed character '%c' in literal string.") % c);
      throw DemanglerError(error);
    }
    c = get_next_char();
    digits++;
  }

  // Now build the return string from the bytes we consumed.
  std::string literal = mangled.substr(start_offset, offset - start_offset);
  if (debug) std::cout << "Anonymous namespace ID was: " << literal << std::endl;

  // Advance past the '@' that terminated the literal.
  advance_to_next_char();

  auto ans = std::make_shared<Namespace>(literal);
  ans->is_anonymous = true;
  return std::move(ans);
}

std::string VisualStudioDemangler::get_literal() {
  std::string literal;

  size_t start_offset = offset;
  progress("literal");

  char c = get_current_char();
  while (c != '@') {
    // Allowed characters are:
    if ((c >= 'A' && c <= 'Z') || // uppercase letters
        (c >= 'a' && c <= 'z') || // lowercase letters
        (c >= '0' && c <= '9') || // digits
        c == '_' || c == '$') {  // underscore and dollar sign
      // Allowed
    }
    else {
      error = boost::str(boost::format("Disallowed character '%c' in literal string.") % c);
      throw DemanglerError(error);
    }
    c = get_next_char();
  }

  // Now build the return string from the bytes we consumed.
  literal = mangled.substr(start_offset, offset - start_offset);

  if (debug) {
    std::cout << "Extracted literal from " << start_offset << " to " << offset
              << " (len=" << (offset - start_offset)
              << ") resulting in string: " << literal << std::endl;
  }

  // Advance past the '@' that terminated the literal.
  advance_to_next_char();
  // We should also add the literal to the "stack".
  return literal;
}

int64_t VisualStudioDemangler::get_number() {
  // Is the number signed?
  bool negative = false;
  int64_t num = 0;

  char c = get_current_char();
  progress("number");

  // If the string starts with '?' then it's negative.
  if (c == '?') {
    negative = true;
    c = get_next_char();
  }

  // Numbers between 1 and 10 expressed as 0-9.
  if (c >= '0' &&  c <= '9') {
    advance_to_next_char();
    num = (c - '0') + 1;
    if (negative) return -num;
    return num;
  }

  // The wikiversity article claims that '@' and '?@' both represent zero, but I've not found
  // that to be true (yet?).  My experience matches Agner's that it's encoded as 'A@' (or
  // perhaps '?A@').

  // All other codings are variations of hexadecimal values encoded as A-P.
  // Count the digits found to prevent integer overflows.
  size_t digits_found = 0;

  while (c >= 'A' && c <= 'P') {
    num *= 16;
    num += (c - 'A');
    digits_found++;
    c = get_next_char();
  }

  if (c != '@') {
    error = "Numbers must be terminated with an '@' character. ";
    throw DemanglerError(error);
  }
  progress("end of number");
  advance_to_next_char();

  if (digits_found <= 0) {
    error = "There were too few hex digits endecoded in the number.";
    throw DemanglerError(error);
  }

  if (digits_found > 8) {
    error = "There were too many hex digits encoded in the number.";
    throw DemanglerError(error);
  }

  if (negative) return -num;
  return num;
}

DemangledTypePtr & VisualStudioDemangler::get_function(DemangledTypePtr & t) {
  // And then the remaining codes are the same for functions and methods.
  process_calling_convention(t);
  // Return code.  It's annoying that the modifiers come first and require us to allocate it.
  t->retval = std::make_shared<DemangledType>();
  get_return_type(t->retval);
  if (debug) std::cout << "Return value was: " << t->retval->str() << std::endl;


  // Whenever we start a nex set of function arguments, we start a new type stack?
  //auto saved_type_stack = save_stack(type_stack);

  // Function arguments.
  size_t argno = 0;
  progress("start of function arguments");
  while (true) {
    // Must be at least one argument, but after that '@' marks the end.
    if (argno > 0 && get_current_char() == '@') {
      progress("end of args");
      advance_to_next_char();
      break;
    }
    progress("function argument");
    auto arg = get_type();
    t->args.push_back(arg);
    if (debug) std::cout << "Arg #" << argno << " was: " << arg->str() << std::endl;
    // If the first parameter is void, it's the only parameter.
    argno++;
    if (argno == 1 && arg->simple_type == "void") break;
    // If the most recent parameter is '...', it's the last parameter.
    if (arg->simple_type == "...") break;
  }

  progress("end of function arguments");

  // I'm confused about how certain this 'Z' is...
  if (get_current_char() == 'Z') {
    advance_to_next_char();
  }

  //if (get_current_char() != 'Z') {
  //  error = "Expected 'Z' to terminate function.";
  //  throw DemanglerError(error);
  //}
  return t;
}

DemangledTypePtr VisualStudioDemangler::get_symbol() {
  get_symbol_start();

  auto t = std::make_shared<DemangledType>();
  get_fully_qualified_name(t, false);
  progress("here");
  get_symbol_type(t);

  switch(t->symbol_type) {
   case SymbolType::GlobalThing2:
    t->instance_name = t->name;
    t->name.clear();
    process_method_storage_class(t);
    // The interface name is optional.
    if (get_current_char() != '@') {
      t->com_interface = std::make_shared<DemangledType>();
      get_fully_qualified_name(t->com_interface);
    }
    if (get_current_char() != '@') {
      error = "Expected '@' at end of SymbolType6.";
      throw DemanglerError(error);
    }
    return t;
   case SymbolType::GlobalThing1:
    return t;
   case SymbolType::GlobalObject:
   case SymbolType::StaticClassMember:
    // This is backwards.  We should have read the initial name into a special place, and then
    // had all other places use the default place...
    t->instance_name = t->name;
    t->name.clear();
    get_type(t); // Table 9
    get_storage_class(t); // Table 10
    return t;
   case SymbolType::ClassMethod:
    // There's no storage class code for static class methods.
    if (t->method_property != MethodProperty::Static) {
      process_method_storage_class(t); // Table 15
    }
    // Fall through to global function.
   case SymbolType::GlobalFunction:
    return get_function(t);
   default:
    error = "Unrecognized symbol type.";
    throw DemanglerError(error);
  }
}


// Not part of the constructor because it throws.
DemangledTypePtr VisualStudioDemangler::analyze() {

  char c = get_current_char();
  if (c == '_') {
    error = "Mangled names beginning with '_' are currently not supported.";
    throw DemanglerError(error);
  }
  else if (c == '.') {
    advance_to_next_char();
    // Why there's a return type for RTTI descriptor is a little unclear to me...
    auto t = std::make_shared<DemangledType>();
    get_return_type(t);
    return t;
  }
  else {
    return get_symbol();
  }
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
