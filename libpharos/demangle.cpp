#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <boost/format.hpp>
#include <boost/locale/encoding_utf.hpp>

#include "demangle.hpp"

// Perhaps we should eliminated the unused parameters (basically all match booleans to the
// str_xxx functions).  Right now it's easier fo rthem all to match though...
#define UNUSED __attribute__((unused))

namespace demangle {
namespace detail {

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

  [[noreturn]] void bad_code(char c, const std::string & desc);
  [[noreturn]] void general_error(const std::string & e);

  // Given a stack and a position character, safely resolve and return the reference.
  DemangledTypePtr resolve_reference(ReferenceStack & stack, char poschar);

  DemangledTypePtr get_type(DemangledTypePtr t = DemangledTypePtr(), bool push = true);
  DemangledTypePtr get_array_type(DemangledTypePtr & t, bool push = true);
  DemangledTypePtr & get_pointer_type(DemangledTypePtr & t, bool push = true);
  DemangledTypePtr & get_templated_type(DemangledTypePtr & t);
  DemangledTypePtr & get_templated_function_arg(DemangledTypePtr & t);
  DemangledTypePtr & get_return_type(DemangledTypePtr & t);
  DemangledTypePtr & get_fully_qualified_name(DemangledTypePtr & t, bool push = true);
  DemangledTypePtr & get_symbol_type(DemangledTypePtr & t);
  DemangledTypePtr & get_function(DemangledTypePtr & t);
  DemangledTypePtr & get_storage_class(DemangledTypePtr & t);
  DemangledTypePtr & get_storage_class_modifiers(DemangledTypePtr & t);
  DemangledTypePtr & get_managed_properties(DemangledTypePtr & t, int & cli_array);
  DemangledTypePtr & get_real_enum_type(DemangledTypePtr & t);
  DemangledTypePtr & get_rtti(DemangledTypePtr & t);
  DemangledTypePtr & process_return_storage_class(DemangledTypePtr & t);
  DemangledTypePtr & process_calling_convention(DemangledTypePtr & t);
  DemangledTypePtr & process_method_storage_class(DemangledTypePtr & t);
  DemangledTypePtr & get_special_name_code(DemangledTypePtr & t);
  DemangledTypePtr & get_string(DemangledTypePtr & t);
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
  void progress(const std::string & msg);
  void stack_debug(ReferenceStack & stack, size_t position, const std::string & msg);

 public:

  VisualStudioDemangler(const std::string & mangled, bool debug = false);

  DemangledTypePtr analyze();
};

} // namespace detail

DemangledTypePtr visual_studio_demangle(const std::string & mangled, bool debug)
{
  detail::VisualStudioDemangler demangler(mangled, debug);
  return demangler.analyze();
}

std::string quote_string(const std::string & input)
{
  static auto special_chars = "\"\\\a\b\f\n\r\t\v";
  static auto names = "\"\\abfnrtv";
  std::string output;
  output.reserve(input.size() + 2);
  output.push_back('\"');
  for (auto c : input) {
    if (c == '\0') {
      output.push_back('\\');
      output.push_back('0');
    } else {
      auto pos = std::strchr(special_chars, c);
      if (pos) {
        output.push_back('\\');
        output.push_back(*(names + (pos - special_chars)));
      } else {
        output.push_back(c);
      }
    }
  }
  output.push_back('\"');
  return output;
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
  for (auto it = name.rbegin(); it != name.rend(); ++it) {
    (*it)->debug_type(match, indent + 1, boost::str(boost::format("Name %d") % i));
    i++;
  }

  i = 0;
  for (const auto & p : template_parameters) {
    if (p->type != nullptr) {
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

  if (match && extern_c) {
    stream << "extern \"C\" ";
  }

  if (match && method_property == MethodProperty::Thunk) stream << "[thunk]:";

  // I should convert these enums to use the enum stringifier...
  if (scope == Scope::Private) stream << "private: ";
  if (scope == Scope::Protected) stream << "protected: ";
  if (scope == Scope::Public) stream << "public: ";

  if (method_property == MethodProperty::Static) stream << "static ";
  if (method_property == MethodProperty::Virtual) stream << "virtual ";
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
    if (ptr64) return "__ptr64 ";
    return "";
  }

  if (!ptr64 && !is_const && !is_volatile) return "";

  std::ostringstream stream;
  if (is_const) stream << "const ";
  if (is_volatile) stream << "volatile ";
  if (match && unaligned) stream << "__unaligned ";
  if (match && ptr64) stream << "__ptr64 ";
  if (match && restrict) stream << "__restrict ";
  if (is_reference) stream << "& ";
  if (is_refref) stream << "&& ";
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
      auto next = pit + 1;
      if (tp) {
        tpstr = tp->str(match);
        stream << tpstr;
      }
      if (next != template_parameters.end() && *(next)) {
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
DemangledType::str_name_qualifiers(const FullyQualifiedName& the_name, bool match,
                                   bool except_last) const
{
  if (the_name.empty()) {
    return std::string();
  }

  std::ostringstream stream;

  auto e = the_name.rend();
  if (except_last) --e;
  auto const b = the_name.rbegin();
  for (auto nit = b; nit != e; ++nit) {
    if (nit != b) stream << "::";
    auto & ndt = *nit;
    // Some names have things that require extra quotations...
    if (ndt->is_embedded) {
      stream << "`";
      std::string rendered = ndt->str(match);
      // Some nasty whitespace kludging here.  If the last character is a space, remove it.
      // There's almost certainly a better way to do this.  Perhaps all types ought to remove
      // their own trailing spaces?
      if (rendered.size() > 1 && rendered.back() == ' ') {
        rendered.pop_back();
      }
      stream << rendered;
      stream << "'";
    }
    else if (ndt->is_ctor || ndt->is_dtor) {
      if (ndt->is_dtor) {
        stream << '~';
      }
      if (nit == the_name.rbegin()) {
        stream << "ERRORNOCLASS";
      } else if (match) {
        stream << (*(std::prev(nit)))->str(match);
      } else {
        stream << (*(std::prev(nit)))->get_pname();
      }
      stream << ndt->str_template_parameters(match);
    }
    else {
      stream << ndt->str(match);
    }
  }

  return stream.str();
}

// Public API to get the method name used by the OOAnalzyer.
std::string
DemangledType::get_method_name() const
{
  if (name.empty() || !simple_type.empty()) {
    return std::string();
  }

  std::ostringstream stream;
  auto & method = name.front();
  if (method->is_ctor || method->is_dtor) {
    if (method->is_dtor) stream << "~";

    if (name.size() < 2) {
      stream << "ERRORNOCLASS";
    } else {
      stream << name[1]->get_pname();
    }
  }
  else {
    auto & mname = method->get_pname();
    stream << mname;
    if (retval && mname == "operator ") {
      stream << retval->str();
    }
  }

  return stream.str();
}

std::string
DemangledType::get_class_name() const
{
  if (symbol_type == SymbolType::GlobalThing2) {
    return str_name_qualifiers(instance_name, false, true);
  }
  return str_name_qualifiers(name, false, simple_type.empty());
}

std::string
DemangledType::str_array(UNUSED bool match) const
{
  if (!is_array) return "";
  std::ostringstream stream;
  for (auto dim : dimensions) {
    stream << '[' << dim << ']';
  }
  return stream.str();
}

std::string
DemangledType::str_pointer_punctuation(UNUSED bool match) const
{
  if (is_refref) return "&&";
  if (is_pointer) return is_gc ? "^" : "*";
  if (is_reference) return is_gc ? "%" : "&";
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

std::string const &
DemangledType::get_pname() const
{
  if (name.empty()) {
    return simple_type;
  }
  return name.front()->get_pname();
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

  if (symbol_type == SymbolType::HexSymbol) {
    return simple_type;
  }

  std::ostringstream stream;

  stream << str_class_properties(match);

  // Partially conversion from old code and partially simplification of this method.
  if (symbol_type == SymbolType::GlobalFunction || symbol_type == SymbolType::ClassMethod
      || symbol_type == SymbolType::VtorDisp)
  {
    stream << str_distance(match);
    // Guessing at formatting..
    if (is_exported) stream << "__declspec(dllexport)";

    // Annoying, but we currently have a retval for non-existent return values, which causes
    // use to emit an extra space.  Perhaps there's a cleaner way to do this?  Another very
    // annoying special case is that for "operator <type>", the return code becomes part of the
    // method name, but is _NOT_ explicitly part of the type... :-( Increasingly it looks like
    // we should precompute where we want the retval to be rendered, and then emit it only
    // where we decided.
    if (retval && get_pname() != "operator ") {
      std::string retstr;
      if (retval->is_func_ptr()) {
        retstr = retval->str(match, true);
        if (retstr.size() > 0) stream << retstr;
      }
      else {
        retstr = retval->str(match, true);
        if (retstr.size() > 0) stream << retstr << " ";
      }
    }

    stream << calling_convention << " ";
    stream << str_name_qualifiers(name, match);
    if (retval && get_pname() == "operator ") {
      stream << retval->str(match);
    }
    if (match && symbol_type == SymbolType::VtorDisp) {
      stream << "`vtordisp{" << n1 << ',' << n2 << "}' ";
    } else if (match && method_property == MethodProperty::Thunk) {
      stream << "`adjustor{" << n2 << "}' ";
    }
    stream << str_function_arguments(match);

    if (retval && retval->is_func_ptr() && get_pname() != "operator ") {
      stream << ")";
      // The name of the function is not present...
      stream << retval->inner_type->str_function_arguments(match);
      stream << retval->inner_type->str_storage_properties(match);
    }

    stream << str_storage_properties(match);

    return stream.str();
  }

  if (symbol_type == SymbolType::MethodThunk) {
    stream << ' ' << calling_convention << ' ';
    stream << str_name_qualifiers(name, match);
    if (match) {
      stream << '{' << n1 << ",{flat}}' }'";
    }
    return stream.str();
  }

  if (symbol_type == SymbolType::String) {
    if (match) {
      return simple_type;
    }
    stream << inner_type->str() << '[' << n1 << "] = " << quote_string(get_pname());
    if (n1 > 32) {
      stream << "...";
    }
    return stream.str();
  }

  if (is_pointer || is_reference) {
    if (inner_type == nullptr) {
      std::cerr << "Unparse error: Inner type is not set for pointer or reference!" << std::endl;
    }
    else {
      if (inner_type->is_func) {
        // Less drama is required for non-existent return values because you can't pass constructors,
        // destructors, and opertator overloads?
        stream << inner_type->retval->str(match, true);
        // The calling convention is formatted differently...
        stream << " (" << inner_type->calling_convention;
        if (inner_type->is_member) {
          stream << ' ';
        }
      }
      else if (!inner_type->is_member) {
        stream << inner_type->str(match) << " ";
      }

      if (inner_type->is_member) {
        stream << str_name_qualifiers(inner_type->name, match) << "::";
      }
      stream << str_pointer_punctuation(match);
    }
  } else if (is_func && inner_type) {
    stream << inner_type->retval->str(match, true);
    stream << ' ' << inner_type->calling_convention;
    stream << inner_type->str_function_arguments(match);
  }

  stream << str_distance(match);
  stream << str_simple_type(match);
  stream << str_name_qualifiers(name, match);
  stream << str_array(match);
  stream << str_template_parameters(match);

  // Ugly. :-( Move the space from after the storage keywords to before the keywords.
  std::string spstr = str_storage_properties(match, is_retval);
  if (!spstr.empty()) {
    spstr.pop_back();
    stream << " " << spstr;
  }

  // If the symbol is a global object or a static class member, the name of the object (not the
  // type) will be in the instance_name and not the ordinary name field.
  if (symbol_type == SymbolType::GlobalObject || symbol_type == SymbolType::StaticClassMember
      || symbol_type == SymbolType::GlobalThing1 || symbol_type == SymbolType::GlobalThing2)
  {
    stream << " ";
    stream << str_name_qualifiers(instance_name, match);
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

  if (symbol_type == SymbolType::StaticGuard) {
    if (!name.empty()) {
      stream << "::";
    }
    stream << '{' << n1 << '}';
    if (match) {
      stream << '\'';
    }
  }

  if (!com_interface.empty()) {
    stream << "{for ";
    auto i = com_interface.begin();
    auto e = com_interface.end();
    while (i != e) {
      stream << '`' << (*i++)->str(match) << '\'';
      if (i != e) {
        stream << "s ";
      }
    }
    stream << '}';
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
  std::ostringstream stream;
  if (type == nullptr) {
    stream << constant_value;
  }
  else if (pointer) {
    if (type->symbol_type == SymbolType::ClassMethod
        || (type->is_func && type->is_member))
    {
      stream << '{' << type->str(match) << ',' << constant_value << '}';
    } else {
      stream << "std::addressof(" << type->str(match) << ')';
    }
  } else {
    return type->str(match);
  }
  return stream.str();
}

namespace detail {

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
    general_error("Attempt to read past end of mangled string.");
  }
  return mangled[offset];
}

[[noreturn]] void VisualStudioDemangler::bad_code(char c, const std::string & desc)
{
  error = boost::str(boost::format("Unrecognized %s code '%c' at offset %d") % desc % c % offset);
  throw Error(error);
}

[[noreturn]] void VisualStudioDemangler::general_error(const std::string & e)
{
  error = e;
  throw Error(error);
}

void VisualStudioDemangler::progress(const std::string & msg)
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
    bad_code(c, "calling convention");
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
VisualStudioDemangler::get_managed_properties(DemangledTypePtr & t, int & cli_array)
{
  cli_array = 0;

  char c = get_current_char();

  if (c == '$') {
    c = get_next_char();
    switch (c) {
     case 'A':
      t->is_gc = true;
      break;
     case 'B': // __pin  BUG!!! Unimplemented!
      t->is_pin = true;
      break;
     case '0': case '1': case '2':
      {
        // C++/CLI array
        auto xdigit = [this](char d) -> int {
                        if (d >= '0' && d <= '9')
                          return (d - '0');
                        else if (d >= 'a' && d <= 'f')
                          return (d - 'a');
                        else if (d >= 'A' && d <= 'F')
                          return (d - 'A');
                        else bad_code(d, "hex digit"); };
        int val = xdigit(c) * 16;
        c = get_next_char();
        val += xdigit(c);
        cli_array = val ? val : -1;
      }
      break;
     default:
      bad_code(c, "managed C++ property");
    }
    advance_to_next_char();
  }
  return t;
}

DemangledTypePtr &
VisualStudioDemangler::get_storage_class_modifiers(DemangledTypePtr & t)
{
  char c = get_current_char();

  // Type storage class modifiers.  These letters are currently non-overlapping with the
  // storage class and can occur zero or more times.  Technically it's probably invalid for
  // them to occur more than once each however.
  bool cont = true;
  while (cont) {
    progress("pointer storage class modifier");
    switch (c) {
     case 'E':
      t->ptr64 = true;        // <type> __ptr64
      break;
     case 'F':
      t->unaligned = true;    // __unaligned <type>
      break;
     case 'G':
      t->is_reference = true; // <type> &
      break;
     case 'H':
      t->is_refref = true;   // <type> &&
      break;
     case 'I':
      t->restrict = true;     // <type> __restrict
      break;
     default:
      cont = false;
    }
    if (cont) {
      c = get_next_char();
    }
  }

  return t;
}

// Pointer base codes.  Agner Fog's Table 13.
DemangledTypePtr &
VisualStudioDemangler::get_pointer_type(DemangledTypePtr & t, bool push)
{
  advance_to_next_char();
  get_storage_class_modifiers(t);
  int handling_cli_array;
  get_managed_properties(t, handling_cli_array);

  progress("pointer storage class");
  // Const and volatile for the thing being pointed to (or referenced).
  t->inner_type = std::make_shared<DemangledType>();
  get_storage_class(t->inner_type);

  if (t->inner_type->is_member && !t->inner_type->is_based) {
    get_fully_qualified_name(t->inner_type, push);
  }

  // Hack (like undname).
  if (t->inner_type->is_func) {
    progress("function pointed to");
    get_function(t->inner_type);
    // if (t->inner_type->is_member && !t->inner_type->is_based) {
    //   t->inner_type->calling_convention = "__thiscall";
    // }
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

  if (handling_cli_array) {
    auto at = std::make_shared<DemangledType>();
    at->name.push_back(std::make_shared<Namespace>("array"));
    at->name.push_back(std::make_shared<Namespace>("cli"));
    at->template_parameters.push_back(
      std::make_shared<DemangledTemplateParameter>(t->inner_type));
    if (handling_cli_array > 1) {
      at->template_parameters.push_back(
        std::make_shared<DemangledTemplateParameter>(handling_cli_array));
    }
    t->inner_type = at;
    t->is_gc = true;
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
    bad_code(c, "enum real type");
  }

  return t;
}

DemangledTypePtr VisualStudioDemangler::get_array_type(DemangledTypePtr & t, bool push) {
  t->is_array = true;
  auto num_dim = get_number();
  for (decltype(num_dim) i = 0; i < num_dim; ++i) {
    t->dimensions.push_back(uint64_t(get_number()));
  }
  return get_type(t, push);
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
   case 'Y': // array
    advance_to_next_char();
    return get_array_type(t, push);
   case 'Z': return update_simple_type(t, "...");
   case '0': case '1': case '2': case '3': case '4':
   case '5': case '6': case '7': case '8': case '9':
    // Consume the reference character...
    advance_to_next_char();
    return resolve_reference(type_stack, c);
   case '_': // Extended simple types.
    c = get_next_char();
    switch(c) {
     case '$': bad_code(c, "_w64 prefix");
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
     case 'O': bad_code(c, "unhandled array");
     case 'S': update_simple_type(t, "char16_t"); break;
     case 'U': update_simple_type(t, "char32_t"); break;
     case 'W': update_simple_type(t, "wchar_t"); break;
     case 'X': bad_code(c, "coclass");
     case 'Y': bad_code(c, "cointerface");
     default:
      bad_code(c, "extended '_' type");
    }
    // Apparently _X is a two character type, and two character types get pushed onto the stack.
    if (push) {
      type_stack.push_back(t);
      stack_debug(type_stack, type_stack.size()-1, "type");
    }
    return t;
   case '?': // Documented at wikiversity as "type modifier, template parameter"
    advance_to_next_char();
    get_storage_class(t);
    return get_type(t, push);
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
       case 'A':
        t->is_func = true;
        return get_pointer_type(t, push);
       case 'B':
        // Seems to be array type in template.  Next char should be 'Y'
        advance_to_next_char();
        return get_type(t, push);
       case 'C':
        advance_to_next_char();
        get_storage_class(t);
        return get_type(t, push);
       case 'T':
        advance_to_next_char();
        t->name.push_back(std::make_shared<Namespace>("nullptr_t"));
        t->name.push_back(std::make_shared<Namespace>("std"));
        return t;
       case 'V':
       case 'Z':
        // end of parameter pack.  Return null
        advance_to_next_char();
        return DemangledTypePtr();
       default:
        bad_code(c, "extended '$$' type");
      }
    }
    // All characters after a single '$' are template parameters.
    else {
      return get_templated_function_arg(t);
    }
   default:
    bad_code(c, "type");
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
   case '2': t->add_name("operator new"); break;
   case '3': t->add_name("operator delete"); break;
   case '4': t->add_name("operator="); break;
   case '5': t->add_name("operator>>"); break;
   case '6': t->add_name("operator<<"); break;
   case '7': t->add_name("operator!"); break;
   case '8': t->add_name("operator=="); break;
   case '9': t->add_name("operator!="); break;
   case 'A': t->add_name("operator[]"); break;
   case 'B': t->add_name("operator "); break; // missing logic?
   case 'C': t->add_name("operator->"); break;
   case 'D': t->add_name("operator*"); break;
   case 'E': t->add_name("operator++"); break;
   case 'F': t->add_name("operator--"); break;
   case 'G': t->add_name("operator-"); break;
   case 'H': t->add_name("operator+"); break;
   case 'I': t->add_name("operator&"); break;
   case 'J': t->add_name("operator->*"); break;
   case 'K': t->add_name("operator/"); break;
   case 'L': t->add_name("operator%"); break;
   case 'M': t->add_name("operator<"); break;
   case 'N': t->add_name("operator<="); break;
   case 'O': t->add_name("operator>"); break;
   case 'P': t->add_name("operator>="); break;
   case 'Q': t->add_name("operator,"); break;
   case 'R': t->add_name("operator()"); break;
   case 'S': t->add_name("operator~"); break;
   case 'T': t->add_name("operator^"); break;
   case 'U': t->add_name("operator|"); break;
   case 'V': t->add_name("operator&&"); break;
   case 'W': t->add_name("operator||"); break;
   case 'X': t->add_name("operator*="); break;
   case 'Y': t->add_name("operator+="); break;
   case 'Z': t->add_name("operator-="); break;
   case '?': {
     auto embedded = get_symbol();
     embedded->is_embedded = true;
     if (debug) std::cout << "The fully embedded type was:" << embedded->str() << std::endl;
     t->name.push_back(std::move(embedded));
     return t;
   }
   case '_':
    c = get_next_char();
    switch(c) {
     case '0': t->add_name("operator/="); break;
     case '1': t->add_name("operator%="); break;
     case '2': t->add_name("operator>>="); break;
     case '3': t->add_name("operator<<="); break;
     case '4': t->add_name("operator&="); break;
     case '5': t->add_name("operator|="); break;
     case '6': t->add_name("operator^="); break;
     case '7': t->add_name("`vftable'"); break;
     case '8': t->add_name("`vbtable'"); break;
     case '9': t->add_name("`vcall'"); break;
     case 'A': t->add_name("`typeof'"); break;
     case 'B': t->add_name("`local static guard'"); break;
     case 'C': get_string(t);
      return t;
     case 'D': t->add_name("`vbase destructor'"); break;
     case 'E': t->add_name("`vector deleting destructor'"); break;
     case 'F': t->add_name("`default constructor closure'"); break;
     case 'G': t->add_name("`scalar deleting destructor'"); break;
     case 'H': t->add_name("`vector constructor iterator'"); break;
     case 'I': t->add_name("`vector destructor iterator'"); break;
     case 'J': t->add_name("`vector vbase constructor iterator'"); break;
     case 'K': t->add_name("`virtual displacement map'"); break;
     case 'L': t->add_name("`eh vector constructor iterator'"); break;
     case 'M': t->add_name("`eh vector destructor iterator'"); break;
     case 'N': t->add_name("`eh vector vbase constructor iterator'"); break;
     case 'O': t->add_name("`copy constructor closure'"); break;
     case 'P': t->add_name("`udt returning'"); break;
     case 'R': return get_rtti(t);
     case 'S': t->add_name("`local vftable'"); break;
     case 'T': t->add_name("`local vftable constructor closure'"); break;
     case 'U': t->add_name("operator new[]"); break;
     case 'V': t->add_name("operator delete[]"); break;
     case 'X': t->add_name("`placement delete closure'"); break;
     case 'Y': t->add_name("`placement delete[] closure'"); break;
     case '_':
      c = get_next_char();
      switch(c) {
       case 'A': t->add_name("`managed vector constructor iterator'"); break;
       case 'B': t->add_name("`managed vector destructor iterator'"); break;
       case 'C': t->add_name("`eh vector copy constructor iterator'"); break;
       case 'D': t->add_name("`eh vector vbase copy constructor iterator'"); break;
       case 'E': t->add_name("`dynamic initializer'"); break;
       case 'F': t->add_name("`dynamic atexit destructor'"); break;
       case 'G': t->add_name("`vector copy constructor iterator'"); break;
       case 'H': t->add_name("`vector vbase copy constructor iterator'"); break;
       case 'I': t->add_name("`managed vector copy constructor iterator'"); break;
       case 'J': t->add_name("`local static thread guard'"); break;
       default:
        bad_code(c, "special name '__')");
      }
      break;
     default:
      bad_code(c, "special name '_'");
    }
    break;
   case '@':
    t->symbol_type = SymbolType::HexSymbol;
    advance_to_next_char();
    t->simple_type = get_literal();
    return t;
   default:
    bad_code(c, "special name");
  }

  advance_to_next_char();
  return t;
}

DemangledTypePtr & VisualStudioDemangler::get_string(DemangledTypePtr & t) {
  char c = get_next_char();
  if (c != '@') {
    bad_code(c, "string constant");
  }
  c = get_next_char();
  if (c != '_') {
    bad_code(c, "string constant");
  }
  c = get_next_char();
  bool multibyte = false;
  switch (c) {
   case '0': break;
   case '1': multibyte = true; break;
   default:
    bad_code(c, "string constant");
  }
  advance_to_next_char();
  auto real_len = get_number();
  auto len = std::min(real_len, int64_t(multibyte ? 64 : 32));
  UNUSED int64_t hash = get_number();
  std::string result;
  for (int64_t i = 0; i < len; ++i) {
    char v;
    c = get_current_char();
    if (c == '@') {
      break;
    }
    if (c == '?') {
      c = get_next_char();
      if (c == '$') {
        // Hexadecimal byte
        v = 0;
        for (int j = 0; j < 2; ++j) {
          c = get_next_char();
          if (c < 'A' || c > 'P') {
            bad_code(c, "character hex digit");
          }
          v = v * 16 + (c - 'A');
        }
      } else if (c >= '0' && c <= '9') {
        // Special encodings
        static char const * special = ",/\\:. \v\n'-";
        v = special[c - '0'];
      } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        v = c + 0x80;
      } else {
        bad_code(c, "string special char");
      }
    } else {
      v = c;
    }
    result.push_back(v);
    advance_to_next_char();
  }

  if (multibyte) {
    std::basic_string<char16_t> wide;
    for (size_t i = 0; i < result.size(); i += 2) {
      char16_t c16 = result[i] * 0x100 + result[i + 1];
      wide.push_back(c16);
    }
    result = boost::locale::conv::utf_to_utf<char>(wide);
  }
  if (result.back() == 0) {
    result.pop_back();
  }

  t->symbol_type = SymbolType::String;
  t->inner_type = std::make_shared<DemangledType>();
  t->inner_type->simple_type = multibyte ? "char16_t" : "char";
  t->simple_type = "`string'";
  t->n1 = multibyte ? (real_len / 2) : real_len;
  t->is_pointer = true;
  t->add_name(std::move(result));
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
    t->add_name("`RTTI Type Descriptor'");
    break;
   case '1': {
     advance_to_next_char();
     // These should be stored in the result...
     t->n1 = get_number();
     t->n2 = get_number();
     t->n3 = get_number();
     t->n4 = get_number();
     std::string location = boost::str(boost::format("(%d, %d, %d, %d)'")
                                       % t->n1 % t->n2 % t->n3 % t->n4);
     t->add_name("`RTTI Base Class Descriptor at " + location);
     break;
   }
   case '2':
    advance_to_next_char();
    t->add_name("`RTTI Base Class Array'"); break;
   case '3':
    advance_to_next_char();
    t->add_name("`RTTI Class Hierarchy Descriptor'"); break;
   case '4':
    advance_to_next_char();
    t->add_name("`RTTI Complete Object Locator'"); break;
   default:
    bad_code(c, "RTTI");
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
  t->is_member = is_member;

  // Unused currently...
  t->is_based = is_based;

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
      bad_code(c, "extended storage class");
    }
    break;
   default:
    bad_code(c, "storage class");
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
    bad_code(c, "return storage class");
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

   case '5':
    t->symbol_type = SymbolType::StaticGuard;
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

   case '$':
    c = get_current_char();
    advance_to_next_char();
    switch (c) {
     case '0': update_method(t, Scope::Private, MethodProperty::Thunk, Distance::Near); break;
     case '1': update_method(t, Scope::Private, MethodProperty::Thunk, Distance::Far); break;
     case '2': update_method(t, Scope::Protected, MethodProperty::Thunk, Distance::Near); break;
     case '3': update_method(t, Scope::Protected, MethodProperty::Thunk, Distance::Far); break;
     case '4': update_method(t, Scope::Public, MethodProperty::Thunk, Distance::Near); break;
     case '5': update_method(t, Scope::Public, MethodProperty::Thunk, Distance::Far); break;
     case 'B':
      t->method_property = MethodProperty::Thunk;
      t->symbol_type = SymbolType::MethodThunk;
      return t;
     case '$':
      // Prefix codes
      c = get_current_char();
      advance_to_next_char();
      switch (c) {
       case 'J':
        {
          t->extern_c = true;
          // Ignore the next <number> - 1 characters
          auto n = get_number() - 1;
          for (int i = 0; i < n; ++i) {
            advance_to_next_char();
          }
        }
        break;
       case 'F':
       case 'H':
        // Unknown.  No difference in undname output
        break;
       default:
        bad_code(c, "symbol type prefix");
      }
      return get_symbol_type(t);
     default:
      bad_code(c, "extended symbol type");
    }
    t->symbol_type = SymbolType::VtorDisp;
    return t;
    break;
   default:
    bad_code(c, "symbol type");
  }
}

// Storage class codes for methods.  Agner Fog's Table 15.
// Nearly identical to Table 12, but needs to update a function and lacks '?' introducer.
DemangledTypePtr & VisualStudioDemangler::process_method_storage_class(DemangledTypePtr & t)
{
  get_storage_class_modifiers(t);
  int handling_cli_array;
  get_managed_properties(t, handling_cli_array);
  if (handling_cli_array) {
    general_error("unexpected cli array");
  }

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
    bad_code(c, "method storage class");
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
    throw Error(error);
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
    bad_code(c, "templated function arg");
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


DemangledTypePtr & VisualStudioDemangler::get_templated_type(DemangledTypePtr & templated_type)
{
  // The current character was the '$' when this method was called.
  char c = get_next_char();
  progress("templated symbol");

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
       case 'H':
        advance_to_next_char();
        progress("constant function pointer template parameter");
        parameter = std::make_shared<DemangledTemplateParameter>(get_symbol());
        parameter->pointer = true;
        parameter->constant_value = get_number();
        break;
       case 'S':
        // Empty non-type parameter pack.  Treat similar to $$V
        advance_to_next_char();
        progress("empty non-type parameter pack");
        break;
       case '$':
        {
          // We'll interpret as a $$ type, but there could be any number of $s first.  So skip
          // past the last $ and then go back two
          auto pos = mangled.find_first_not_of('$', offset);
          if (pos == std::string::npos) {
            bad_code(c, "template argument");
          }
          offset = pos - 2;
          if (auto type = get_type()) {
            parameter = std::make_shared<DemangledTemplateParameter>(std::move(type));
          }
        }
        break;
       default:
        bad_code(c, "template argument");
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

  return templated_type;
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
        t->name.push_back(tt);
        if (pushing) {
          name_stack.push_back(std::move(tt));
          stack_debug(name_stack, name_stack.size()-1, "name");
        }
      }
      else {
        // This feels wrong...  If it's the first term in the name it's a special name, but if
        // it's not the first term it's a numbered namespace?  This seems like more evidence
        // that the parsing of the first term is definitely a different routine than the
        // namespace terms in a fully qualified name...   Perhaps some code cleanup is needed?
        if (first || get_current_char() == '?') {
          auto tt = std::make_shared<DemangledType>();
          tt = get_special_name_code(tt);
          if (tt->symbol_type != t->symbol_type) {
            return t = std::move(tt);
          }
          t->name.push_back(std::move(tt));
        }
        else {
          // Wow is this ugly.  But it looks like Microsoft really did it this way, so what
          // else can we do?  A number that starts with 'A' would be a namespace number that
          // has a leading zero digit, which is not required.  Thus it signals a strangely
          // handled "anonymous namespace" with a discarded unqie identifier.
          if (get_current_char() == 'A') {
            t->name.push_back(get_anonymous_namespace());
          }
          else {
            uint64_t number = get_number();
            std::string numbered_namespace = boost::str(boost::format("`%d'") % number);
            if (debug) std::cout << "Found numbered namespace: "
                                 << numbered_namespace << std::endl;
            auto nns = std::make_shared<Namespace>(numbered_namespace);
            t->name.push_back(std::move(nns));
          }
        }
      }
    }
    else if (c >= '0' && c <= '9') {
      progress("reference to symbol");
      t->name.push_back(resolve_reference(name_stack, c));
      advance_to_next_char();
    }
    else {
      auto ns = std::make_shared<Namespace>(get_literal());
      t->name.push_back(ns);
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
    general_error(
      boost::str(boost::format("Expected '0' in anonymous namespace, found '%c'.") % c));
  }
  c = get_next_char();
  if (c != 'x') {
    general_error(
      boost::str(boost::format("Expected 'x' in anonymous namespace, found '%c'.") % c));
  }

  size_t digits = 0;
  c = get_next_char();
  progress("anonymous namespace digits");
  while (c != '@') {
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
      // Allowed
    }
    else {
      general_error(
        boost::str(boost::format("Disallowed character '%c' in anonymous namespace digits.")
                   % c));
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
    switch (c) {
      // misc punctuation
     case '_': case '$':
     case '<': case '>':
     case '-': case '.':
      break;
     default:
      if (!((c >= 'A' && c <= 'Z') || // uppercase letters
            (c >= 'a' && c <= 'z') || // lowercase letters
            (c >= '0' && c <= '9'))) // digits
      {
        general_error(
          boost::str(boost::format("Disallowed character '%c' in literal string.") % c));
      }
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
    general_error("Numbers must be terminated with an '@' character. ");
  }
  progress("end of number");
  advance_to_next_char();

  if (digits_found <= 0) {
    general_error("There were too few hex digits endecoded in the number.");
  }

  if (digits_found > 16) {
    general_error("There were too many hex digits encoded in the number.");
  }

  if (negative) return -num;
  return num;
}

DemangledTypePtr & VisualStudioDemangler::get_function(DemangledTypePtr & t) {
  // Storage class for methods
  if (t->is_func && t->is_member) {
    auto tmp = std::make_shared<DemangledType>();
    get_storage_class_modifiers(tmp);
    get_storage_class(tmp);
    t->is_const = tmp->is_const;
    t->is_volatile = tmp->is_volatile;
    t->ptr64 = tmp->ptr64;
    t->unaligned = tmp->unaligned;
    t->restrict = tmp->restrict;
  }
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
  //  general_error("Expected 'Z' to terminate function.");
  //}
  return t;
}

DemangledTypePtr VisualStudioDemangler::get_symbol() {
  get_symbol_start();

  auto t = std::make_shared<DemangledType>();
  get_fully_qualified_name(t, false);
  if (t->symbol_type == SymbolType::Unspecified) {
    get_symbol_type(t);
  }

  switch(t->symbol_type) {
   case SymbolType::GlobalThing2:
    {
      t->instance_name = t->name;
      t->name.clear();
      process_method_storage_class(t);
      // The interface name is optional.
      while (get_current_char() != '@') {
        auto n = std::make_shared<DemangledType>();
        t->com_interface.push_back(get_fully_qualified_name(n, false));
      }
    }
    return t;
   case SymbolType::String:
   case SymbolType::GlobalThing1:
   case SymbolType::HexSymbol:
    return t;
   case SymbolType::GlobalObject:
   case SymbolType::StaticClassMember:
    // This is backwards.  We should have read the initial name into a special place, and then
    // had all other places use the default place...
    t->instance_name = t->name;
    t->name.clear();
    get_type(t); // Table 9
    get_storage_class_modifiers(t);
    get_storage_class(t); // Table 10
    return t;
   case SymbolType::VtorDisp:
    // Get the displacement, then treat as method
    t->n1 = get_number();
    // Fall through
   case SymbolType::ClassMethod:
    if (t->method_property == MethodProperty::Thunk) {
      // get the thunk offset
      t->n2 = get_number();
    }
    // There's no storage class code for static class methods.
    if (t->method_property != MethodProperty::Static) {
      process_method_storage_class(t); // Table 15
    }
    // Fall through
   case SymbolType::GlobalFunction:
    return get_function(t);
   case SymbolType::StaticGuard:
    t->n1 = get_number();
    return t;
   case SymbolType::MethodThunk:
    t->n1 = get_number();
    switch (char c = get_current_char()) {
     case 'A': break; // Only known type: flat
     default: bad_code(c, "method thunk type");
    }
    advance_to_next_char();
    process_calling_convention(t);
    return t;
   default:
    general_error("Unrecognized symbol type.");
  }
}


// Not part of the constructor because it throws.
DemangledTypePtr VisualStudioDemangler::analyze() {

  char c = get_current_char();
  if (c == '_') {
    general_error("Mangled names beginning with '_' are currently not supported.");
    throw Error(error);
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

} // namespace detail
} // namespace demangle

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
