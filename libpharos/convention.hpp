// Copyright 2015-2019, 2022 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Convention_H
#define Pharos_Convention_H

#include "semantics.hpp"
// For RegisterSet..
#include "state.hpp"
#include "threads.hpp"
#include "apidb.hpp"

namespace pharos {

// Forward declaration to simplify include cycles.
class FunctionDescriptor;

//===========================================================================================
// Calling convention
//===========================================================================================

// Describes a particular calling convention.  This class is currently pretty much a copy of
// Robb Matzke's BinaryCallingConvention::Convention.  His implementation was obviously
// incomplete, but he put a lot of thought into designing and documenting the class, so I
// wanted to reuse as much of his defintiion as possible.  Since 99% of the parts worth keeping
// were in the header, and there was no convenient way to extend the existing class, I just
// made a copy in our coding style, which was kind of important to me since there was a loit of
// work still to be done.  Our implementation was probably going to diverge significantly from
// his anyway, and so this seemed reasonable.

class CallingConvention {
 public:

  // The order that arguments are pushed onto the stack.  If a particular call has more
  // arguments than the size of the reg_params vector then the extra (last) arguments are
  // pushed onto the stack either in left-to-right or right-to-left lexical order.
  enum ParameterOrder {
    ORDER_LTR,     // Parameters pushed in left to right (Pascal) order.
    ORDER_RTL,     // Parameters pushed in right to left (C) order.
    ORDER_UNKNOWN, // Parameter order is not known.
  };

  // Location of "this" argument.  For object oriented code, the "this" object of class methods
  // needs to be passed to the function implementing the method.  Calling conventions vary in
  // where they put the "this" pointer.
  enum ThisPointerLocation {
    THIS_FIRST_PARAM,     // The "this" pointer is treated as an implicit first parameter.
    THIS_REGISTER,        // A dedicated register is used for the "this" pointer.
    THIS_NOT_APPLICABLE,  // Calling convention is not valid for class methods.
    THIS_UNKNOWN,         // Location of "this" pointer is not known.
  };

  // Location of return value.  This is insufficiently expressive.  Functions are allowed to
  // return 8-byte structures in EDX:EAX, and floating point values in ST0.
  enum ReturnValueLocation {
    RETVAL_STACK,          // The return value is placed on the stack. (FIXME: more specificity)
    RETVAL_REGISTER,       // Return value is stored in a register specified by retval_reg.
    RETVAL_NOT_APPLICABLE, // Function does not return a value.
    RETVAL_UNKNOWN,        // Location of return value is not known.
  };

  // Specifies how the stack is cleaned up.
  enum StackCleanup {
    CLEANUP_CALLER,         // The caller cleans up the stack.
    CLEANUP_CALLEE,         // The called function cleans up the stack.
    CLEANUP_NOT_APPLICABLE, // No need to clean up the stack because the stack is not used.
    CLEANUP_UNKNOWN,        // It is not known how the stack is cleaned up.
  };

 private:

  // Word size for the architecture for which this calling convention applies.  The size is
  // measured in bits.  When searching for a calling convention dictionary, only conventions
  // matching the specified word size are considered.  This is rquired because the calling
  // convention with the same name and purpose can be of different on each platform.
  size_t word_size;

  // The name of the calling convention.  Certain calling conventions have well-defined names,
  // such as "__cdecl" and can be looked up by their name in the calling convention dictionary.
  // Other ad hoc calling conventions have arbitrary names, or even no name at all.  The names
  // need not be unique and are mainly for human consumtion.
  std::string name;

  // The name of the compiler that produces the calling convention.  Cory thinks that Borland
  // fastcall is different then C++ fastcall.  We could include this information in the name,
  // but we could also handle word size there, so this seems more consistent.
  std::string compiler;

  // The optional comment field is for human consumption and provides a londer description of
  // the calling convention.  Cory's not sure why this would really be used, but he sees no
  // harm in keeping it, and it might be useful.
  std::string comment;

  // The order of the parameters on the stack.
  ParameterOrder param_order;

  // The location of the "this" argument.
  ThisPointerLocation this_location;

  // Dedicated register for "this" pointer when this_location is THIS_REGISTER. Returns the an
  // invalid register if the location is other than THIS_REGISTER or if the register is
  // unknown, and sets the location to THIS_REGISTER when setting a register. When setting the
  // register, a default-constructed value means that the "this" pointer is stored in a
  // register but it is unknown which register that is.
  RegisterDescriptor this_reg;

  // Location of return value.
  ReturnValueLocation retval_location;

  // Dedicated register for return value when return_location is RETVAL_REGISTER.  Returns an
  // invalid register if the location is other than RETVAL_REGISTER or if the register is
  // unknown, and sets the location to RETVAL_REGISTER when setting a register.  When setting
  // the register, a default constructed value means that the return value is stored in a
  // register but it is unknown which register that is.  This is insufficiently expressive.
  // Functions are allowed to return 8-byte structures in EDX:EAX, and floating point values in
  // ST0.
  RegisterDescriptor retval_reg;

  // Specifies how the stack is cleaned up.
  StackCleanup stack_cleanup;

  // Stack alignment.  Some functions adjust the stack pointer so local variables are aligned
  // on a certain byte boundary.  The alignment is measured in bytes and is usually a power of
  // two. A value of one indicates that no alignment is necessary; a value of zero indicates
  // that the alignment is unknown.
  size_t stack_alignment;

  // Registers used for initial arguments.  This vector lists the registers (if any) that are
  // used for initial parameters. The length of the vector doesn't correspond to the number of
  // parameters actually passed.  In other words, a particular function call might pass only
  // two parameters even though this vector has four entries.  If a function call has more
  // arguments than the number of registers available to the calling convention, the additional
  // arguments are passed on the stack.  Parameters are assigned to the registers in
  // left-to-right order from the vector.  Some additional work is required here to support
  // multiple sets of registers based on the size of the parameter type.
  RegisterVector reg_params;

  // The registers that are required to be used as parameters in the convention.  On second
  // thought, Cory thinks that this can be implemented as: if there are any reg_params, then at
  // least one of those is required.
  // RegisterVector required_registers;

  // Registers saved by the callee (these will not be changed across the function).  These are
  // registers that if they're modified, the function can't be following the calling
  // convention.  All other registers are assumed to be volatile (saved by caller if needed).
  RegisterSet nonvolatile;

  // With regards to floating point, Microsoft says: If you are writing assembly routines for
  // the floating point coprocessor, you must preserve the floating point control word and
  // clean the coprocessor stack unless you are returning a float or double value (which your
  // function should return in ST(0)).

 public:

  // Constructor. All calling conventions must have a non-zero word size and non-empty
  // name. The name need not be unique, but it is often helpful if it is.  The compiler name
  // field may be empty.
  CallingConvention(size_t word_size_, const std::string &name_, const std::string &compiler_);

  size_t get_word_size() const { return word_size; }
  void set_word_size(size_t w) { word_size = w; }

  const std::string& get_name() const { return name; }
  void set_name(const std::string &n) { name = n; }

  const std::string &get_compiler() const { return compiler; }
  void set_compiler(const std::string &c) { compiler = c; }

  const std::string &get_comment() const { return comment; }
  void set_comment(const std::string &c) { comment = c; }

  ParameterOrder get_param_order() const { return param_order; }
  void set_param_order(ParameterOrder order) { param_order = order; }

  ThisPointerLocation get_this_location() const { return this_location; }
  void set_this_location(ThisPointerLocation loc) { this_location = loc; }

  RegisterDescriptor get_this_register() const {
    if (this_location != THIS_REGISTER) return RegisterDescriptor();
    return this_reg;
  }
  void set_this_register(RegisterDescriptor reg) {
    this_location = THIS_REGISTER;
    this_reg = reg;
  }

  ReturnValueLocation get_retval_location() const { return retval_location; }
  void set_retval_location(ReturnValueLocation loc) { retval_location = loc; }

  RegisterDescriptor get_retval_register() const {
    if (retval_location != RETVAL_REGISTER) return RegisterDescriptor();
    return retval_reg;
  }
  void set_retval_register(RegisterDescriptor reg) {
    retval_location = RETVAL_REGISTER;
    retval_reg = reg;
  }

  StackCleanup get_stack_cleanup() const { return stack_cleanup; }
  void set_stack_cleanup(StackCleanup cleanup) { stack_cleanup = cleanup; }

  size_t get_stack_alignment() const { return stack_alignment; }
  void set_stack_alignment(size_t alignment) { stack_alignment = alignment; }

  const RegisterVector& get_reg_params() const { return reg_params; }
  void add_reg_param(RegisterDescriptor reg) { reg_params.push_back(reg); }

  const RegisterSet& get_nonvolatile() const { return nonvolatile; }
  void add_nonvolatile(RegisterDictionaryPtrArg dict, std::string name);
  void add_nonvolatile(RegisterDescriptor rd);
  void add_nonvolatile(const RegisterSet& regs);

  // Write information about this calling convention to the debug log stream.
  void report() const;
};

// Robb's design kept the calling conventions in a vector.  Cory's not at all convinced of the
// merits of that approch yet, so he's commented out most of that code here.
// std::vector<const Convention*> cconvs;

// Appends the specified calling convention to this dictionary.  No check is made for whether
// the calling convention is already present in the dictionary--it is added regardless.
//void append(const Convention *cconv) { cconvs.push_back(cconv); }

// Deletes the specified calling convention from the dictionary.
//void erase(const Convention *conv);
//void erase(size_t index);

// Clears the dictionary.  Removes all calling conventions from the dictionary without
// destroying them.
// void clear() { cconvs.clear(); }

// Returns the size of the dictionary.  Returns the number of calling conventions in the
// dictionary. Duplicates are counted multiple times.
// size_t size() { return cconvs.size(); }

//===========================================================================================
// Parameter definition
//===========================================================================================

// Describes a single parameter in terms of it's value and location.  The parameter definitions
// are attached to both the function descriptors and the call descriptors with slightly
// different meanings.  Import descriptions get their parameters from their embedded function
// descriptor.  Not all fields are needed for both functions and calls, but there are enough
// fields in common that Cory has decided to use the same structure for both definitions (at
// least until we've figured out exactly what's needed).  Currently, he keeps changing his mind
// abotu the right thing to do. :-(

class ParameterDefinition {
 public:
  // Determines whether this parameter is a a read-only, read-write, or write-only parameter.
  // This member was added as part of the API database code, and is not currently computed
  // based on access patterns for functions linked into the excutable.  It should be.
  enum DirectionEnum { DIRECTION_NONE, DIRECTION_IN, DIRECTION_OUT, DIRECTION_INOUT };

 private:

  struct data {
    // Cory has no problem with making these all public right now, because access is pretty much
    // going to be entirely through const objects anyway (hopefully/maybe?).  This is still being
    // figured out...

    // This parameter's number is source code order.  This should match the order in the vector,
    // and is enforced by making users call add_parameter() to get the parameter into the list?
    size_t num;

    // The name of the field if known (presumably assigned from imports or the user's config).
    // Probably just copied from the function descriptor when associated with a call, although
    // there are some interesting questions about how to handle calls to multiple functions with
    // identical types and different names.
    std::string name;

    // This will eventually be populated with type information for the parameter (first from
    // imports, and later from the type recovery system).  Chuck suggested that we would key the
    // types by a string representation of the type and Cory agreeed, so this field is
    // simultaneously the human readable type and a key into the real type map or whatever.  It
    // would appear that in C++ at least, this is just a copy of the type from the matching
    // function parameter definition.
    std::string type;

    // The symbolic value that represents this parameter in the current function.  When
    // associated with a function descriptor, this is the value of the parameter in the called
    // function, and is usually just a single symbolic variable (although there currently appears
    // to be some bug in memory read/write infrastructure that occasionally yields a
    // concat/extract expression).  When attached to a call descriptor this is the value in the
    // calling function, where it may have a wide variety of values including complex
    // expressions, and references to memory that were in fact parameters to function containing
    // the call being analyzed.
    SymbolicValuePtr value;

    // If the value of the parameter refers to an address with a defined value, this field
    // contains the value pointed to.  It does not mean that the parameter is actually a pointer,
    // which will require additional type discovery effort.  At the current time, this field is
    // available for systems that have better human provided type information (e.g. ApiAnalyzer)
    // so that they can better know what the machine state was at the time of the call.  This
    // value will be NULL if there was nothing at the parameter's memory address at the time of
    // the call.
    SymbolicValuePtr value_pointed_to;

    // If this parameter was passed in a register, this value will be the appropriate register
    // descriptor, otherwise it will be the default-constructed descriptor.  This should always
    // match between the caller and the called function.
    RegisterDescriptor reg;

    // If this parameter was passed on the stack, the delta to where the parameter is stored
    // relative to the return address of the call.  In practice this means that these values
    // begin at zero, and grow in increments of four for each stack parameter.  Given this
    // choice, the stack deltas should match between the caller and the called function.

    // It might be cleaner to use the deltas from the current context (calling function or called
    // function) to be consistent with the rest of these fields.  In the called function, they
    // would all be shifted by the size of a return address, and in the caller by the stacl delta
    // at the time of the call.  I think the merits of this choice is at least partially
    // dependent on how well we're doing at calculating stack deltas, and the address field ends
    // up being used.
    size_t stack_delta;

    // If the parameter is a stack paramater, this is the memory address of the parameter in the
    // form of a symbolic value.  It is by necessity specific to the context (caller or called
    // function), and includes both the initial vaue of ESP in each context as well as any
    // adjustments required for the size of the return address in the called context.
    SymbolicValuePtr address;

    // In the called context, this is the instruction that provides evidence that the parameter
    // was read while uninitilized.  Mostly useful for determining how we decided that there was
    // a parameter at all.  In the caller context, this is the instruction that passed the
    // parameter (push it onto the stack or loaded it into a register).
    const SgAsmInstruction* insn;

    DirectionEnum direction = DIRECTION_NONE;
  };

  data d;
  mutable shared_mutex mutex;

  ParameterDefinition() = default;

 public:

  // Chuck has remarked that this class should perhaps contain an abstract access instead of
  // the value, address, and register descriptor.  This would also add a bit size and
  // read/write flags that may not be appropriate (but wouldn't be harmful either).  The
  // AbstractAccess doesn't and shouldn't contain a stack delta value, a name or a type.  The
  // merits of this approach will increase if we being using abstract accesses more widely.

  // Jeff Gennari has remarked that we should probably be recording whether the parameter was
  // used for input-only, input-output, or output-only, since there's a fairly common paradigm
  // of returning values by updating the memory pointed to by pointer parameters.  That can be
  // added in the future, but isn't currently supported.

  // A constructor convenient for adding stack parameters.
  ParameterDefinition(
    size_t c, const SymbolicValuePtr& v, std::string n, std::string t,
    const SgAsmInstruction* i, const SymbolicValuePtr& a, size_t d);

  // A form convenient for adding register parameters.
  ParameterDefinition(
    size_t c, const SymbolicValuePtr& v, std::string n, std::string t,
    const SgAsmInstruction* i, RegisterDescriptor r);

  ParameterDefinition(ParameterDefinition const & other) {
    *this = other;
  }
  ParameterDefinition &operator=(ParameterDefinition const & other) {
    read_guard<decltype(other.mutex)> guard{other.mutex};
    d = other.d;
    return *this;
  }

  ParameterDefinition(ParameterDefinition &&) = delete;
  ParameterDefinition &operator=(ParameterDefinition &&) = delete;

  bool is_reg() const { return d.reg.is_valid(); }
  bool is_stack() const { return !d.reg.is_valid(); }

  size_t get_num() const { return d.num; }
  const std::string& get_name() const {
    read_guard<decltype(mutex)> guard{mutex};
    return d.name;
  }
  void set_name(std::string n) {
    write_guard<decltype(mutex)> guard{mutex};
    d.name = std::move(n);
  }
  const std::string & get_type() const {
    read_guard<decltype(mutex)> guard{mutex};
    return d.type;
  }
  void set_type(std::string t) {
    write_guard<decltype(mutex)> guard{mutex};
    d.type = std::move(t);
  }
  DirectionEnum get_direction() const {
    read_guard<decltype(mutex)> guard{mutex};
    return d.direction;
  }
  SymbolicValuePtr get_value() const {
    read_guard<decltype(mutex)> guard{mutex};
    return d.value;
  }
  void set_value(SymbolicValuePtr p) {
    write_guard<decltype(mutex)> guard{mutex};
    d.value = p;
  }
  SymbolicValuePtr get_value_pointed_to() const { return d.value_pointed_to; }
  SymbolicValuePtr get_address() const { return d.address; }
  TreeNodePtr get_expression() const {
    read_guard<decltype(mutex)> guard{mutex};
    return d.value->get_expression();
  }
  void set_stack_attributes(const SymbolicValuePtr& v, const SymbolicValuePtr& a,
                            SgAsmInstruction* i, const SymbolicValuePtr& p);
  void set_reg_attributes(const SymbolicValuePtr& v, const SgAsmInstruction* i,
                          const SymbolicValuePtr& p);

  void copy_parameter_description(ParameterDefinition const & other);
  void copy_parameter_description(APIParam const & other);
  void set_parameter_description(std::string n, std::string t, DirectionEnum d);

  RegisterDescriptor get_register() const { return d.reg; }
  size_t get_stack_delta() const { return d.stack_delta; }
  SgAsmInstruction const * get_insn() const { return d.insn; }

  // Spew a description of the parameter to the log.
  void debug() const;
  std::string to_string() const;
};

//===========================================================================================
// Parameter list
//===========================================================================================

// Describes the parameters to a specific function.  This defintion specifies the parameters in
// source code order irrespective of how the calling convention marshals them onto the stack,
// and makes the values of those parameters conveniently accessible.  This is likely to be the
// most useful interface for interacting with the parameters to the function.

// This presentation, while convenient and useful prevents some complications in corner cases
// where there's ambiguity about the calling convention.  The assumption currently being made
// is that any of the "matched" calling conventions could be valid, and so it's not
// unreasonable to just pick the first one and use it for ordering and other source code level
// details.  In cases where there were no matching calling conventions, we don't want to just
// abandon the use of this API completely because that would require higher level code to
// support both this API and the lower level RegisterUsage API.  The solution appears to be to
// set convention to NULL in those cases, and report all read registers and memory as
// parameters and all changed registers as return values.  This should generally produce
// correct results for custom calling conventions in algorithms that doing something for each
// parameter or return value (although there may be more of these than expected when the
// calling convention was not recognized).

using ParamVector = std::vector<ParameterDefinition>;

class ParameterList {

  struct data {
    // The calling convention that explains this interpretation of the parameters.
    const CallingConvention* convention = nullptr;

    // The ordered list of the parameters.
    ParamVector params;

    // The return values.  There's a lot of poorly understood stuff surrounding multiple return
    // values right now.  Cory feels like this issue is parallel to the parameter definitions,
    // which is to say that meaning, ordering, etc. begins to emerge only when you assign a
    // particular calling convention to the factual set of changed registers recorded in the
    // RegisterUsage object.  So that object would report all changed registers, and here we
    // would restrict ourselves to the ones that were intended to be used as a return value.
    // That will pretty much always be EAX on x86 and RAX on x64, but technically it could
    // include EDX and ST0 was well, which are currently completely unsupported in our code.  I
    // wouldn't be surprised to find other architectures that return values on the stack, and
    // return mutiple values.  Thus the conclusion to declare returns as a ParamVector.
    ParamVector returns;
  };

  // These should be private to enforce the internal consistency of the object.
  ParameterDefinition* get_rw_stack_parameter(size_t delta);
  ParameterDefinition* get_rw_reg_parameter(RegisterDescriptor rd);
  ParameterDefinition* get_rw_return_reg(RegisterDescriptor rd);

  data d;

  mutable shared_mutex mutex;

 public:
  ParameterList() = default;
  ParameterList(ParameterList const & other) {
    *this = other;
  }
  ParameterList & operator=(ParameterList const & other) {
    read_guard<decltype(other.mutex)> guard{other.mutex};
    d = other.d;
    return *this;
  }

  ParameterList(ParameterList &&) = delete;
  ParameterList & operator=(ParameterList &&) = delete;

  // Find a stack parameter at a specific stack delta.
  const ParameterDefinition* get_stack_parameter(size_t delta) const;
  const ParameterDefinition* get_reg_parameter(RegisterDescriptor rd) const;
  const ParameterDefinition* get_return_reg(RegisterDescriptor rd) const;

  auto get_params() const { return make_read_locked_range(d.params, mutex); }
  auto get_returns() const { return make_read_locked_range(d.returns, mutex); }

  // Get and set the calling convention.  Cory would like to isolate this better.  The
  // convention should only ever be set once by the function descriptor shortly after
  // determining wich convention is the best match.  Perhaps use friend?
  void set_calling_convention(const CallingConvention* c) { d.convention = c; }
  const CallingConvention* get_calling_convention() const { return d.convention; }

  // Some discussion with Duggan convinced Cory that the API cor creating new parameters really
  // ought to involve a builder class where the restrictions have been temporarily relaxed.
  // That API would have methods that are no longer appropriate to call once the parameter list
  // has been "finalized", plus it would give us a place that's guaranteed to be called where
  // we can make assertions about the caller parameter list not matching the called parameter
  // list.  Unfortunately, that doesn't actually improve our results, just our code, so I'm
  // leaving that improvement for a later day.

  // Find and create if needed the parameter at a specific stack delta.
  ParameterDefinition* create_stack_parameter(size_t delta);
  // Find and create if needed the parameter for a given register descriptor.
  ParameterDefinition & create_reg_parameter(RegisterDescriptor r,
                                             const SymbolicValuePtr v,
                                             const SgAsmInstruction* i,
                                             const SymbolicValuePtr p);
  ParameterDefinition & create_return_reg(RegisterDescriptor r,
                                          const SymbolicValuePtr v);


  // Spew a description of the parameters to the log.
  void debug() const;
};

//===========================================================================================
// Saved Register
//===========================================================================================

// This class communciates the details of a saved and restored register.  It allows us to no
// only identify the saved registers, but the instructions that did the saving and the
// restoring.

class SavedRegister {
 public:
  // The register that was saved.
  RegisterDescriptor reg;
  // The instruction that did the saving (usually a push).
  SgAsmInstruction* save;
  // The instruction that did the restoring (usually a pop).
  SgAsmInstruction* restore;

  SavedRegister(RegisterDescriptor r, SgAsmInstruction* push, SgAsmInstruction* pop);
};

class SavedRegisterCompare {
 public:
  bool operator()(const SavedRegister& x, const SavedRegister& y) const;
};
using SavedRegisterSet = std::set<SavedRegister, SavedRegisterCompare>;

using RegisterEvidenceMap = std::map<RegisterDescriptor, const SgAsmInstruction*>;

//===========================================================================================
// Register usage
//===========================================================================================

// Describes the register usage of a specific function.  This class is primarily used for
// determining the calling convention from a pattern of register accesses.
class RegisterUsage {

  // Populate saved and parameter registers.
  void analyze_parameters();
  // Populate changed and unchanged registers.
  void analyze_changed();

 public:
  FunctionDescriptor const * fd = NULL;

  // Registers that were changed between the input state and the output state.
  RegisterSet changed_registers;
  // Registers that were saved and then restored.  (A subset of unchanged).
  SavedRegisterSet saved_registers;
  // Registers that were read as a parameter to the function.
  RegisterEvidenceMap parameter_registers;

  // Instructions only used to allocate stack memory
  InsnSet stack_allocation_insns;

  // These two may not be needed...

  // Registers that were read at anytime in the execution of the function.
  RegisterSet read_registers;
  // Registers that were written at anytime in the execution of the function.
  RegisterSet written_registers;

  // Analyze the function...
  void analyze(FunctionDescriptor const * f);

  // Check whether a given instruction saves a register.  If so, add an entry to
  // saved_registers.
  bool check_saved_register(SgAsmX86Instruction* insn, RegisterDescriptor reg);

  // Return a parameter list object describing the parameters.
  ParameterList* make_parameter_list();
};

// For use inside the matcher, where the calling conventions are allocated.
using CallingConventionVector = std::vector<CallingConvention>;
// For use inside FunctionDescriptors where we simply want to reference a calling convention.
using CallingConventionPtrVector = std::vector<const CallingConvention*>;

// This class enumerates clearly defined standardized calling conventions.  It's job is to
// match arbitrary patterns of register and stack parameter accesses agaist these known
// conventions, and return a list of matching conventions.
class CallingConventionMatcher {
 private:

  RegisterDictionaryPtr regdict;
  CallingConventionVector conventions;

 public:

  CallingConventionMatcher();

  // Write information about each calling convention to the debug log stream.
  void report() const;

  RegisterDictionaryPtrArg get_regdict() { return regdict; }
  CallingConventionPtrVector match(const FunctionDescriptor* fd,
                                   bool allow_unused_parameters = true) const;

  // Finds a calling convention.  The vector is scanned to find a calling convention having the
  // specified name and wordsize.  Returns a pointer to the matching calling convention, or the
  // null pointer if no match was found.
  const CallingConvention* find(size_t word_size, const std::string &name) const;

};

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
