% Copyright 2020 Carnegie Mellon University.

% ============================================================================================
% Declare the dynamic predicates that constitute our OOAnalyzer initial facts.
% ============================================================================================

% This file documents the "initial facts" that are asserted by the C++ component to describe
% the likely object-oriented behaviors of the program being analyzed.  They are essentially the
% "inputs" to the Prolog reasoning component of OOAnalyzer.  These facts are never asserted
% dynamically or are changed in any way during the execution of the Prolog component.  This is
% in contrast to the "dynamic facts", which typically of the form factXXX, and are concluded by
% the reasoning and guessing rules of the Prolog logic.

% fileInfo(FileMD5, Filename).
%
% Documents which executable file was analyzed, reporting the FileMD5 and Filename.  This
% information is used in part to pair JSON outputs with inpute executables.
%
initialFact(fileInfo/2).

% returnsSelf(Method).
%
% Method returns ECX in EAX.
%
initialFact(returnsSelf/1).

% noCallsBefore(Method).
%
% Method meets C++ ordering expectations for a constructor (e.g. no calls before it).
%
initialFact(noCallsBefore/1).

% noCallsAfter(Method).
%
%  Method meets C++ ordering expectations for a destructor (e.g. no calls after it).
%
initialFact(noCallsAfter/1).

% uninitializedReads(Method).
%
% Method has uninitialized reads that are often (but not always) indicative that Method is not
% a constructor.  Specifically, the method reads members from the object that are not
% initialized in the local evaluation context.  The most significant (only?) case that this
% algorithm does not test for is reads of members that were initialized by a call to another
% method such as a parent constructor.
%
initialFact(uninitializedReads/1).

% insnCallsDelete(Insn, Func, ThisPtr).
%
% Instruction Insn in Function Func calls the delete method.  The ThisPtr argument is the hash
% of the this-pointer that was passed to the delete method.  Note that the determination of
% which functions are delete() is not 100% correct and has small numbers of both false
% negatives and false positives.  This fact frequently does not include class specific custom
% delete() overrides.
%
initialFact(insnCallsDelete/3).

% insnCallsNew(Insn, Func, ThisPtr).
%
% Instruction Insn in Function Func calls the new method.  The ThisPtr argument is the hash
% of the this-pointer that was returned by the new method.  Note that the determination of
% which functions are new() is not 100% correct and has small numbers of both false
% negatives and false positives, although it's generally better that delete detection.
%
initialFact(insnCallsNew/3).

% purecall(Address).
%
% The method/function/import at Address is an implementation of the purecall stub that Visual
% Studio uses to mark virtual methods on abstract base classes that do not have
% implementations.
%
initialFact(purecall/1).

% rTTICompleteObjectLocator(Pointer, Address, TDAddress, CHDAddress, Offset, CDOffset)
%
% There's a pointer to an RTTI Complete Object Locator data structure at Pointer which points
% to Address which is where the RTTI Complete Object Locator data structure is located in
% memory.  TDAddress and CHDAddress are the addresses of the corresponding Type Descriptor and
% Class Hierarchy Descriptor respectively.  Offset is described as the offset of this VFTable
% in the class.  CDOffset is described as the constructor displacement offset (?).  This object
% occurs once per VFTable (not once per class), and the VFTable being described occurs one
% pointer length (typically 4 or 8 bytes) beyond the address of pointer.
%
initialFact(rTTICompleteObjectLocator/6).

% rTTITypeDescriptor(Address, VFTable, Name, DemangledName)
%
% There's an RTTI Type Descriptor at Address.  VFTable points to type_info::`vftable`.  The
% Name of the class being described is specified (in the mangled name format).  The
% DemangledName is also exported using the Pharos Visual Studio name demangler now.
%
initialFact(rTTITypeDescriptor/4).

% rTTIClassHierarchyDescriptor(Address, Attributes, BaseClasses)
%
% There's an RTTI Class Hierarchy Descriptor at Address. The Attributes are reported to be two
% individual bits.  If bit zero is set there is multiple inheritance.  If bit one set, there is
% virtual inheritance.  BaseClasses is a list of RTTI Base Class Descriptor addresses.
%
initialFact(rTTIClassHierarchyDescriptor/3).

% rTTIBaseClassDescriptor(Address, TypeDescriptorAddress, NumBases, WhereM, WhereP, WhereV,
%                         Attributes, ClassHierarchyDescriptor)
%
% There's an RTTI Base Class Descriptor at Address. The type of the base class is described by
% the RTTI Type Descriptor at TypeDescriptorAddress.  WhereM, WhereP and WhereV describe the
% location of the base class relative to the derived class.  WhereM is the member displacement,
% WhereP is the vtable displacement, WhereV is the displacement inside the vtable.  The class
% hierarchy descriptor parameter is an undocumented extension that appears to describe this
% particular base class' hierarchy.
%
initialFact(rTTIBaseClassDescriptor/8).

% thisPtrAllocation(Insn, Function, ThisPtr, Type, Size).
%
% Instruction Insn in Function allocates Size bytes of memory of Type and assigns it to the
% specified ThisPtr. Type is one of: "type_Heap", "type_Unknown", "type_Stack", "type_Global",
% or "type_Param".  It's likely that only "type_Heap" is exported as a Prolog fact currently.
% This fact uses an approximate detection of new() methods wih many of the same caveats as the
% delete() detection, but is in general much more accurate.
initialFact(thisPtrAllocation/5).

% methodMemberAccess(Insn, Method, Offset, Size).
%
% Instruction Insn in Method accesses the current Size bytes of memory at Offset in the current
% this-pointer.
%
initialFact(methodMemberAccess/4).

% possibleVirtualFunctionCall(Insn, Function, ThisPtr, VTableOffset, VFuncOffset).
%
% Instruction Insn in Function makes a call that structurally resembles a virtual function
% call.  VTableOffset is the offset in the object where the virtual function table is located,
% and VFuncOffset is the offset into the virtual function table (provided that call is in fact
% a virtual function call).
%
initialFact(possibleVirtualFunctionCall/5).

% possibleVFTableWrite(Insn, Function, ThisPtr, Offset, ExpandedThisPtr, VFTable).
%
% Instruction Insn in Function writes a possible virtual function table pointer (VFTable) at
% Offset into the object represented by ThisPtr for the Method.
%
% The ExpandedThisPtr is a thisptr hash that has a corresponding thisPtrDefinition fact.
%
initialFact(possibleVFTableWrite/6).

% possibleVBTableWrite(Insn, Function, ThisPtr, Offset, ExpandedThisPtr, VBTable).
%
% Instruction Insn in Function writes a possible virtual base table pointer (VBTable) at Offset
% into the object represent by ThisPtr for the Method.
%
% The ExpandedThisPtr is a thisptr hash that has a corresponding thisPtrDefinition fact.
%
initialFact(possibleVBTableWrite/6).

% initialMemory(Address, Value).
%
% The Address contains the Value in the program's initialized memory.  Typically, the value is
% an entry in a possible virtual function table or a possible virtual base table.
%
initialFact(initialMemory/2).

% thisPtrOffset(ThisPtr1, Offset, ThisPtr2).
%
% When Offset is added to ThisPtr1, it yields ThisPtr2.  Typically this means that ThisPtr2 is
% a pointer to an embedded object of base class at the given offset within ThisPtr1.  ThisPtr1
% and ThisPtr2 are represented by the their symbolic value hashes.
%
initialFact(thisPtrOffset/3).

% thisPtrDefinition(ThisPtr, ThisPtrExpression, DefinerOrNull, Func).
%
% This is intended to be a generalization of thisPtrOffset.
% The main part of this fact is ThisPtrExpression, which allows reasoning of relative thisptr
% relationships beyond simply a constant offset.  This is important for virtual inheritance,
% which may cause thisptrs to be accessed via a vbtable lookup.
initialFact(thisPtrDefinition/4).

% symbolGlobalObject(Address, ClassName, VariableName).
%
% There's a global object at Address of type ClassName with the name VariableName.  This fact
% is currently unused because it's unclear how the ClassName/Address can be connected to other
% facts, and we're not currently reporting global object instances.
%
initialFact(symbolGlobalObject/3).

% symbolClass(Address, MangledName, ClassName, MethodName).
%
% The method at the Address has the MangledName.  It is known to be on the class represented by
% ClassName, and be named MethodName (both demangled).  This information comes from symbols
% such as imports by name, but might also come from embedded debugging information in other
% architectures and file formats.  The names are demangled names because of the requirement to
% separate MethodName from ClassName.
%
initialFact(symbolClass/4).

% symbolProperty(Address, property).
%
% The method at the Address is known to have the stated property.  Property would be one of
% 'constructor', 'realDestructor', 'deletingDestructor', or 'virtual'.
%
initialFact(symbolProperty/2).

% thunk(Thunk, Function).
%
% The instruction at Thunk is an unconditional jump to Function.
%
initialFact(thunk/2).

% callingConvention(Function, Convention).
%
% The Function can be the calling Convention.
%
initialFact(callingConvention/2).

% funcParameter(Function, Position, SVHash).
%
% The Function takes as a parameter in Position the symbolic value represented by SVHash.  The
% Position will be a number representing the stack delta for stack parameters, or the name of
% the register for register parameters.
%
initialFact(funcParameter/3).

% funcReturn(Function, Position, SVHash).
%
% The Function returns the symbolic value represented by SVHash in Position.  Position is
% always a register name, and is typically 'eax'.
%
initialFact(funcReturn/3).

% callParameter(Instruction, Function, Position, SVHash).
%
% The call Instruction in Function passes the symbolic value SVHash in Position. The Position
% will be a number representing the stack delta for stack parameters, or the name of the
% register for register parameters.
%
initialFact(callParameter/4).

% callReturn(Instruction, Function, Position, SVHash).
%
% The call Instruction in Function returns the symbolic value represented by SVHash in
% Position.  Position is always a register name, and is typically 'eax'.
%
initialFact(callReturn/4).

% callTarget(Instruction, Function, Target).
%
% The call Instruction in Function calls to the Target address.
%
initialFact(callTarget/3).

% Declare all initial facts as dynamic since they're loaded from files.
initfacts :-
    forall(initialFact(X), dynamic(X)).

:- initialization(initfacts).

% ============================================================================================
% Load (and validate) files containing OOAnalyzer initial facts.
% ============================================================================================

isInitialFact(X) :-
    functor(X, Name, Arity),
    initialFact(Name/Arity).

loadInitialFacts(File) :-
    loadPredicates(File, isInitialFact).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
