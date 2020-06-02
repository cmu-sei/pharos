% Copyright 2020 Carnegie Mellon University.

% ============================================================================================
% Declare the dynamic predicates that constitute our results.
% ============================================================================================

% This file defines the "results" or the outputs from the OOAnalyzer Prolog reasoning
% component.  Since the results are more likely to be consumed by other tools or humans, we've
% tried to defined them more clearly than the initial facts or dynamic facts.

% Unfortunately, the format has also undergone numerous revisions over the years.  The original
% design goal was to export the results in a format that was absolutely minimal, not including
% any information beyond what was importantly concluded by the Prolog component.  We explicitly
% did not export any data that duplicated by the initial facts (e.g. the contents of memory for
% the virtual function tables), or data that could be easily obtained from the program image.
% As more analysis logic has migrated into the Prolog component, and the Prolog code has
% increasingly stood on it's own, this design goal has largely been abandoned, leaving the
% results in messy state. :-(

% finalFileInfo(FileMD5, Filename).
%
% Documents which executable file was analyzed, reporting the FileMD5 and Filename.  This
% information is used in part to pair JSON outputs with inpute executables.
%
result(finalFileInfo/2).

% finalClass(ClassID, VFTable, MinSize, MaxSize, RealDestructor, MethodList)
%
% This result defines the existance of a class.  It is intended to be the first query to
% Prolog, which could drive all other required queries.  The ClassID field is a unique
% identifier for a class.
%
% VFTable is the address of the primary virtual function table associated with this class.
% This is the table that contains the derived class' newly declared virtual methods, and
% typically contains the method of the class' primary parent as well.  It is typically the
% table at offset zero in the object.  The VFTable will have the value zero if no VFTable was
% associated with the class.  In the case of multiple inheritance, additional tables may be
% associated with this class through the inheritance result described below.
%
% Minsize and MaxSize both decribe the most likely size of the class.  The use of two fields is
% historical, and one of the fields should be removed.
%
% The RealDestructor field is the address of the real destructor associated with the class if
% one was identified, and zero otherwise.
%
% The MethodList field contains all methods associated with the class regardless of their
% confidence levels or status as constructors, destructors, etc.  This list should include only
% those methods actually implemented on the class.  Thus all methods in the list should
% reference the same class name in their symbols.  Listing methods in this way is partially a
% convenience and optimization for importing class definitions into C++, since it allows the
% association with the class to be made simply and early in the import.
%
result(finalClass/6).

% finalVFTable(VFTable, CertainSize, LikelySize, RTTIAddress, RTTIName)
%
% The virtual function table at the address specified by VFTable is associated with the RTTI
% object locator at address RTTIAddress.  If there is no object locator, this value will be
% zero.
%
% The CertainSize and LikelySize both describe the most likely size of the virtual function
% table.  The use of two fields is historical, and one of the fields should be removed.
%
% The RTTIName field extracts the mangled name of the class from the TypeDescriptor implied by
% the RTTIAddress.  If there was no RTTI data for this VFTable, the RTTIAddress will be zero
% and the RTTIName will be ''.  The RTTIAddress is effectively always VFTAble less the size of
% a pointer, and was included for convenience.
%
result(finalVFTable/5).

% finalVFTableEntry(VFTable, Offset, Method)
%
% The virtual function table at address VFTable has an entry at Offset that refers to Method.
%
result(finalVFTableEntry/3).

% finalVBTable(VBTable, Class, Size, Offset)
%
% The virtual base table at address VBTable is associated with class identified in the Class
% field.  The next field specifies the size of of the table.  The Offset field is the offset in
% the class where the virtual base table pointer is written.
%
result(finalVBTable/4).

% finalVBTableEntry(VBTable, Offset, Value)
%
% The virtual base table at the address VBTable has an entry at Offset with value Value.  The
% value is an object offset. This result predicate was added so that the answer from Prolog was
% "complete".
%
result(finalVBTableEntry/3).

% finalResolvedVirtualCall(Insn, VFTable, Target)
%
% The call at Insn can be resolved to the Target through the virtual function table at VFTable.
% Most of the information describing a virtual function call is already avilable in C++ once
% you know the address of the call instruction.  This result communicates just the required
% information for simplicity and clarity.  Since minimal reporting is no longer a design goal,
% this result should probably be expanded to include VFTable offset, and possibly other
% details.
%
result(finalResolvedVirtualCall/3).

% finalInheritance(DerivedClassID, BaseClassID, ObjectOffset, VFTable, Virtual)
%
% In the Derived class at the specified offset is an object instance of the type specified by
% Base.  If the base class is not the first base class (non-zero offset) and the base class has
% a virtual function table, the VFTable field will contain the derived class instance of that
% virtual function table.
%
% The Virtual field is supposed to be true if the inheritance relationship is virtual and false
% if it is not, but is currently always false.
%
% In general, our understanding of how to report multiple and virtual inheritance is evolving.
% The latest output does NOT report virtual ancestors as direct bases of the derived class.  We
% should probably report those as a separate result?
%
result(finalInheritance/5).

% finalEmbeddedObject(OuterClass, Offset, EmbeddedClass, likely)
%
% In the OuterClass (which is a class identifier) at the specified offset is an object instance
% of the type specified by EmbeddedClass.  EmbeddedClass is also a class identifier.  The
% embedded object is not believed to be a base class (via an inheritance relationship), for
% that relationship see finalInheritance().
%
% The ordering of the parameters should perhaps be changed to match the facts. The 'likely'
% parameter is garbage and should be removed.
%
result(finalEmbeddedObject/4).

% finalMember(Class, Offset, Sizes, certain)
%
% The finalMember() result documents the existence of the definition of a member on a specific
% class.  This fact is intended to only report the members defined on the class from a C++
% source code perspective.
%
% The Class is specified with a class identifier.  Offset is the positive offset into the
% specified class (and not it's base or embedded classes).  Sizes is a list of all the
% different sizes through which the member has been accessed anywhere in the program.
%
% Embedded object and inherited bases are not listed again as finalMembers.  Instead they are
% list in the finalEmbeddedObject and finalInheritance results.
%
% The final field is garbage and should be removed.
%
result(finalMember/4).

% finalMemberAccess(Class, Offset, Size, EvidenceList)
%
% The member at Offset in Class was accessed using the given Size by the list of evidence
% instructions provided. The list of evidence instructions only contains instructions from the
% methods assigned to the class.  Other accesses of base class members will appear in the
% accesses for their respective classes.
%
% Note that that presentation does not present knowledge about the class and subclass
% relationships particularly clearly.  For those observations refer to finalMember() instead.
%
result(finalMemberAccess/4).

% finalMethodProperty(Method, constructor, certain)
%
% This result marks that a Method is a constructor.
% The 'certain' field is garbage and should be removed.
%
% finalMethodProperty(Method, deletingDestructor, certain)
%
% This result marks that a method is a deleting destructor.
% The 'certain' field is garbage and should be removed.
%
% finalMethodProperty(Method, realDestructor, certain)
%
% This result marks that a method is a real destructor.
% The 'certain' field is garbage and should be removed.
%
% This is duplicative of the field in the finalClass result but it was more convenient to have
% it reported consistently with otehr properties for debugging.  In the future, we may remove
% the corresponding field from the finalClass result.
%
% finalMethodProperty(Method, virtual, certain)
%
% This result marks that a method is declared virtual.
% The 'certain' field is garbage and should be removed.
%
result(finalMethodProperty/3).

% finalThunk(From, To)
%
% There's a thunk From one address To another.  This final fact is currently needed to connect
% finalVFTableEntry facts to the method list in finalClass.
%
result(finalThunk/2).

% finalDemangledName(Address, MangledName, ClassName, MethodName)
%
% There's a Class at the RTTITypeDescriptor Address, with the MangledName and demangled
% ClassName, or a method at the Address with the MangledName, the demangled ClassName and the
% demangled MethodName.  These results were exported to provide access to the demangled names
% provided by the Pharos Visual Studio demangler in Prolog, or in IDA/Ghidra when the Pharos
% results were better.
%
result(finalDemangledName/4).

% Declare all results as dynamic since they're sometimes loaded from files when postprocessing
% the results for ground truth validation of JSON generation in Prolog.  As with initial facts,
% not all results will contain instances of every results predicate.
initResults :-
    forall(result(X), dynamic(X)).

:- initialization(initResults).

% ============================================================================================
% Load (and validate) files containing OOAnalyzer results.
% ============================================================================================

isResult(X) :-
    functor(X, Name, Arity),
    result(Name/Arity).

loadResults(File) :-
    loadPredicates(File, isResult).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
