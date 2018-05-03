% Copyright 2017 Carnegie Mellon University.
% ============================================================================================
% Forward reasoning from given facts.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% Convert some new style facts to old style facts.

:- table possibleConstructor/1 as opaque.

possibleConstructor(M) :-
    returnsSelf(M),
    noCallsBefore(M).

:- table possibleDestructor/1 as opaque.

possibleDestructor(M) :-
    noCallsAfter(M).

% --------------------------------------------------------------------------------------------

% Hack togetther compatability with the old system.
:- table possibleVFTableEntry/3 as opaque.
:- table possibleVBTableEntry/3 as opaque.

possibleVFTableEntry(VFTable, 0, Entry) :-
    possibleVFTableWrite(_Insn, _Method, _ObjectOffset, VFTable),
    initialMemory(VFTable, Entry).

possibleVFTableEntry(VFTable, 0, Entry) :-
    rTTICompleteObjectLocator(Pointer, _Address, _TDAddress, _CHAddress, _Offset, _CDOffset),
    VFTable is Pointer + 4,
    initialMemory(VFTable, Entry).

possibleVFTableEntry(VFTable, NewOffset, Entry) :-
    possibleVFTableEntry(VFTable, Offset, _),
    NewOffset is Offset + 4,
    Address is VFTable + NewOffset,
    not(possibleVFTableWrite(_Insn, _Method, _Offset, Address)),
    initialMemory(Address, Entry),
    % Now that initialMemory facts also include virtual base table entries, we need some
    % additional validation to prevent adding base table entries as methods.
    Entry > 0x1000.

possibleVBTableEntry(VBTable, Offset, Value) :-
    possibleVBTableWrite(_Insn, _Method, _ObjectOffset, VBTable),
    % This is messed up!  Hardcoding zero in the rule does not work, but this does?
    Offset is 0,
    initialMemory(VBTable, Value).

possibleVBTableEntry(VBTable, NewOffset, Value) :-
    possibleVBTableEntry(VBTable, Offset, _),
    NewOffset is Offset + 4,
    Address is VBTable + NewOffset,
    not(possibleVBTableWrite(_Insn, _Method, _Offset, Address)),
    initialMemory(Address, Value).

% --------------------------------------------------------------------------------------------
:- table possibleVFTable/1 as opaque.

% VFTable writes are sometimes currently missed for a variety of strange reasons.  See 0x40247e
% in 2010/Lite/oo for an example involving a 'vbase destructor' for basic_ostream.  We're going
% to use two definitions of possibleVFTable so that an entry and _either_ a vftable write or an
% RTTI data structure is sufficient to be "possible".  We'll still fail to associate the
% VFTable with a class unless we've correctly identified the write, but one problem at a time.

% These are more confidently vftables than the rule below because having the RTTI Complete
% Object Locator data structures at the correct address is a pretty amazing coincidence.  By
% ordering this rule first do we implicitly control which order the guess are made in as well?
% PAPER: rTTI-PossibleVFTable
possibleVFTable(VFTable) :-
    possibleVFTableEntry(VFTable, _Offset2, _Entry),
    rTTICompleteObjectLocator(Pointer, _RTTIAddress, _TypeDesc, _ClassDesc, _O1, _O2),
    VFTable is Pointer + 4.

% PAPER: Write-PossibleVFTable
possibleVFTable(VFTable) :-
    possibleVFTableEntry(VFTable, _Offset2, _Entry),
    possibleVFTableWrite(_Insn, _Method, _Offset1, VFTable).

possibleVFTableSet(Set) :-
    setof(VFTable, possibleVFTable(VFTable), Set).

% --------------------------------------------------------------------------------------------
% The rules in this section are still very experimental and are only used in a limited way in
% reasoning.  Hopefully we'll make better use of this data as our confidence in it's
% correctness improves.  For now the goal can best be described as "if everything lines up
% perfectly, let's take that as a strong indicator that we know what's happening".  This is
% very similar to how our logic for virtual function calls works...

% Something strange is going on with these rules and opaque vs. incremental tabling.  These
% rules cause crashes if they're used in rules.pl, with errors about incremenatal tabling and
% specialization.
:- table validVBTableEntry/3 as opaque.

% Build on the knowledge from the previous virtual base table entry to determine whether the
% next entry is valid.  We're checking whether the expected calls to the constructors are
% present, and they might not be if the constructors were inlined or the offsets into the
% object were computed incorrectly by OOAnalyzer.
validVBTableEntry(VBTable, Entry, Offset) :-
    % There's a possible entry...
    possibleVBTableEntry(VBTable, Entry, Offset),
    % And the entry that came before it is already valid...
    PreviousEntry is Entry - 4,
    validVBTableEntry(VBTable, PreviousEntry, _PreviousOffset),
    % The constructor that the table was installed into will be the derived constructor.
    possibleVBTableWrite(_Insn1, DerivedConstructor, BaseOffset, VBTable),
    possibleConstructor(DerivedConstructor),
    % And the method invoked at the computed offset will be the base constructor.
    ObjectOffset is BaseOffset + Offset,
    %debug('Object Offset for '), debug(VBTable), debug(' entry '),
    %debug(Entry), debug(' is '), debugln(ObjectOffset),
    funcOffset(_Insn2, DerivedConstructor, BaseConstructor, ObjectOffset),
    possibleConstructor(BaseConstructor).

validVBTableEntry(VBTable, 0, Offset) :-
    % There's a possible entry...
    possibleVBTableEntry(VBTable, 0, Offset),
    % Find out where the table is installed into the object (BaseOffset).
    possibleVBTableWrite(_Insn1, Constructor, BaseOffset, VBTable),
    % If BaseOffset is non zero...
    iso_dif(BaseOffset, 0),
    % Then the constructor should be a possible consuctor...
    possibleConstructor(Constructor),
    % And we should also have a possible VFTable write at that relative offset into the object.
    % This rule is still a little flawed because of upstream problems computing the object
    % offsets correctly in the case where complex virtual base tables exist.  Fortunately, I
    % think that the default presumption (that the BaseOffset is zero) is the most common case.
    FunctionOffset is Offset + BaseOffset,
    possibleVFTableWrite(_Insn2, Constructor, FunctionOffset, _VFTable).

% If the first entry in the virtual base table is zero, that means that we have no virtual
% function table, and so there's less to validate.
validVBTableEntry(VBTable, 0, 0) :-
    possibleVBTableEntry(VBTable, 0, Offset),
    possibleVBTableWrite(_Insn1, Constructor, Offset, VBTable),
    possibleConstructor(Constructor).

:- table validVBTableWrite/4 as opaque.

% Our only rule right now is that the virtual base table must have at least two valid entries.
validVBTableWrite(Insn, Method, Offset, VBTable) :-
    possibleVBTableWrite(Insn, Method, Offset, VBTable),
    validVBTableEntry(VBTable, Entry1, _Value1),
    validVBTableEntry(VBTable, Entry2, _Value2),
    iso_dif(Entry1, Entry2).

% --------------------------------------------------------------------------------------------
% Perhaps these should be filtered before exporting to Prolog...  Or maybe it's better to leave
% the filtering in Prolog because we could propogate "non-objectness" more effectively.  For
% right now the primary goal is to prevent the bad records from being used in reasoning.
:- table validFuncOffset/4 as opaque.

validFuncOffset(Insn, Function, Method, Offset) :-
    funcOffset(Insn, Function, Method, Offset),
    Offset < 0x100000.

% Here's an example of how we can use the "invalid" offsets to our advantage.  Defining an
% invalid access as an offset greater than 100,000 allows us to subsequently observe that
% "valid" offsets on the same this-pointer are not in fact true object pointers.  See 0x407544
% (Leadup3) in 2010/Lite/ooex0 for an example.  Now all we have to do is figure out how to
% handle really large objects correctly. :-)
:- table invalidMethodMemberAccess/1 as opaque.

invalidMethodMemberAccess(Method) :-
    methodMemberAccess(_Insn, Method, Offset, _Size),
    Offset >= 0x100000.

:- table validMethodMemberAccess/4 as opaque.

validMethodMemberAccess(Insn, Method, Offset, Size) :-
    methodMemberAccess(Insn, Method, Offset, Size),
    not(invalidMethodMemberAccess(Method)).

% ============================================================================================
% Thunk handling...
% ============================================================================================

% What function does a given thunk eventually end at?
:- table eventualThunk/2 as opaque.
eventualThunk(Thunk, Func) :-
    thunk(Thunk, Func),
    not(thunk(Func, _)).

eventualThunk(Thunk, Func) :-
    thunk(Thunk, Middle),
    eventualThunk(Middle, Func).

:- table eventualThunk/2 as opaque.
dethunk(Thunk, Result) :-
    eventualThunk(Thunk, Target) -> Result = Target; Result = Thunk.

% Is this thunk the only thunk that eventually executes this method?
:- table uniqueThunk/2 as opaque.
uniqueThunk(Thunk, Method) :-
    eventualThunk(Thunk, Method),
    not((eventualThunk(Other, Method), Other \= Thunk)).

% Is this thunk the only thunk that eventually executes this method?
:- table conflictedThunk/3 as opaque.
conflictedThunk(Thunk1, Thunk2, Method) :-
    eventualThunk(Thunk1, Method),
    eventualThunk(Thunk2, Method),
    Thunk1 \= Thunk2.

:- table possiblyVirtual/1 as opaque.
possiblyVirtual(Method) :-
    possibleVFTableEntry(_VFTable1, _VFTableOffset, Entry),
    dethunk(Entry, Method).

% ============================================================================================
% Rules for setting up preconditions for good guesses...
% ============================================================================================

% --------------------------------------------------------------------------------------------
:- table possibleConstructorForThisPtr/2 as opaque.
% Method is likely a constructor, and it's definitely associated with the this-pointer.
possibleConstructorForThisPtr(Method, ThisPtr) :-
    % If the method is a likely constructor.
    possibleConstructor(Method),
    % And there's a this-pointer usage that calls the constructor.
    thisPtrUsage(_Insn, _Function, ThisPtr, Method).

:- table possibleVFTableOverwrite/6 as opaque.
% Two possible VFTables are written to the same offset of the same object in the same method.
% VFTable1 which was written by Insn1 is overwritten by VFTable2 in Insn2.
possibleVFTableOverwrite(Insn1, Insn2, Method, ObjectOffset, VFTable1, VFTable2) :-
    possibleVFTableWrite(Insn1, Method, ObjectOffset, VFTable1),
    possibleVFTableWrite(Insn2, Method, ObjectOffset, VFTable2),
    % This rule should really use can_preceed(Insn1, Insn2) but the VFTable write instruction
    % addresses are not currently included in the preceeds facts.  In the meantime we're going
    % to totally hack this up and use a simple comparison.
    Insn1 < Insn2.

% --------------------------------------------------------------------------------------------
:- table likelyVirtualFunctionCall/5 as opaque.
% Insn is likely to be a real virtual function call.  This rule does not validate offsets into
% the virtual function table or actually resolve the call, since that brings in issues of
% vftable size, disassembly correctness etc.
likelyVirtualFunctionCall(Insn, Constructor, ObjectOffset, VFTable, VFTableOffset) :-
    % We're only interested in the matching possible virtual function calls.
    possibleVirtualFunctionCall(Insn, _Function, ThisPtr, ObjectOffset, VFTableOffset),
    % Do we think we know which constructor constructed the this-pointer?
    possibleConstructorForThisPtr(Constructor, ThisPtr),
    % Did that constructor write a vftable into the appropriate object offset?
    possibleVFTableWrite(_WriteInsn, Constructor, ObjectOffset, VFTable).

% Insn is likely to be a real virtual function call.  This version of the rule is tailored to
% handle multiple inheritance situations where the object pointer (ThisPtr) is not actually the
% object that the ObjectOffset is relative to.  This rule is very non-intuitive right now.
% Basically the idea is to recast the ambiguously defined possibleVirtualFunctionCall as a
% correct pairing of ThisPtr and VTableOffset (always zero), by confirming that there's a
% thisPtrOffset with the same offset.  The VFTable write at the expected offset will only
% be found in the derived constructor, not the base class constructor.
likelyVirtualFunctionCall(Insn, Constructor, 0, VFTable, VFTableOffset) :-
    % We're only interested in the matching possible virtual function calls.
    possibleVirtualFunctionCall(Insn, _Function, ThisPtr, ObjectOffset, VFTableOffset),
    % What's our root of our real derived object pointer?
    thisPtrOffset(RealDerivedPtr, ObjectOffset, ThisPtr),
    % Do we think we know which constructor constructed the real derived object pointer?
    possibleConstructorForThisPtr(Constructor, RealDerivedPtr),
    % Did that constructor write a vftable into the appropriate object offset?
    possibleVFTableWrite(_WriteInsn, Constructor, ObjectOffset, VFTable).

% --------------------------------------------------------------------------------------------

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
