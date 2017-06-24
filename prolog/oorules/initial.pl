% Copyright 2017 Carnegie Mellon University.
% ============================================================================================
% Forward reasoning from given facts.
% ============================================================================================

:- import maplist/2 from swi.

% --------------------------------------------------------------------------------------------
% Important instructions are the ones that we actually care about knowing the ordering for.
:- table importantInsn/1 as opaque.

importantInsn(Insn) :-
    thisPtrUsage(Insn, _Func, _Thisptr, _PriorMethod).

importantInsn(Insn) :-
    possibleVFTableWrite(Insn, _Method, _Offset, _VFTable).

importantInsn(Insn) :-
    insnCallsDelete(Insn).

importantInsn(Insn) :-
    validFuncOffset(Insn, _Function, _Method, _Offset).

% --------------------------------------------------------------------------------------------
% This rule is also expressed as preceeds() facts asserted by the fact exporter.  It's tabled
% because the control flow call order in the executable is independent of all other facts.
% There's some kind of a Prolog problem where I can't just build on the existing preceeds
% facts. :-(
:- table canpreceedHelper/2 as opaque.

canpreceedHelper(I1, I2) :-
    preceeds(I1, I2).

% If I1 preceeds IM, and IM preceeds I2, then I1 preceeds I2.
canpreceedHelper(I1, I2) :-
    preceeds(I1, IM),
    iso_dif(I1, IM),
    canpreceedHelper(IM, I2),
    iso_dif(I2, IM),
    iso_dif(I1, I2).

% --------------------------------------------------------------------------------------------
% This rule, along wuth importantInsn was added to establish which canpreeed(X,Y) facts were
% actually relevant, and which were only used as an intermediate step to computing the relevant
% ones.   A canpreceed relationship is "relevant" if both instructions are "important".
:- table canpreceed/2 as opaque.

canpreceed(I1, I2) :-
    canpreceedHelper(I1, I2),
    importantInsn(I1),
    importantInsn(I2).

% --------------------------------------------------------------------------------------------
:- table initialNOTConstructor/1 as opaque.

% The method is certain to NOT be a constructor, because some other method in a sequence of
% methods on an object instance can be called before this method.  This is a much stronger rule
% resulting a level of certainty not provided by the likelyConstructor rule.  However, because
% we generally want to test for something being a constructor and not vice-versa, it isn't as
% useful.
initialNOTConstructor(Method) :-
    % Two methods are invoked on a single this-pointer object instance.
    thisPtrUsage(I1, Fc, Thisptr, PriorMethod),
    thisPtrUsage(I2, Fc, Thisptr, Method),
    % This clause prevents a method from excluding itself from being NOT a constructor.  It's a
    % pretty nasty hack to correct a defect in Lite/oo and Lite/poly that's probably really
    % caused by a complex issue involving functions that do not return and the true control
    % flow edges.
    iso_dif(PriorMethod, Method),
    % If I1 can be called before I2, then the method cannot be a constructor.
    canpreceed(I1, I2),
    % The instructions must be different.
    iso_dif(I1, I2).
    %debug('Method '), debug(Method), debug(' is not a constructor because '),
    %debug(I1), debug(' preceeds '), debugln(I2).

% --------------------------------------------------------------------------------------------
:- table initialNOTRealDestructor/1 as opaque.

% Method is certain to NOT be a destructor, because some other method in a sequence of methods
% on an object instance can be called after it.  The same reasoning make us certain that we're
% not a deleting destructor either, but that's handled in a different rule.
initialNOTRealDestructor(Method) :-
    % Two methods are invoked on a single this-pointer object instance.
    thisPtrUsage(I2, Fc, Thisptr, Method),
    thisPtrUsage(I1, Fc, Thisptr, _PriorMethod),
    % The instructions must be different.
    iso_dif(I1, I2),
    % If I2 can be called before I1, then the method cannot be a real destructor.
    canpreceed(I2, I1).


% --------------------------------------------------------------------------------------------
:- table initialNOTDeletingDestructor/1 as opaque.

% Cory's a little unsure about this one because we're still learning about deleting
% destructors, but I think it's correct.  The same reasoning also results in us being certain
% that the method is not a real destructor either, but that's handled in a different rule.
initialNOTDeletingDestructor(Method) :-
    % Two methods are invoked on a single this-pointer object instance.
    thisPtrUsage(I1, Fc, Thisptr, _PriorMethod),
    thisPtrUsage(I2, Fc, Thisptr, Method),
    % If I2 can be called before I1, then the method cannot be a deleting destructor.
    canpreceed(I2, I1),
    % The instructions must be different.
    iso_dif(I1, I2).

% --------------------------------------------------------------------------------------------
% These are guessable quality addresses of methods (e.g. don't include
:- table likelyMethod/1 as opaque.

% PAPER: likelyMethod-1 (moved to likelyMethod)
likelyMethod(Method) :-
    thisPtrUsage(_Insn, _Func, _ThisPtr, Method).
% PAPER: likelyMethod-2 (moved to likelyMethod)
% Perhaps the ones mentioned in funcOffset() are always certain to methods?
likelyMethod(Method) :-
    validFuncOffset(_Insn, _Caller, Method, _Offset).
% PAPER: likelyMethod-3 (moved to likelyMethod)
likelyMethod(Method) :-
    validMethodMemberAccess(_Insn, Method, _Offset, _Size).
% Actually, these are certain to be methods, but they're also likely and possible
likelyMethod(Method) :-
    symbolClass(Method, _ClassName, _MethodName).
% Actually, these are certain to be methods, but they're also likely and possible
likelyMethod(Method) :-
    symbolProperty(Method, _Property).

likelyMethodSet(Set) :-
    setof(Method, likelyMethod(Method), Set).

% --------------------------------------------------------------------------------------------
:- table possibleMethod/1 as opaque.

possibleMethod(Method) :-
    likelyMethod(Method).
% PAPER: possibleMethod-4
possibleMethod(Method) :-
    possibleVFTableEntry(_VFtable, _Offset, Method).

possibleMethodSet(Set) :-
    setof(Method, possibleMethod(Method), Set).

% Start out by allocating each object as its own class
makeAllObjects :-
    possibleMethodSet(PS),
    maplist(make, PS).

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
    possibleVFTableEntry(VFTable, _Offset2, _Address),
    rTTICompleteObjectLocator(Pointer, _RTTIAddress, _TypeDesc, _ClassDesc, _O1, _O2),
    VFTable is Pointer + 4.

% PAPER: Write-PossibleVFTable
possibleVFTable(VFTable) :-
    possibleVFTableEntry(VFTable, _Offset2, _Address),
    possibleVFTableWrite(_Insn, _Method, _Offset1, VFTable).

possibleVFTableSet(Set) :-
    setof(VFTable, possibleVFTable(VFTable), Set).

% --------------------------------------------------------------------------------------------
% The rules in this section are still very experimental and are only used in a limited way in
% reasoning.  Hopefully we'll make better use of this data as our confidence in it's
% correctness improves.  For now the goal can best be described as "if everything lines up
% perfectly, let's take that as a strong indicator that we know what's happening".  This is
% very similar to how our logic for virtual function calls works...
:- table validVBTableEntry/3 as opaque.

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

% Build on the knowledge from the previous virtual base table entry to determine whether the
% next entry is valid.  We're checking whether the expected calls to the constructors are
% present, and they might not be if the constructors were inlined or the offsets into the
% object were computed incorrectly by Objdigger.
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

:- table validVBTableWrite/4 as opaque.

% Our only rule right now is that the virtual base table must have at least two valid entries.
validVBTableWrite(Insn, Method, Offset, VBTable) :-
    possibleVBTableWrite(Insn, Method, Offset, VBTable),
    validVBTableEntry(VBTable, Entry1, _Value1),
    validVBTableEntry(VBTable, Entry2, _Value2),
    iso_dif(Entry1, Entry2).

% --------------------------------------------------------------------------------------------
% The method is certain to be an isolated method, which is a method that we have no known calls
% to.  As a consequence we're unable to place it in a calling context, and therefore shouldn't
% make assertions about whether it's a constructor or destructor.  A closely related phenomenon
% is when the only reference to a method is in a call chain of length (it could be both a
% constructor and a destructor).  It's unclear what should be done in this second case.

:- table certainIsolatedMethod/1 as opaque.
certainIsolatedMethod(Method) :-
    not(thisPtrUsage(_Insn, _Function, _ThisPtr, Method)).

% --------------------------------------------------------------------------------------------
% Perhaps these should be filtered before exporting to Prolog...  Or maybe it's better to leave
% the filtering in Prolog because we could propogate "non-objectness" more effectively.  For
% right now the primary goal is to prevent the bad records from being used in reasoning.
:- table validFuncOffset/4 as opaque.

validFuncOffset(Insn, Function, Method, Offset) :-
    funcOffset(Insn, Function, Method, Offset),
    Offset < 0x100000.

:- table validMethodMemberAccess/4 as opaque.

validMethodMemberAccess(Insn, Method, Offset, Size) :-
    methodMemberAccess(Insn, Method, Offset, Size),
    Offset < 0x100000.

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
