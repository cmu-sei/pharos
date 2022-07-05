% Copyright 2017-2020 Carnegie Mellon University.
% ============================================================================================
% Forward reasoning from given facts.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% Convert some new style facts to old style facts.

:- table possibleVFTableWrite/5 as opaque.
:- table possibleVBTableWrite/5 as opaque.

% For now, ignore the ExpandedThisPtr argument.
possibleVFTableWrite(Insn, Function, ThisPtr, Offset, VFTable) :-
  possibleVFTableWrite(Insn, Function, ThisPtr, Offset, _ExpandedThisPtr, VFTable).
possibleVBTableWrite(Insn, Function, ThisPtr, Offset, VBTable) :-
  possibleVBTableWrite(Insn, Function, ThisPtr, Offset, _ExpandedThisPtr, VBTable).

:- table possibleConstructor/1 as opaque.

possibleConstructor(M) :-
    (returnsSelf(M), noCallsBefore(M));
    symbolProperty(M, constructor).

:- table possibleDestructor/1 as opaque.

possibleDestructor(M) :-
    noCallsAfter(M);
    symbolProperty(M, realDestructor);
    symbolProperty(M, deletingDestructor).


% --------------------------------------------------------------------------------------------

% Hack togetther compatability with the old system.
:- table possibleVFTableEntry/3 as opaque.
:- table possibleVBTableEntry/3 as opaque.

possibleVFTableEntry(VFTable, 0, Entry) :-
    possibleVFTableWrite(_Insn, _Func, _ThisPtr, _ObjectOffset, VFTable),
    initialMemory(VFTable, Entry).

possibleVFTableEntry(VFTable, 0, Entry) :-
    rTTICompleteObjectLocator(Pointer, _Address, _TDAddress, _CHAddress, _Offset, _CDOffset),
    VFTable is Pointer + 4,
    initialMemory(VFTable, Entry).

possibleVFTableEntry(VFTable, NewOffset, Entry) :-
    possibleVFTableEntry(VFTable, Offset, _),
    NewOffset is Offset + 4,
    Address is VFTable + NewOffset,
    not(possibleVFTableWrite(_Insn, _Func, _ThisPtr, _Offset, Address)),
    initialMemory(Address, Entry),
    % Now that initialMemory facts also include virtual base table entries, we need some
    % additional validation to prevent adding base table entries as methods.
    Entry > 0x1000.

possibleVBTableEntry(VBTable, Offset, Value) :-
    possibleVBTableWrite(_Insn, _Func, _ThisPtr, _ObjectOffset, VBTable),
    % This is messed up!  Hardcoding zero in the rule does not work, but this does?
    Offset is 0,
    initialMemory(VBTable, Value).

possibleVBTableEntry(VBTable, NewOffset, Value) :-
    possibleVBTableEntry(VBTable, Offset, _),
    NewOffset is Offset + 4,
    Address is VBTable + NewOffset,
    not(possibleVBTableWrite(_Insn, _Func, _ThisPtr, _Offset, Address)),
    initialMemory(Address, Value).

% --------------------------------------------------------------------------------------------
:- table possibleMethod/1 as opaque.

% There's at least some evidence that that address is a function.  Primarily used for
% separating plausible methods from arbitrary addresses during guessing.
possibleMethod(Address) :-
    callingConvention(Address, _CallingConvention);
    thunk(Address, _Target1);
    noCallsAfter(Address);
    noCallsBefore(Address);
    returnsSelf(Address);
    purecall(Address);
    callTarget(_Insn, Address, _Target2).

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
    possibleVBTableWrite(_Insn1, DerivedConstructor, _ThisPtr, _BaseOffset, VBTable),
    possibleConstructor(DerivedConstructor),
    % And the method invoked at the computed offset will be the base constructor.
    %ObjectOffset is BaseOffset + Offset,
    %logtraceln('Object Offset for ~Q entry ~Q is ~Q', [VBTable, Entry, ObjectOffset]),

    % Intentionally NOT a validMethodCallAtOffset because we're speculating fairly widely here.
    % A validMethodCallAtOffset might be more correct, but that would require that we already
    % know that BaseConstructor is a validMethod, and we'd like to conclude that from guessing
    % about the VBTable that is in turn dependent on this fact.  Some more though is needed
    % here...
    %methodCallAtOffset(_Insn2, DerivedConstructor, BaseConstructor, ObjectOffset),
    %possibleConstructor(BaseConstructor),
    true.

validVBTableEntry(VBTable, 0, Offset) :-
    % There's a possible entry...
    possibleVBTableEntry(VBTable, 0, Offset),
    % Find out where the table is installed into the object (BaseOffset).
    possibleVBTableWrite(_Insn1, Constructor, _ThisPtr, BaseOffset, VBTable),
    % If BaseOffset is non zero...
    iso_dif(BaseOffset, 0),
    % Then the constructor should be a possible consuctor...
    possibleConstructor(Constructor),
    % And we should also have a possible VFTable write at that relative offset into the object.
    % This rule is still a little flawed because of upstream problems computing the object
    % offsets correctly in the case where complex virtual base tables exist.  Fortunately, I
    % think that the default presumption (that the BaseOffset is zero) is the most common case.
    FunctionOffset is Offset + BaseOffset,
    possibleVFTableWrite(_Insn2, Constructor, _ThisPtr2, FunctionOffset, _VFTable).

% If the first entry in the virtual base table is zero, that means that we have no virtual
% function table, and so there's less to validate.
validVBTableEntry(VBTable, 0, 0) :-
    possibleVBTableEntry(VBTable, 0, Offset),
    possibleVBTableWrite(_Insn1, Constructor, _ThisPtr, Offset, VBTable),
    possibleConstructor(Constructor).

:- table validVBTableWrite/5 as opaque.

% Our only rule right now is that the virtual base table must have at least two valid entries.
validVBTableWrite(Insn, Func, ThisPtr, Offset, VBTable) :-
    possibleVBTableWrite(Insn, Func, ThisPtr, Offset, VBTable),
    Offset >= 0,
    validVBTableEntry(VBTable, Entry1, _Value1),
    validVBTableEntry(VBTable, Entry2, _Value2),
    iso_dif(Entry1, Entry2),
    % Debugging
    %logtrace('~Q.', validVBTableWrite(Insn, Func, ThisPtr, Offset, VBTable)),
    true.

% --------------------------------------------------------------------------------------------
% Perhaps these should be filtered before exporting to Prolog...  Or maybe it's better to leave
% the filtering in Prolog because we could propogate "non-objectness" more effectively.  For
% right now the primary goal is to prevent the bad records from being used in reasoning.
:- table validMethodCallAtOffset/4 as incremental.

validMethodCallAtOffset(Insn, Caller, Callee, Offset) :-
    methodCallAtOffset(Insn, Caller, Callee, Offset),
    factMethod(Callee),
    Offset < 0x100000.

% Replaces the old-style fact named funcOffset.
:- table methodCallAtOffset/4 as opaque.

methodCallAtOffset(Insn, Caller, Callee, Offset) :-
    funcParameter(Caller, ecx, CallerThisPtr),
    callParameter(Insn, Caller, ecx, CalleeThisPtr),
    thisPtrOffset(CallerThisPtr, Offset, CalleeThisPtr),
    callTarget(Insn, Caller, Thunk),
    dethunk(Thunk, Callee),
    %loginfoln('~Q.', methodCallAtOffset(Insn, Caller, Callee, Offset)),
    true.

methodCallAtOffset(Insn, Caller, Callee, 0) :-
    funcParameter(Caller, ecx, ThisPtr),
    callParameter(Insn, Caller, ecx, ThisPtr),
    callTarget(Insn, Caller, Thunk),
    dethunk(Thunk, Callee),
    %loginfoln('~Q.', methodCallAtOffset(Insn, Caller, Callee, 0)),
    true.

% Replaces an old-style fact of the same name.
:- table thisPtrUsage/4 as opaque.

thisPtrUsage(Insn, Function, ThisPtr, Method) :-
    callParameter(Insn, Function, ecx, ThisPtr),
    callTarget(Insn, Function, Thunk),
    dethunk(Thunk, Method),
    %loginfoln('~Q.', thisPtrUsage(Insn, Function, ThisPtr, Method)),
    true.

% Here's an example of how we can use the "invalid" offsets to our advantage.  Defining an
% invalid access as an offset greater than 100,000 allows us to subsequently observe that
% "valid" offsets on the same this-pointer are not in fact true object pointers.  See 0x407544
% (Leadup3) in 2010/Lite/ooex0 for an example.  Now all we have to do is figure out how to
% handle really large objects correctly. :-)
:- table invalidMethodMemberAccess/1 as opaque.

invalidMethodMemberAccess(Method) :-
    methodMemberAccess(_Insn, Method, Offset, _Size),
    Offset >= 0x100000.

:- table validMethodMemberAccess/4 as incremental.

validMethodMemberAccess(Insn, Method, Offset, Size) :-
    methodMemberAccess(Insn, Method, Offset, Size),
    factMethod(Method),
    not(invalidMethodMemberAccess(Method)).

% ============================================================================================
% This code is an attempt to handle functions optimized by link-time code generation to use the
% same address for methods that are actually on different classes.  When this occurs it is a
% fairly significant problem for the overall OOAnalyzer strategy for assigning methods to
% classes.  To attempt to combat the problem, we start with two observations: First, that the
% optimization is most common for "trivial" functions with very few instructions like "xor
% eax,eax; ret".  Second, that the problem seems to cause the most trouble when methods are
% assigned to classes via VFTable reasoning rules that are otherwise sound.  These two rules
% will not "fix" the problem but they should significantly reduce the frequency at which it
% causes consistency failures.
% ============================================================================================
:- table trivial/1 as opaque.

% A trivial function is defined roughly as one that has no facts to speak of.  Having all four
% calling conventions typically means that the function was trivial enough that we were unable
% to differentiate between the calling conventions.  The rest of the not() clauses are further
% checks to ensure that the method does more or less nothing.
trivial(Address):-
    % Having all of these calling conventions limits the behavior of the function a fair bit.
    % Having the cdecl calling convention is also permitted, but _not_ required.
    callingConvention(Address, '__stdcall'),
    callingConvention(Address, '__thiscall'),
    callingConvention(Address, '__fastcall'),
    callingConvention(Address, '__vectorcall'),

    % Can't require EAX return code because some trivial functions "just return", not even
    % setting EAX.

    % And a bunch of other things should NOT be true...

    % No reading of parameters is allowed!  First because it's very common.
    not(callParameter(_, Address, _, _)),
    not(funcParameter(_, Address, _)),
    % No calling other functions, unless they're also trivial.  Very common.
    not((callTarget(_, Address, Called), not(trivial(Called)))),
    % No reading from the object.  Anotehr very effective blocker.
    not(methodMemberAccess(_, Address, _, _)),

    % Trivial methods are certainly not valid for constructor like methods, and possibly not
    % for destructor like as well.
    not(noCallsBefore(Address)),
    not(noCallsAfter(Address)),
    % No thunking to other functions.
    not(thunk(Address, _)),
    % No allocating memory.
    not(thisPtrAllocation(_, Address, _, _, _)),

    % Implied by no callTargets?
    not(methodCallAtOffset(_, Address, _, _)),
    not(insnCallsDelete(_, Address, _)),
    % Implied by no methodMemberAccess?
    not(uninitializedReads(Address)),
    not(returnsSelf(Address)),
    not(thisPtrUsage(_, Address, _, _)),
    not(possibleVFTableWrite(_, Address, _, _, _)),
    not(possibleVBTableWrite(_, Address, _, _, _)),
    logtraceln('Reasoning ~Q.', factTrivial(Address)).

% For the second part of our approach, we're going to look for trivial functions that _might_
% be in more than one VFTable.  This opaquely tabled predicate is still very broad.  For
% example, it doesn't even prove that the function appears in more than one table because both
% entry addresses might be in the same table.  This rule might eventually need to be broadened
% further to include reuse situations that don't involve VFTables in reused functions are a
% problem in other rules as well.  Also see a more restricted version of this rule in rules.pl
% named reasonReusedImplementation that greatly strengthens the requirements.
:- table possiblyReused/1 as opaque.

possiblyReused(Function):-
    trivial(Function),
    initialMemory(EntryAddress1, Function),
    initialMemory(EntryAddress2, Function),
    iso_dif(EntryAddress1, EntryAddress2),
    logtraceln('Reasoning ~Q.', factPossiblyReused(Function)).

% ============================================================================================
% Thunk handling...
% ============================================================================================

% What function does a given thunk eventually end at?
:- table eventualThunk/2 as opaque.
eventualThunk(Thunk, Func) :-
    thunk(Thunk, Func),
    not(thunk(Func, _)).

eventualThunk(Thunk, Func) :-
    eventualThunk(Middle, Func),
    thunk(Thunk, Middle).

:- table dethunk/2 as opaque.
dethunk(Thunk, Result) :-
    dethunk_nontabled(Thunk, Result).

dethunk_nontabled(Thunk, Result) :-
    var(Thunk),
    ground(Result),
    throw_with_backtrace(error(uninstantiation_error(Result), dethunk/2)).

dethunk_nontabled(Thunk, Result) :-
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
    var(Method),
    !,
    possibleVFTableEntry(_VFTable1, _VFTableOffset, Entry),
    % It's ok to call the tabled version because Method is unbound here
    dethunk(Entry, Method).

possiblyVirtual(Method) :-
    ground(Method),
    !,
    possibleVFTableEntry(_VFTable1, _VFTableOffset, Entry),
    % Call the non tabled version to avoid huge table blow-ups. Another solution would be to
    % allow calls to dethunk to be properly handled when only the second argument is bound.
    dethunk_nontabled(Entry, Method).

% ============================================================================================
% Intentionally dynamic rules.
% ============================================================================================

% Make factNOTMergeClasses symmetric, without storing it as such.  The goal here is to reduce
% memory consumption, potentially at a small expense of run time.  This is also useful just for
% ensuring that the symmetry is applied consistently when writing rules.
dynFactNOTMergeClasses(Class1, Class2) :-
    % If the first one is true, don't try the second ordering.
    (factNOTMergeClasses(Class1, Class2) -> true;
     % If the first one isn't true, try the second one.
     factNOTMergeClasses(Class2, Class1)).

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
possibleVFTableOverwrite(Insn1, Insn2, Func, ObjectOffset, VFTable1, VFTable2) :-
    possibleVFTableWrite(Insn1, Func, ThisPtr, ObjectOffset, VFTable1),
    possibleVFTableWrite(Insn2, Func, ThisPtr, ObjectOffset, VFTable2),
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
    possibleVFTableWrite(_WriteInsn, Constructor, _ThisPtr2, ObjectOffset, VFTable).

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
    possibleVFTableWrite(_WriteInsn, Constructor, _ThisPtr2, ObjectOffset, VFTable).

% --------------------------------------------------------------------------------------------

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
