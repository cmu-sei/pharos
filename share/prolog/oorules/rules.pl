% Copyright 2017 Carnegie Mellon University.

% --------------------------------------------------------------------------------------------
% The method is certain to be an object-oriented method.
:- table reasonMethod/1 as incremental.

:- table reasonMethod_A/1 as incremental.
:- table reasonMethod_B/1 as incremental.
:- table reasonMethod_C/1 as incremental.
:- table reasonMethod_D/1 as incremental.
:- table reasonMethod_E/1 as incremental.
:- table reasonMethod_F/1 as incremental.
:- table reasonMethod_G/1 as incremental.
:- table reasonMethod_H/1 as incremental.
:- table reasonMethod_I/1 as incremental.
:- table reasonMethod_J/1 as incremental.
:- table reasonMethod_K/1 as incremental.
:- table reasonMethod_L/1 as incremental.
:- table reasonMethod_M/1 as incremental.
:- table reasonMethod_N/1 as incremental.
:- table reasonMethod_O/1 as incremental.
:- table reasonMethod_P/1 as incremental.

reasonMethod(Method) :-
    or([reasonMethod_A(Method),
        reasonMethod_B(Method),
        reasonMethod_C(Method),
        reasonMethod_D(Method),
        reasonMethod_E(Method),
        reasonMethod_F(Method),
        reasonMethod_G(Method),
        reasonMethod_H(Method),
        reasonMethod_I(Method),
        reasonMethod_J(Method),
        reasonMethod_K(Method),
        reasonMethod_L(Method),
        reasonMethod_M(Method),
        reasonMethod_N(Method)
%        reasonMethod_O(Method),
%        reasonMethod_P(Method)
      ]).

% Because we already know.
% PAPER: ??? This entire rule is new and still pretty experimental.
reasonMethod_A(Method) :-
    factMethod(Method).

% Because contructors are definitely methods.
reasonMethod_B(Method) :-
    factConstructor(Method).

% Because real destructors are definitely methods.
reasonMethod_C(Method) :-
    factRealDestructor(Method).

% Because deleting destructors are methods as far as Cory knows.
reasonMethod_D(Method) :-
    factDeletingDestructor(Method).

% Because a symbol told us so.
reasonMethod_E(Method) :-
    symbolClass(Method, _ClassName, _MethodName).

% Because a symbol property told us so.
reasonMethod_F(Method) :-
    symbolProperty(Method, _Property).

% Because proven entries in proven virtual function tables are methods.
% ED_PAPER_INTERESTING
reasonMethod_G(Method) :-
    factVFTableEntry(_VFTable, _Offset, Entry),
    dethunk(Entry, Method).

% Because we've already proven that the VFTable write was legitimate.
% Technically this is not sound, but it should have very low false positives.
reasonMethod_H(Method) :-
    factVFTableWrite(_Insn, Method, _Offset, _VFTable).

reasonMethod_I(Method) :-
    factVBTableWrite(_Insn, Method, _Offset, _VBTable).

% Because the calling convention proves it's on OO method.
% This is currently weak enough that we're guessing it instead.
% But it might be fixed now, so we should try it again...
%reasonMethod_I(Method) :-
%    thisCallMethod(Method, _ThisPtr, certain).

% Because it's called on a class that's known to be a class.
reasonMethod_J(Method) :-
    factClassCallsMethod(_Class, Method).

% Because the thisptr is known to be an object pointer.
reasonMethod_K(Method) :-
    thisPtrUsage(_Insn1, Func, ThisPtr, Method1),
    factMethod(Method1),
    thisPtrUsage(_Insn2, Func, ThisPtr, Method).

% Because the thisptr is known to be an object pointer.
reasonMethod_L(Method) :-
    factMethod(Caller),
    funcOffset(_Insn1, Caller, Method, 0).

% Because direct data flow from new() makes the function a method.
reasonMethod_M(Method) :-
    thisPtrAllocation(_Insn1, Func, ThisPtr, _Type, _Size),
    thisPtrUsage(_Insn2, Func, ThisPtr, Method).

% Because the thisptr is known to be an object pointer.
reasonMethod_N(Func) :-
    thisPtrUsage(_Insn1, Func, ThisPtr, Method),
    factMethod(Method),
    % We explicitly don't care about certainty here, even it contradicts this rule.
    thisCallMethod(Func, ThisPtr, _Certainty).

% First attempt at guessing that a cdecl method is really an OO cdecl method.
reasonMethod_O(Method) :-
    % There's a method that we know is an OO method.
    factMethod(Proven),
    % Obtain it's thisPtr... also in funcParameter(Proven, ecx, ThisPtr)?
    thisCallMethod(Proven, ThisPtr, _Convention),
    % The ThisPtr is passed to another method in a call
    callParameter(Insn, Proven, 0, ThisPtr),
    % That Method is us.
    callTarget(Insn, Proven, Target),
    dethunk(Target, Method),
    % And we're __cdecl.
    callingConvention(Method, '__cdecl').

% Know this-pointers passed from one method to another within a function.
reasonMethod_P(Method) :-
    % A ThisPtr is passed to a known method.
    callParameter(Insn1, Func, 0, ThisPtr),
    callTarget(Insn1, Func, Target1),
    dethunk(Target1, Proven),
    factMethod(Proven),
    % Then the same this-pointer is passed to another method.
    callParameter(Insn2, Func, 0, ThisPtr),
    callTarget(Insn2, Func, Target2),
    dethunk(Target2, Method),
    callingConvention(Method, '__cdecl').

reasonMethodSet(Set) :-
    setof(Method, reasonMethod(Method), Set).

% --------------------------------------------------------------------------------------------
% The method is certain to be a constructor.
:- table reasonConstructor/1 as incremental.

% Because it is already known to be a constructor.
% PAPER: Not relevant
reasonConstructor(Method) :-
    factConstructor(Method).

% Because it is known to be a constructor or destructor and we've eliminited the other
% possibilities.
% PAPER: Logic
reasonConstructor(Method) :-
    certainConstructorOrDestructor(Method),
    factNOTRealDestructor(Method),
    factNOTDeletingDestructor(Method).

% Because there are virtual base table writes, and that only happens in constructors (as far as
% we know currently).  Strictly speaking, this rule should really be based on factVBTableWrite,
% and we should guess that as we do virtual function calls (with very high confidence and very
% early), but this code is still so experimental that seems too heavy weight for right now.
% PAPER: VFTableWrite-ConstructorDestructor  (Cory notes that this PAPER name is poor!)
% ED_PAPER_INTERESTING
reasonConstructor(Method) :-
    factVBTableWrite(_Insn, Method, _Offset, _VBTable).

% Because a symbol says so!
reasonConstructor(Method) :-
    symbolProperty(Method, constructor).

% Because if we're certain about a derived constructor relationship then obviously both methods
% are constructors.  Duplicative?
%reasonConstructor(Method) :-
%    factDerivedClass(_DerivedConstructor, Method, _Offset).
%reasonConstructor(Method) :-
%    factDerivedClass(Method, _BaseConstructor, _Offset).

% Because we already know the direction of the Base/Derived class relationship.  This rule is
% complicated.  The idea is that knowing which class is the Base and which is the Derived tells
% us whether the Method is a Constructor or Destructor.  Ahh...  That's probably where this
% rule belongs.

% Because there's a VFTable overwrite and a known inheritance relationship.
%reasonConstructor(Method) :-
%    % VFTable1 is overwritten by VFTable2.
%    possibleVFTableOverwrite(_Insn1, _Insn2, Method, Offset, VFTable1, VFTable2),
%    factVFTable(VFTable1),
%    factVFTable(VFTable2),
%    %
%    find(Method, Class1),
%    possibleVFTableWrite(_Insn3, OtherMethod, Offset, VFTable2),
%    find(OtherMethod, Class2),
%    factDerivedClass(DerivedClass, BaseClass, Offset).

reasonConstructorSet(Set) :-
    setof(Method, reasonConstructor(Method), Set).

% --------------------------------------------------------------------------------------------
% The method is certain to NOT be a constructor.
:- table reasonNOTConstructor/1 as incremental.

:- table reasonNOTConstructor_A/1 as incremental.
:- table reasonNOTConstructor_B/1 as incremental.
:- table reasonNOTConstructor_C/1 as incremental.
:- table reasonNOTConstructor_D/1 as incremental.
:- table reasonNOTConstructor_E/1 as incremental.
:- table reasonNOTConstructor_F/1 as incremental.
:- table reasonNOTConstructor_G/1 as incremental.

reasonNOTConstructor(Method) :-
    or([reasonNOTConstructor_A(Method),
        reasonNOTConstructor_B(Method),
        reasonNOTConstructor_C(Method),
        reasonNOTConstructor_D(Method),
        reasonNOTConstructor_E(Method),
        reasonNOTConstructor_F(Method),
        reasonNOTConstructor_G(Method)
      ]).

% Because it is already known to NOT be a constructor.
% PAPER: NA
reasonNOTConstructor_A(Method) :-
    factNOTConstructor(Method).

% Because it is a real destructor.
% PAPER: Logic
reasonNOTConstructor_B(Method) :-
    factRealDestructor(Method),
    % Debugging
    %not(factNOTConstructor(Method)),
    %debug('reasonFactNOTConstructor_B('), debug(Method),debugln(').'),
    true.

% Because it is a deleting destructor.
% PAPER: Logic
reasonNOTConstructor_C(Method) :-
    factDeletingDestructor(Method),
    % Debugging
    %not(factNOTConstructor(Method)),
    %debug('reasonFactNOTConstructor_C('), debug(Method),debugln(').'),
    true.

% Because it is in a virtual function table and constructors can't be virtual.
% PAPER: VFTableEntry-NotConstructor
% ED_PAPER_INTERESTING
reasonNOTConstructor_D(Method) :-
    factVFTableEntry(_VFTable, _Offset, Entry),
    dethunk(Entry, Method),
    % Debugging
    %not(factNOTConstructor(Method)),
    %debug('reasonFactNOTConstructor_D('), debug(Method),debugln(').'),
    true.

% Because it is called after another method on an object instance pointer.
% PAPER: Order-NotConstructor
% ED_PAPER_INTERESTING
reasonNOTConstructor_E(Method) :-
    factMethod(Method),
    not(possibleConstructor(Method)),
    % Debugging
    %not(factNOTConstructor(Method)),
    %debug('reasonFactNOTConstructor_E('), debug(Method),debugln(').'),
    true.

% Because it is called by a non-constructor on the same object instance.
% PAPER: Call-NotConstructor
% ED_PAPER_INTERESTING
reasonNOTConstructor_F(Method) :-
    factNOTConstructor(OtherMethod),
    funcOffset(_Insn, OtherMethod, Method, _Offset),
    % Debugging
    %not(factNOTConstructor(Method)),
    %debug('reasonFactNOTConstructor_F('), debug(Method),debugln(').'),
    true.

% Because you can't be a constructor on a class that's already known to have a VFTable if you
% you don't have a VFTable.  This rule was added largely to reach the correct conclusions on
% methods like operator=.
% ED_PAPER_INTERESTING
reasonNOTConstructor_G(Method) :-
    % There's another method that calls this method on the same object pointer.
    funcOffset(_, Caller, Method, 0),
    % The caller is known to be a constructor or destructor.
    (factConstructor(Caller); factRealDestructor(Caller)),
    % The caller is already known to have a VFTable write.
    factVFTableWrite(_Insn1, Caller, 0, _VFTable1),
    % But this method doesn't have the required write.
    not(possibleVFTableWrite(_Insn2, Method, 0, _VFTable2)),
    %
    % Debugging
    not(factNOTConstructor(Method)),
    %debug('reasonFactNOTConstructor_G('),
    %debug(Caller),debug(', '),
    %debug(Method),debugln(').'),
    true.

reasonNOTConstructorSet(Set) :-
    setof(Method, reasonNOTConstructor(Method), Set).

% --------------------------------------------------------------------------------------------
% The method is certain to be a real destructor.
:- table reasonRealDestructor/1 as incremental.

% Because it is already known to be a real destructor.
% PAPER: NA
reasonRealDestructor(Method) :-
    factRealDestructor(Method).

% Because it is known to be a constructor or destructor and we've eliminited the other
% possibilities.
% PAPER: Logic
reasonRealDestructor(Method) :-
    certainConstructorOrDestructor(Method),
    factNOTConstructor(Method),
    factNOTDeletingDestructor(Method).

% Because a symbol says so!
reasonRealDestructor(Method) :-
    symbolProperty(Method, realDestructor).

% Because a symbol says so! (Bit of a hacky corner case).
% PAPER: ??? NEW!
% This should probably be a separate type of desstructor really.
reasonRealDestructor(Method) :-
    symbolClass(Method, _ClassName, '`vbase destructor''').

reasonRealDestructorSet(Set) :-
    setof(Method, reasonRealDestructor(Method), Set).

% --------------------------------------------------------------------------------------------
% The method is certain to NOT be a real destructor.
:- table reasonNOTRealDestructor/1 as incremental.

:- table reasonNOTRealDestructor_A/1 as incremental.
:- table reasonNOTRealDestructor_B/1 as incremental.
:- table reasonNOTRealDestructor_C/1 as incremental.
:- table reasonNOTRealDestructor_D/1 as incremental.
:- table reasonNOTRealDestructor_E/1 as incremental.
:- table reasonNOTRealDestructor_F/1 as incremental.
:- table reasonNOTRealDestructor_G/1 as incremental.

reasonNOTRealDestructor(Method) :-
    or([reasonNOTRealDestructor_A(Method),
        reasonNOTRealDestructor_B(Method),
        reasonNOTRealDestructor_C(Method),
        reasonNOTRealDestructor_D(Method),
        reasonNOTRealDestructor_E(Method),
        reasonNOTRealDestructor_F(Method),
        reasonNOTRealDestructor_G(Method)
      ]).

% Because it is already known to NOT be a real destructor.
% PAPER: NA
reasonNOTRealDestructor_A(Method) :-
    factNOTRealDestructor(Method).

% Because it is a constructor.
% PAPER: Logic
reasonNOTRealDestructor_B(Method) :-
    factConstructor(Method).

% Because it is a deleting destructor.
% PAPER: Logic
reasonNOTRealDestructor_C(Method) :-
    factDeletingDestructor(Method).

% Because it was called before another method on a this-pointer.
% PAPER: Order-NotDestructor
reasonNOTRealDestructor_D(Method) :-
    factMethod(Method),
    not(possibleDestructor(Method)).

% Because a class can have only one real destructor and we've already one for this class.
% PAPER: Sanity constraints for each class.  Currently: "Each class has one real destructor"
reasonNOTRealDestructor_E(Method) :-
    findall(Method, MethodSet),
    member(RealDestructor, MethodSet),
    factRealDestructor(RealDestructor),
    iso_dif(Method, RealDestructor).

% Because a method on a class cannot destruct itself (unless it's a deleting destructor).
reasonNOTRealDestructor_F(Method) :-
    factMethod(Method),
    find(Method, Class),
    find(Caller, Class),
    iso_dif(Method, Caller),
    funcOffset(_Insn, Caller, Method, 0),
    factNOTDeletingDestructor(Caller),
    % Debugging
    %debug('reasonNOTRealDestructor_F('),
    %debug(Method), debug(', '),
    %debug(Caller), debugln(').'),
    true.

% A correlary to reasonNOTConstructor_G (requiring VFTable writes if others have them).
% PAPER: ??? NEW!
reasonNOTRealDestructor_G(Method) :-
    % There's another method that calls this method on the same object pointer.
    funcOffset(_, Caller, Method, 0),
    % The caller is known to be a constructor or destructor.
    (factConstructor(Caller); factRealDestructor(Caller)),
    % The caller is already known to have a VFTable write.
    factVFTableWrite(_Insn1, Caller, 0, _VFTable1),
    % But this method doesn't have the required write.
    not(possibleVFTableWrite(_Insn2, Method, 0, _VFTable2)),
    % Debugging
    not(factNOTRealDestructor(Method)),
    debug('reasonFactNOTRealDestructor_G('),
    debug(Caller),debug(', '),
    debug(Method),debugln(').'),
    true.

reasonNOTRealDestructorSet(Set) :-
    setof(Method, reasonNOTRealDestructor(Method), Set).

% --------------------------------------------------------------------------------------------
% The method is certain to be a deleting destructor.
:- table reasonDeletingDestructor/1 as incremental.

% Because it is already known to be a deleting destructor.
% PAPER: NA
reasonDeletingDestructor(Method) :-
    factDeletingDestructor(Method).

% Because it is known to be a constructor or destructor and we've eliminited the other
% possibilities.  It appears that deleting destructors participate in the vftable write rule.
% PAPER: Logic
reasonDeletingDestructor(Method) :-
    certainConstructorOrDestructor(Method),
    factNOTConstructor(Method),
    factNOTRealDestructor(Method).

% Because a symbol says so!
reasonDeletingDestructor(Method) :-
    symbolProperty(Method, deletingDestructor).

% --------------------------------------------------------------------------------------------
% The method is certain to NOT be a deleting destructor.
:- table reasonNOTDeletingDestructor/1 as incremental.

:- table reasonNOTDeletingDestructor_A/1 as incremental.
:- table reasonNOTDeletingDestructor_B/1 as incremental.
:- table reasonNOTDeletingDestructor_C/1 as incremental.
:- table reasonNOTDeletingDestructor_D/1 as incremental.
:- table reasonNOTDeletingDestructor_E/1 as incremental.

reasonNOTDeletingDestructor(Method) :-
    or([reasonNOTDeletingDestructor_A(Method),
        reasonNOTDeletingDestructor_B(Method),
        reasonNOTDeletingDestructor_C(Method),
        reasonNOTDeletingDestructor_D(Method),
        reasonNOTDeletingDestructor_E(Method)
      ]).

% Because it is already known to NOT be a deleting destructor.
% PAPER: NA
reasonNOTDeletingDestructor_A(Method) :-
    factNOTDeletingDestructor(Method).

% Because it is a constructor.
% PAPER: Logic
reasonNOTDeletingDestructor_B(Method) :-
    factConstructor(Method).

% Because it is a real destructor.
% PAPER: Logic
reasonNOTDeletingDestructor_C(Method) :-
    factRealDestructor(Method).

% Because it was called before another method on a this-pointer.
% PAPER: Order-NotDestructor
reasonNOTDeletingDestructor_D(Method) :-
    factMethod(Method),
    not(possibleDestructor(Method)).

% Because a method on a class cannot _deallocate_ itself.
% PAPER: ??? NEW!
reasonNOTDeletingDestructor_E(Method) :-
    % This rule can be pretty broad, because I'm not aware of any circumstances where passing
    % your own this pointer to a deleting destructor is valid.
    factMethod(Method),
    factMethod(Caller),
    iso_dif(Method, Caller),
    funcOffset(_Insn, Caller, Method, 0),
    % Debugging
    %debug('reasonNOTDeletingDestructor_E('),
    %debug(Method), debug(', '),
    %debug(Caller), debugln(').'),
    true.

reasonNOTDeletingDestructorSet(Set) :-
    setof(Method, reasonNOTDeletingDestructor(Method), Set).

% --------------------------------------------------------------------------------------------
% Method is certain to be either a constructor or a destructor.  The reasoning here is that any
% method that is writing VFTable values into an object must be either a constructor or
% destructor, since as mentioned in the reasonVFTableWrite rule, no user code has access to the
% virtual function table address.  There was some confusion about inlined constructors for
% other objects (e.g. local stack objects or heap allocated objects), but they won't be writing
% into the current method's object, so there wouldn't have been a possibleVFTableWrite() fact
% in the first place.  Jeff Gennari and Cory Cohen are both fairly confident of this rule, but
% it's hard to prove the negative (that the compiler doesn't use the VFTable under any other
% condition).  Cory subsequently established (via the badalloc deleting destructor in
% Lite/ooex0) that deleting destructors can install the VFTable for the current object
% (possibly due to inlining?) so this conclusion does NOT say which type of destructor it might
% be.  This rule is here and named in the old style mostly so that this gigantic comment can be
% here rather than in the middle of a bunch of other rules.
% PAPER: VFTableWrite-ConstructorDestructor
% ED_PAPER_INTERESTING
certainConstructorOrDestructor(Method) :-
    factVFTableWrite(_Insn, Method, _Offset, _VFTable).

certainConstructorOrDestructor(Method) :-
    factVBTableWrite(_Insn, Method, _Offset, _VBTable).

certainConstructorOrDestructorSet(Set) :-
    setof(Method, certainConstructorOrDestructor(Method), Set).

% ============================================================================================
% Rules for virtual function tables, virtual function calls, etc.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% The address VFTable is certain to be a virtual function table.
% This rule does not say which class the VFTable is associated with.
:- table reasonVFTable/1 as incremental.

% Because it is already known to be a VFTable.
% PAPER: NA
reasonVFTable(VFTable) :-
    factVFTable(VFTable).

% Because the RTTI information says so.
% PAPER: ??? NEW?
reasonVFTable(VFTable) :-
    rTTIEnabled,
    rTTIValid,
    rTTITDA2VFTable(_TDA, VFTable).
    %debug('reasonVFTable1('), debug(VFTable), debugln(').').

% Because the VFTable was used in a virtual function call.
% PAPER: VirtualCall-VFTable
reasonVFTable(VFTable) :-
    factVirtualFunctionCall(_Insn, _Method, _ObjectOffset, VFTable, _VFTableOffset).

% Implement: Derived/Base class relationships validate the virtual function tables at the same
% offsets in oteher class?  Is it possible to conclude the derived class relationship without
% the being certain of the VFTables (if there are VFTables)?

% --------------------------------------------------------------------------------------------
% The Insn in Method writing to Offset in the current object is known to be writing a certain
% virtual function table pointer.
:- table reasonVFTableWrite/4 as incremental.

% Because it is already known to be a valid VFTable write.
% PAPER: NA
reasonVFTableWrite(Insn, Method, Offset, VFTable) :-
    factVFTableWrite(Insn, Method, Offset, VFTable).

% Because if we know that the address is a VFTable, and it's apparently being written into an
% object, there's almost no chance that it's not a legitimate VFTable write.  The source code
% doesn't legitimately have access to the VFTables addresses, so no instruction other than a
% constructor/destructor vftable write should mention the address.
% PAPER: VFTable-VFTableWrite
reasonVFTableWrite(Insn, Method, Offset, VFTable) :-
    % The VFTtable itself must already be certain.
    factVFTable(VFTable),
    % And there's a VFTable write that references that VFTable.
    possibleVFTableWrite(Insn, Method, Offset, VFTable).

% It should be possible to use the base table entry at offset zero (the one that the virtual
% base class uses to find it's virtual funtion table) to prove the existence of the virtual
% function table write.  I haven't actually implemented this rule yet, because it's a little
% unclear under exactly what circumstances it would be beneficial.  Perhaps it would be better
% implemented as a validation rule.

% --------------------------------------------------------------------------------------------
% Rules for overwritten VFTables when more than one VFTable is written to the same object
% offset.  Unlike possibleVFTableOverwrite, which is based on the literal overwriting of
% VFTable pointers based on instruction ordering, this rule is conceptual ordered from the
% perspective of the constructor (which is reversed in the destructors).

:- table reasonVFTableOverwrite/3 as incremental.

% Because VFTable1 is overwritten by VFTable2, and the method is a constructor, so we're
% overwriting tables in the "normal" direction, meaning that the order of the instructions
% matches the semantic meaning of the overwrite.
reasonVFTableOverwrite(VFTable1, VFTable2, Offset) :-
    possibleVFTableOverwrite(_Insn1, _Insn2, Method, Offset, VFTable1, VFTable2),
    factVFTable(VFTable1),
    factVFTable(VFTable2),
    factConstructor(Method).

% Because VFTable1 is overwritten by VFTable2, and the method is a NOT a constructor, so we're
% overwriting tables in the "opposite" direction, meaning that the order of the instructions is
% opposite of the semantics meaning of the overwrite.  Note that the order of VFTable2 and
% VFTable1 has been reversed from the previous rule.
reasonVFTableOverwrite(VFTable2, VFTable1, Offset) :-
    possibleVFTableOverwrite(_Insn1, _Insn2, Method, Offset, VFTable1, VFTable2),
    factVFTable(VFTable1),
    factVFTable(VFTable2),

    % You'd think we could say (factDeletingDestructor or factRealDestructor) but it turns out
    % that excludes cases where we're still unclear on which type of destructor it is.  I've
    % included certainConstructorOrDestructor(Method) but that rule is currently just test for
    % a VFTable write, so it's a bit duplicative here.  In the end, factNOTConstructor() may be
    % sufficient even if it's a little confusing.
    certainConstructorOrDestructor(Method),
    factNOTConstructor(Method).

% --------------------------------------------------------------------------------------------
% A new approach to associating VFTables with Classes?  This is not a fact concluding rule
% right now, but it might be in the future.   But it has no "NOT" variation...
:- table reasonPrimaryVFTableForClass/2 as incremental.

% PAPER: PrimaryVFTable
reasonPrimaryVFTableForClass(VFTable, Class) :-
    % Primary VFTables are always at offset zero?
    factVFTableWrite(_Insn, Method, 0, VFTable),
    not(factVFTableOverwrite(_OtherVFTable, VFTable, 0)),
    find(Method, Class).

% --------------------------------------------------------------------------------------------
% The offset in the VFTable is a valid VFTable entry.
:- table reasonVFTableEntry/3 as incremental.

% Because it is already known to be a valid VFTable entry.
% PAPER: NA
reasonVFTableEntry(VFTable, Offset, Entry) :-
    factVFTableEntry(VFTable, Offset, Entry).

% Because the first entry in the VFTable is always valid (they are no zero size VFTables).
% PAPER: VFTable-VFTableEntry
reasonVFTableEntry(VFTable, 0, Entry) :-
    factVFTable(VFTable),
    possibleVFTableEntry(VFTable, 0, Entry).

% Because there is a larger valid VFTable entry in the same VFTable.
% PAPER: Larger-VFTableEntry
reasonVFTableEntry(VFTable, Offset, Entry) :-
    factVFTableEntry(VFTable, ExistingOffset, _OtherEntry),
    possibleVFTableEntry(VFTable, Offset, Entry),
    Offset < ExistingOffset.

% Because the entry was used in a virtual function call.
% PAPER: VirtualCall-VFTableEntry
reasonVFTableEntry(VFTable, Offset, Entry) :-
    factVirtualFunctionCall(_Insn, _Method, _ObjectOffset, VFTable, Offset),
    possibleVFTableEntry(VFTable, Offset, Entry).

% Implement: Because our parent class already has a larger VFTable?

% Implement: The second real DTOR in a table ends the table?

% --------------------------------------------------------------------------------------------
% It is certain that the possible VFTableEntry is NOT in fact a valid entry in that table.
:- table reasonNOTVFTableEntry/3 as incremental.

:- table reasonNOTVFTableEntry_A/3 as incremental.
:- table reasonNOTVFTableEntry_B/3 as incremental.
:- table reasonNOTVFTableEntry_C/3 as incremental.
:- table reasonNOTVFTableEntry_D/3 as incremental.
:- table reasonNOTVFTableEntry_E/3 as incremental.

reasonNOTVFTableEntry(VFTable, Offset, Entry) :-
    or([reasonNOTVFTableEntry_A(VFTable, Offset, Entry),
        reasonNOTVFTableEntry_B(VFTable, Offset, Entry),
        reasonNOTVFTableEntry_C(VFTable, Offset, Entry),
        reasonNOTVFTableEntry_D(VFTable, Offset, Entry),
        reasonNOTVFTableEntry_E(VFTable, Offset, Entry)
      ]).

% Because it has already been proved not to be.
% PAPER: NA
reasonNOTVFTableEntry_A(VFTable, Offset, Entry) :-
    factNOTVFTableEntry(VFTable, Offset, Entry).

% Because the same address is known to already be the start of a different table, and
% virtual function tables can not overlap.
% PAPER: Overlap-NotVFTableEntry
reasonNOTVFTableEntry_B(VFTableAddress, Offset, Entry) :-
    factVFTable(VFTableAddress),
    possibleVFTableEntry(VFTableAddress, Offset, Entry),
    Offset \= 0,
    ComputedAddress is VFTableAddress + Offset,
    factVFTable(ComputedAddress).

% Because the first invalid entry in a table invalidates all subsequent possible entries
% (virtual function tables are contiguous).
% PAPER: Larger-NotVFTableEntry
reasonNOTVFTableEntry_C(VFTable, Offset, Entry) :-
    factVFTable(VFTable),
    possibleVFTableEntry(VFTable, Offset, Entry),
    Offset \= 0,
    ComputedOffset is Offset - 4,
    possibleVFTableEntry(VFTable, ComputedOffset, OtherEntry),
    factNOTVFTableEntry(VFTable, ComputedOffset, OtherEntry).

% Because the address is already used for the RTTI data structure of a confirmed VFTable.
% PAPER: rTTI-NotVFTableEntry
reasonNOTVFTableEntry_D(VFTable, Offset, Entry) :-
    factVFTable(VFTable),
    possibleVFTableEntry(VFTable, Offset, Entry),
    ComputedAddress is VFTable + Offset,
    rTTICompleteObjectLocator(ComputedAddress, _Address, _TDAddress, _CHDAddress, _O1, _O2).

% Because the method it points to is certain to be a constructor.  This rule is suspicious.
% Are we really sure that the method is a constructor?  Why does it appear to be in the virtual
% function table?  I suppose this rule is required to maintain consistency in the solution.
% PAPER: TBD: Add to the consistency rules
reasonNOTVFTableEntry_E(VFTable, Offset, Entry) :-
    possibleVFTableEntry(VFTable, Offset, Entry),
    dethunk(Entry, Method),
    factConstructor(Method),
    % Debugging
    %debug('reasonNOTVFTableEntry_E('),
    %debug(VFTable), debug(', '),
    %debug(Offset), debug(', '),
    %debug(Entry), debugln(').'),
    true.

% Implement: Because our derived VFTable already has a smaller table?

reasonNOTVFTableEntrySet(VFTable, Set) :-
    factVFTable(VFTable),
    setof(Offset, Entry^reasonNOTVFTableEntry(VFTable, Offset, Entry), Set).

% --------------------------------------------------------------------------------------------
:- table reasonVFTableSizeGTE/2 as incremental.

% The size includes the length of the last pointer, and pointers are incorrectly assumed to by
% 4 byte (32-bit) function pointers.  So a table with one entry will have size 4, with two
% entries size 8, and so on.

reasonVFTableSizeGTE(VFTable, Size) :-
    factVFTableSizeGTE(VFTable, Size).

% PAPER: VSize-1
reasonVFTableSizeGTE(VFTable, Size) :-
    % Ed says: By prefixing E^ we tell setof NOT to case on E.
    % If we leave E as _, it will case on different values of E!
    setof(S, E^factVFTableEntry(VFTable, S, E), Set),
    list_max(Set, LastEntry),
    Size is LastEntry + 4,
    % Debugging
    %not((factVFTableSizeGTE(VFTable, ExistingSize), ExistingSize <= Size)),
    %debug('reasonVFTableSizeGTE_A('),
    %debug(VFTable), debug(', '),
    %debug(Size), debugln(').'),
    true.

% A derived class' vftable must be at least as large as its base class'.
% PAPER: VSize-2
% ED_PAPER_INTERESTING
reasonVFTableSizeGTE(VFTable, Size) :-
    factVFTableSizeGTE(BaseVFTable, Size),
    reasonPrimaryVFTableForClass(BaseVFTable, BaseClass),
    %factVFTableWrite(_Insn1, Base, 0, BaseVFTable),
    %not(factVFTableOverwrite(BaseVFTable, _VFTable1, _Offset1)),
    factDerivedClass(DerivedClass, BaseClass, _ObjectOffset),
    reasonPrimaryVFTableForClass(VFTable, DerivedClass),
    %factVFTableWrite(_Insn2, DerivedClass, 0, VFTable),
    %not(factVFTableOverwrite(VFTable, _VFTable2, _Offset2)),
    % Debugging
    %not((factVFTableSizeGTE(VFTable, ExistingSize), ExistingSize <= Size)),
    %debug('reasonVFTableSizeGTE_B('),
    %debug(DerivedClass), debug(', '),
    %debug(BaseClass), debug(', '),
    %debug(VFTable), debug(', '),
    %debug(Size), debugln(').'),
    true.

% --------------------------------------------------------------------------------------------
:- table reasonVFTableSizeLTE/2 as incremental.

% The size includes the length of the last pointer, and pointers are incorrectly assumed to by
% 4 byte (32-bit) function pointers.  So a table with one entry will have size 4, with two
% entries size 8, and so on.

reasonVFTableSizeLTE(VFTable, Size) :-
    factVFTableSizeLTE(VFTable, Size).

% PAPER: VSize-0
reasonVFTableSizeLTE(VFTable, Size) :-
    % Ed says: By prefixing M^ we tell setof NOT to case on M.
    % If we leave M as _, it will case on different values of M!
    setof(S, M^factNOTVFTableEntry(VFTable, S, M), Set),
    list_max(Set, LastEntry),
    Size is LastEntry + 4,
    % Debugging
    %not((factVFTableSizeLTE(VFTable, ExistingSize), ExistingSize >= Size)),
    %debug('reasonVFTableSizeLTE_A('),
    %debug(VFTable), debug(', '),
    %debug(Size), debugln(').'),
    true.

% A base class' vftable must be no larger than its smallest derived class'.
% PAPER: VSize-4
reasonVFTableSizeLTE(VFTable, Size) :-
    factVFTableSizeLTE(DerivedVFTable, Size),
    reasonPrimaryVFTableForClass(DerivedVFTable, DerivedClass),
    %factVFTableWrite(_Insn1, DerivedClass, 0, DerivedVFTable),
    %not(factVFTableOverwrite(DerivedVFTable, _VFTable1, _Offset1)),
    factDerivedClass(DerivedClass, BaseClass, _ObjectOffset),
    reasonPrimaryVFTableForClass(VFTable, BaseClass),
    %factVFTableWrite(_Insn2, BaseClass, 0, VFTable),
    %not(factVFTableOverwrite(VFTable, _VFTable2, _Offset2)),
    % Debugging
    %not((factVFTableSizeLTE(VFTable, ExistingSize), ExistingSize >= Size)),
    %debug('reasonVFTableSizeLTE_B('),
    %debug(DerivedClass), debug(', '),
    %debug(BaseClass), debug(', '),
    %debug(VFTable), debug(', '),
    %debug(Size), debugln(').'),
    true.


% --------------------------------------------------------------------------------------------
:- table reasonVirtualFunctionCall/5 as incremental.

reasonVirtualFunctionCall(Insn, Method, ObjectOffset, VFTable, VFTableOffset) :-
    factVirtualFunctionCall(Insn, Method, ObjectOffset, VFTable, VFTableOffset).

% Because we're able to reolve the call.
% PAPER: XXX
% The call proves the entry in this rule.  It relies on the VFTableWrite which can be proven
% from the VFTable, which can come from RTTI for example.
reasonVirtualFunctionCall(Insn, Method, ObjectOffset, VFTable, VFTableOffset) :-
    % There's a possible virtual function call.
    possibleVirtualFunctionCall(Insn, Function, ThisPtr, ObjectOffset, VFTableOffset),
    % There's a this-pointer usage that calls a method.
    thisPtrUsage(_CallInsn, Function, ThisPtr, Method),
    % We know what VFTable was written into that object offset.
    factVFTableWrite(_WriteInsn, Method, ObjectOffset, VFTable),
    % Debugging
    %debug('reasonVirtualFunctionCall('),
    %debug(Insn), debug(', '),
    %debug(Method), debug(', '),
    %debug(ObjectOffset), debug(', '),
    %debug(VFTable), debug(', '),
    %debug(VFTableOffset), debugln(').'),
    true.

% ============================================================================================
% Rules for virtual BASE tables.
% ============================================================================================

% --------------------------------------------------------------------------------------------
:- table reasonVBTable/1 as incremental.

% Because it is already known to be a VFTable.
% PAPER: NA
reasonVBTable(VBTable) :-
    factVBTable(VBTable).

% Because an entry was validated first, for example from RTTI.
% PAPER: ??? NEW!
reasonVBTable(VBTable) :-
    factVBTableEntry(VBTable, Offset, _Method),
    Offset >= 4,
    %debug('reasonVBTable_A('), debug(VBTable), debugln(').'),
    true.

% --------------------------------------------------------------------------------------------
:- table reasonVBTableWrite/4 as incremental.

% Because it is already known to be a valid VBTable write.
% PAPER: NA
reasonVBTableWrite(Insn, Method, Offset, VBTable) :-
    factVBTableWrite(Insn, Method, Offset, VBTable).

% PAPER: ??? NEW!
reasonVBTableWrite(Insn, Method, Offset, VBTable) :-
    % The VBTtable itself must already be certain.
    factVBTable(VBTable),
    % And there's a VBTable write that references that VBTable.
    possibleVBTableWrite(Insn, Method, Offset, VBTable),
    %debug('reasonVBTableWrite_A('),
    %debug(Insn), debug(', '),
    %debug(Method), debug(', '),
    %debug(Offset), debug(', '),
    %debug(VBTable), debugln(').'),
    true.

% --------------------------------------------------------------------------------------------
:- table reasonVBTableEntry/3 as incremental.

% Because it is already known to be a valid VBTable entry.
% PAPER: NA
reasonVBTableEntry(VBTable, Offset, Value) :-
    factVBTableEntry(VBTable, Offset, Value).

% Because the first two(?) entries in the VBTable are always valid.
% PAPER: ??? NEW!
reasonVBTableEntry(VBTable, 4, Value) :-
    factVBTable(VBTable),
    possibleVBTableEntry(VBTable, 4, Value).

% Because there is a larger valid VBTable entry in the same VBTable.
% PAPER: ??? NEW!
reasonVBTableEntry(VBTable, Offset, Value) :-
    factVBTableEntry(VBTable, ExistingOffset, _ExistingValue),
    possibleVBTableEntry(VBTable, Offset, Value),
    Offset < ExistingOffset.

% Because the RTTI information says so.
% PAPER: ??? NEW!
reasonVBTableEntry(VBTable, Offset, Value) :-
    rTTIEnabled,
    rTTIValid,
    rTTIInheritsFrom(DerivedTDA, _BaseTDA, _Attributes, 0, P, Offset),
    negative(1, NegativeOne),
    iso_dif(P, NegativeOne),
    possibleVBTableWrite(_Insn, Method, P, VBTable),
    rTTITDA2Class(DerivedTDA, DerivedClass),
    find(Method, DerivedClass),
    possibleVBTableEntry(VBTable, Offset, Value),
    %debug('reasonVBTableEntry_A('),
    %debug(VBTable), debug(', '),
    %debug(Offset), debug(', '),
    %debug(Value), debugln(').'),
    true.

% ============================================================================================
% Embedded object rules.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% The member at Offset in OuterConstructor is certain to be an object instance of class
% InnerConstructor.  The InnerConstructor might be a base class or an embedded object.  This
% rule makes no distinction.
:- table reasonObjectInObject/3 as incremental.

% Because it is already known to be true.
% PAPER: NA
reasonObjectInObject(OuterClass, InnerClass, Offset) :-
    factObjectInObject(OuterClass, InnerClass, Offset).

% Because an existing inhertance relationship exists.
reasonObjectInObject(OuterClass, InnerClass, Offset) :-
    % While it's unusual to gain the derived class knowledge first, we should keep the fact
    % database consistent in cases where we do (e.g. from RTTI information).
    factDerivedClass(OuterClass, InnerClass, Offset),
    %debug('reasonObjectInObject_B('),
    %debug(OuterClass), debug(', '),
    %debug(InnerClass), debug(', '),
    %debug(Offset),debugln(').'),
    true.

% Because an existing embedded object relationship exists.
reasonObjectInObject(OuterClass, InnerClass, Offset) :-
    % This case probably is used at all yet, but it might be someday.
    factEmbeddedObject(OuterClass, InnerClass, Offset),
    %debug('reasonObjectInObject_C('),
    %debug(OuterClass), debug(', '),
    %debug(InnerClass), debug(', '),
    %debug(Offset),debugln(').'),
    true.

% Because the outer constructor explicitly calls the inner constructor on that offset.
% PAPER: Relate-1
% ED_PAPER_INTERESTING
reasonObjectInObject(OuterClass, InnerClass, Offset) :-
    % We are certain that this member offset is passed to InnerConstructor.
    validFuncOffset(_CallInsn, OuterConstructor, InnerConstructor, Offset),
    factConstructor(OuterConstructor),
    factConstructor(InnerConstructor),
    iso_dif(InnerConstructor, OuterConstructor),
    find(InnerConstructor, InnerClass),
    find(OuterConstructor, OuterClass),
    % It's not good enough for the methods to currently be on the same class.  What's really
    % correct is that we know that they're on different classes.  To preserve the previous
    % behavior, the weaker rule was moved to a guess.
    (factNOTMergeClasses(InnerClass, OuterClass);
     factNOTMergeClasses(OuterClass, InnerClass)),

    % There's a poorly understood case demonstrated by constructors in Lite/oo:
    %   0x40365c = std::length_error
    %   0x40360f = std::logic_error
    %   0x403f39 = std::exception

    % The hierarchy is length_error is a logic_error, which is an exception, but this rule
    % concludes that there's an exception in length_error, which is probably not what we
    % wanted.  This blocks that condition, but it's not clear that it does so optimally.
    not(reasonDerivedClassRelationship(OuterClass, InnerClass)),

    %debug('reasonObjectInObject_A('),
    %debug(OuterClass), debug(', '),
    %debug(InnerClass), debug(', '),
    %debug(Offset),debugln(').'),
    true.

% The member at Offset in OuterConstructor is certain to be an object instance of class
% InnerConstructor.  The reasoning was intended to be based on two different constructors
% writing the same VFTable.  The intended scenario was that the outer constructor inlined a
% constructor for the inner class (which we detected via the VFTable write) but there was
% another implementation of the inner constructor that was associated with the inner class that
% identifed inner class for us.  But this rule proved to be too fragile.  Specifically, it's
% very important that we properly exclude the case where Offset is zero, and the two
% constructors are really two constructors on the same class.  This was supposed to happen
% because we called methodsNOTOnSameClass(), but that's not a true asserted fact -- it's
% reasoned based on our current find results, which can change with class mergers.  If we want
% this rule, we'll need stronger negative assertions of class non-equivalence.
%reasonObjectInObject(OuterClass, InnerClass, Offset) :-
%    factConstructor(OuterConstructor),
%    factVFTableWrite(_Insn1, OuterConstructor, Offset, VFTable),
%    factConstructor(InnerConstructor),
%    factVFTableWrite(_Insn2, InnerConstructor, 0, VFTable),
%    iso_dif(InnerConstructor, OuterConstructor,
%    find(InnerConstructor, InnerClass),
%    find(OuterConstructor, OuterClass),
%    iso_dif(InnerClass, OuterClass).
%    %debug('reasonObjectInObject2('),
%    %debug(OuterClass), debug(', '),
%    %debug(InnerClass), debug(', '),
%    %debug(Offset),debugln(').').

% --------------------------------------------------------------------------------------------
% The member at Offset in Class is certain to be an object instance of the type associated with
% the class EmbeddedClass.
:- table reasonEmbeddedObject/3 as incremental.

% Because it is already known to be true.
% PAPER: NA
reasonEmbeddedObject(Class, EmbeddedClass, Offset) :-
    factEmbeddedObject(Class, EmbeddedClass, Offset).

% Because the object is there and we know it's not a case of inheritance.
% PAPER: Logic
reasonEmbeddedObject(Class, EmbeddedClass, Offset) :-
    factObjectInObject(Class, EmbeddedClass, Offset),
    % If this were true, we'd be inhertance instead.
    factNOTDerivedClass(Class, EmbeddedClass, Offset).

% Because if a constructor has no base, but there is an object inside an object, then that
% object must be an embedded object (and not a base class).
% PAPER: Relate-2 / logic
reasonEmbeddedObject(Class, EmbeddedClass, Offset) :-
    factObjectInObject(Class, EmbeddedClass, Offset),
    factClassHasNoBase(Class).

% Add rule for: We must be an embedded object if the table we write was the certain normal
% (unmodified) table of the embedded constructor.  Duplicate of inheritance NOT rule?

% --------------------------------------------------------------------------------------------
:- table reasonNOTEmbeddedObject/3 as incremental.

% Because it is already known to be true.
% PAPER: NA
reasonNOTEmbeddedObject(Class, EmbeddedClass, Offset) :-
    factNOTEmbeddedObject(Class, EmbeddedClass, Offset).

% Because we can't be an embedded object if we're already an inheritance relationship.
% PAPER: Logic
reasonNOTEmbeddedObject(Class, EmbeddedClass, Offset) :-
    factObjectInObject(Class, EmbeddedClass, Offset),
    factDerivedClass(Class, EmbeddedClass, Offset).

% Add rule for: We cannot be an embedded object if we've extended the vftable in question.

% ============================================================================================
% Rules for inheritance relationships.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% Derived class is certain to derived from the base class at the specified offset.
:- table reasonDerivedClass/3 as incremental.

:- table reasonDerivedClass_A/3 as incremental.
:- table reasonDerivedClass_B/3 as incremental.
:- table reasonDerivedClass_C/3 as incremental.
:- table reasonDerivedClass_D/3 as incremental.
:- table reasonDerivedClass_E/3 as incremental.

reasonDerivedClass(DerivedClass, BaseClass, ObjectOffset) :-
    or([reasonDerivedClass_A(DerivedClass, BaseClass, ObjectOffset),
        reasonDerivedClass_B(DerivedClass, BaseClass, ObjectOffset),
        reasonDerivedClass_C(DerivedClass, BaseClass, ObjectOffset),
        reasonDerivedClass_D(DerivedClass, BaseClass, ObjectOffset),
        reasonDerivedClass_E(DerivedClass, BaseClass, ObjectOffset)
      ]).

% Because it is already known to be true.
% PAPER: NA
reasonDerivedClass_A(DerivedClass, BaseClass, ObjectOffset) :-
    factDerivedClass(DerivedClass, BaseClass, ObjectOffset).

% Because reasons...
% PAPER: Relate-3
% ED_PAPER_INTERESTING
reasonDerivedClass_B(DerivedClass, BaseClass, ObjectOffset) :-
    % Some instruction in the derived class constructor called the base class constructor.
    % This is the part of the rule that determines which is the base class and which is the
    % derived class.  There might be other ways of doing this as well, like determining which
    % of the two classes is smaller.  Without this clause we'd just be saying that the two
    % constructors had an inheritance relationship without identifying which was the base.
    validFuncOffset(_, DerivedConstructor, BaseConstructor, ObjectOffset),
    factConstructor(DerivedConstructor),
    factConstructor(BaseConstructor),
    iso_dif(DerivedConstructor, BaseConstructor),

    % Both methods wrote confirmed vtables into offsets in the object.  In the derived class,
    % the offset is the location of the object, but in the base class it will always be the
    % table written to offset zero.
    factVFTableWrite(_Insn1, DerivedConstructor, _OtherObjectOffset, DerivedVFTable),
    factVFTableWrite(_Insn2, BaseConstructor, 0, BaseVFTable),

    % And the vtables values written were different
    iso_dif(DerivedVFTable, BaseVFTable),
    % A constructor can't be it's own parent.
    iso_dif(DerivedConstructor, BaseConstructor),
    find(DerivedConstructor, DerivedClass),
    find(BaseConstructor, BaseClass),

    % There's not already an inheritance relationship.  (Prevent grand ancestors)
    not(reasonDerivedClassRelationship(DerivedClass, BaseClass)),

    %debug('DEBUG Derived VFTable: '), debug(DerivedVFTable),
    %debug(' Base VFTable: '), debug(BaseVFTable),
    %debug(' Derived Contstructor: '), debug(DerivedConstructor),
    %debug(' Base Constructor: '), debugln(BaseConstructor),

    % Debugging
    not(factDerivedClass(DerivedClass, BaseClass, ObjectOffset)),
    %debug('reasonDerivedClass_B('),
    %debug(DerivedClass), debug(', '),
    %debug(BaseClass), debug(', '),
    %debug(ObjectOffset), debugln(').'),
    true.

% Ed: So this situation is complicated as well.  This rule is flawed because the last statement
% is incorrect (we are incorrectly permitting cases where the Method is on the base's base
% class).  This rule appears to be related to a failure in muparser where we reach a wrong
% conclusion because of it.  Even with it removed, we can still pass our tests, so it's not
% required.  But I think it was added to correct a problem in Firefox or something like that.
% Unfortunately, because our test suite management is poor, it's difficult to know why we
% needed it.  How do you think we should proceed?

% Because there's a method ocurring in two different VFTables, and those VFTables are written
% into the same location in an object.
% PAPER: Relate-4
%reasonDerivedClass(DerivedClass, BaseClass, ObjectOffset) :-
%    % And there's a method that appears in two different VFTables...
%    factVFTableEntry(BaseVFTable, _BaseVFTableOffset, Entry),
%    factVFTableEntry(DerivedVFTable, _DerivedVFTableOffset, Entry),
%    iso_dif(DerivedVFTable, BaseVFTable),
%    dethunk(Entry, Method),
%
%    % The method must be assigned to the base class because base classes can't call methods on
%    % the derived class.
%    find(Method, BaseClass),
%    not(purecall(Method)),
%
%    % Find a constructor in the base class.
%    factConstructor(BaseConstructor),
%    factVFTableWrite(_Insn1, BaseConstructor, 0, BaseVFTable),
%    find(BaseConstructor, BaseClass),
%
%    % And other constructor that's different from the base constructor.
%    factConstructor(DerivedConstructor),
%    factVFTableWrite(_Insn2, DerivedConstructor, ObjectOffset, DerivedVFTable),
%    iso_dif(DerivedConstructor, BaseConstructor),
%
%    % The derived class must be different from the base class.
%    find(DerivedConstructor, DerivedClass),
%    iso_dif(DerivedClass, BaseClass),
%
%    % We must eliminate cases where the method is really on the base classes' base class.  See
%    % ClassHasUnknownBase for more details.
%    factClassHasNoBase(BaseClass).
%    % Previous (incorrect) versions of this term/line included:
    %not(factDerivedClass(DerivedClass, _ExistingBase, _OtherObjectOffset)),
    %not(factDerivedClass(DerivedClass, BaseClass, _OtherObjectOffset)),

    % Short format debugging.
    %debug('reasonDerivedClass2('), debug(DerivedClass), debug(', '),
    %debug(BaseClass), debug(', '),
    %debug(ObjectOffset), debugln(').').

    % Long format debugging.
    %debug('reasonDerivedClass2()...'),
    %debug('  Method: '), debugln(Method),
    %debug('  Base VFTable: '), debug(BaseVFTable),
    %debug('    Constructor: '), debug(BaseConstructor),
    %debug('    Class: '), debugln(BaseClass),
    %debug('  Derived VFTable: '), debug(DerivedVFTable),
    %debug('    Constructor: '), debug(DerivedConstructor),
    %debug('    Class: '), debugln(DerivedClass).


% This rule might be slightly off, because another possibility is that there's a nearly
% invisible derived class relationship in between the derived class and the base class.  This
% was observed by David in ooex10 and ooex11 test cases.
% PAPER: Logic
reasonDerivedClass_C(DerivedClass, BaseClass, Offset) :-
    factObjectInObject(DerivedClass, BaseClass, Offset),
    factNOTEmbeddedObject(DerivedClass, BaseClass, Offset),
    % Debugging
    %not(factDerivedClass(DerivedClass, BaseClass, Offset)),
    %debug('reasonDerivedClass_C('),
    %debug(DerivedClass), debug(', '),
    %debug(BaseClass), debug(', '),
    %debug(Offset), debugln(').'),
    true.

% Because RTTI tells us so for a non-virtual base class.
reasonDerivedClass_D(DerivedClass, BaseClass, Offset) :-
    rTTIEnabled,
    rTTIValid,
    negative(1, NegativeOne),
    rTTIInheritsFrom(DerivedTDA, BaseTDA, _Attributes, Offset, NegativeOne, 0),
    rTTITDA2Class(DerivedTDA, DerivedClass),
    rTTITDA2Class(BaseTDA, BaseClass),
    iso_dif(BaseClass, DerivedClass),
    % Debugging
    %not(factDerivedClass(DerivedClass, BaseClass, Offset)),
    %debug('reasonDerivedClass_D('),
    %debug(DerivedClass), debug(', '),
    %debug(BaseClass), debug(', '),
    %debug(Offset), debugln(').'),
    true.

% Because RTTI tells us so for a virtual base class.
reasonDerivedClass_E(DerivedClass, BaseClass, Offset) :-
    rTTIEnabled,
    rTTIValid,
    rTTIInheritsFrom(DerivedTDA, BaseTDA, _Attributes, _M, P, V),
    negative(1, NegativeOne),
    iso_dif(P, NegativeOne),
    possibleVBTableWrite(_Insn, Method, P, VBTableAddr),
    rTTITDA2Class(DerivedTDA, DerivedClass),
    rTTITDA2Class(BaseTDA, BaseClass),
    iso_dif(BaseClass, DerivedClass),
    find(Method, DerivedClass),
    possibleVBTableEntry(VBTableAddr, V, Entry),
    Offset is P + Entry,
    % Debugging
    %not(factDerivedClass(DerivedClass, BaseClass, Offset)),
    %debug('reasonDerivedClass_E('),
    %debug(_M), debug(', '),
    %debug(P), debug(', '),
    %debug(V), debug(', '),
    %debug(Method), debug(', '),
    %debug(VBTableAddr), debug(', '),
    %debug(DerivedClass), debug(', '),
    %debug(BaseClass), debug(', '),
    %debug(Offset), debugln(').'),
    true.

% --------------------------------------------------------------------------------------------
:- table reasonNOTDerivedClass/3 as incremental.

% Because it is already known to be true.
% PAPER: NA
reasonNOTDerivedClass(DerivedClass, BaseClass, ObjectOffset) :-
    factNOTDerivedClass(DerivedClass, BaseClass, ObjectOffset).

% Because it can't be an inheritance relationship if it is already an embedded object.
% PAPER: Logic
reasonNOTDerivedClass(DerivedClass, BaseClass, ObjectOffset) :-
    factEmbeddedObject(DerivedClass, BaseClass, ObjectOffset),
    factConstructor(DerivedConstructor),
    factConstructor(BaseConstructor),
    find(DerivedConstructor, DerivedClass),
    find(BaseConstructor, BaseClass).

% Add rule for: We cannot be a derived constructor if the table we write was the certain normal
% (unmodified) table of the base constructor.

% --------------------------------------------------------------------------------------------
% It is certain that there is a derived class relationship between the the two classes,
% although there might be multiple classes in between them in the inheritance hierarchy.
:- table reasonDerivedClassRelationship/2 as incremental.

% Because there's an immediate relationship.
% PAPER: NA
reasonDerivedClassRelationship(DerivedClass, BaseClass) :-
    factDerivedClass(DerivedClass, BaseClass, _Offset).

% Because there's a relationship with one or more intermediate classes.
% PAPER: Do we need this in the paper?
reasonDerivedClassRelationship(DerivedClass, BaseClass) :-
    factDerivedClass(DerivedClass, MiddleClass, _Offset),
    iso_dif(DerivedClass, MiddleClass),
    reasonDerivedClassRelationship(MiddleClass, BaseClass),
    iso_dif(MiddleClass, BaseClass).

% --------------------------------------------------------------------------------------------
% It is certain that the class has no base class.
:- table reasonClassHasNoBase/1 as incremental.

% Because it is already known to be true.
% PAPER: NA
reasonClassHasNoBase(Class) :-
    factClassHasNoBase(Class).

% Because RTTI told us so.
% ED_PAPER_INTERESTING
reasonClassHasNoBase(Class) :-
    % RTTI analysis is enabled, and the data structures were internally consistent.
    rTTIEnabled,
    rTTIValid,
    rTTINoBase(TDA),
    rTTITDA2Class(TDA, Class),
    %debug('reasonClassHasNoBase('), debug(TDA), debug(', '), debug(Class), debugln(').'),
    true.

reasonClassHasNoBaseSet(Set) :-
    setof(Class, reasonClassHasNoBase(Class), Set).

% --------------------------------------------------------------------------------------------
% It is certain that the class has a base class (but we don't know which class it is).
:- table reasonClassHasUnknownBase/1 as incremental.
:- table reasonClassHasUnknownBase_A/1 as incremental.
:- table reasonClassHasUnknownBase_B/1 as incremental.
:- table reasonClassHasUnknownBase_C/1 as incremental.
:- table reasonClassHasUnknownBase_D/1 as incremental.
:- table reasonClassHasUnknownBase_E/1 as incremental.

reasonClassHasUnknownBase(Class) :-
    or([reasonClassHasUnknownBase_A(Class),
        reasonClassHasUnknownBase_B(Class),
        reasonClassHasUnknownBase_C(Class),
        reasonClassHasUnknownBase_D(Class),
        reasonClassHasUnknownBase_E(Class)
      ]).

% Because it is already known to be true.
% PAPER: NA
reasonClassHasUnknownBase_A(Class) :-
    factClassHasUnknownBase(Class).

% Because there's what looks like a valid virtual base table.
% PAPER: Relate-5
% ED_PAPER_INTERESTING
reasonClassHasUnknownBase_B(Class) :-
    factVBTableWrite(_Insn, Constructor, _Offset, _VBTable),
    factConstructor(Constructor),
    find(Constructor, Class).

% Because there's a method ocurring in two different VFTables, and those VFTables are written
% into the same location in an object.  This rule does not prove which class is the base class,
% only that there's an ancestor class (because the rule might match a method on the true base's
% base class as well.
% PAPER: Relate-6
% ED_PAPER_INTERESTING
reasonClassHasUnknownBase_C(DerivedClass) :-
    % And there's a method that appears in two different VFTables...  During the thunk
    % conversion Cory chose to make the VFTable entries match exactly, but it's possible that
    % we really mean any two entries that dethunk to the same actual method.
    factVFTableEntry(AncestorVFTable, _AncestorVFTableOffset, Entry),
    factVFTableEntry(DerivedVFTable, _DerivedVFTableOffset, Entry),
    dethunk(Entry, Method),
    iso_dif(DerivedVFTable, AncestorVFTable),

    % The method must be assigned to the ancestor class because ancestor classes can't call
    % methods on the derived class.
    find(Method, AncestorClass),

    % Find a constructor in the base class.
    find(AncestorConstructor, AncestorClass),
    factConstructor(AncestorConstructor),

    % And other constructor that's different from the base constructor.
    factConstructor(DerivedConstructor),
    iso_dif(DerivedConstructor, AncestorConstructor),

    % The derived class must be different from the base class.
    find(DerivedConstructor, DerivedClass),
    iso_dif(DerivedClass, AncestorClass),

    % Both methods wrote confirmed vtables into offsets in the object.  In the derived class,
    % the offset is the location of the object, but in the base class it will always be the
    % table written to offset zero.
    factVFTableWrite(_Insn1, DerivedConstructor, _ObjectOffset, DerivedVFTable),
    factVFTableWrite(_Insn2, AncestorConstructor, 0, AncestorVFTable).


% Because RTTI tells us so.
reasonClassHasUnknownBase_D(Class) :-
    % Normally we'd conclude that there was a specific derived relationship, but because of
    % problems reliably associating VFTables with methods, in some cases the best that we can
    % manage is to know that there's a base class...
    rTTIEnabled,
    rTTIValid,
    rTTIInheritsFrom(DerivedTDA, _BaseTDA, _Attributes, _Offset, _P, _V),
    rTTITDA2Class(DerivedTDA, Class),
    not(factDerivedClass(Class, _BaseClass, _Offset)),
    not(factClassHasUnknownBase(Class)),
    %debug('reasonClassHasUnknownBase_D('),
    %debug(Class), debugln(').'),
    true.

% Because the class shares a method that we know is not assigned to the class.
reasonClassHasUnknownBase_E(Class) :-
    factClassCallsMethod(Class, Method),
    find(Method, MethodClass),
    factNOTMergeClasses(Class, MethodClass),
    % Debugging
    %debug('reasonClassHasUnknownBase_E('), debug(Class), debugln(').'),
    true.

reasonClassHasUnknownBaseSet(Set) :-
    setof(Class, reasonClassHasUnknownBase(Class), Set).

% ============================================================================================
% Rules for method assignment.
% ============================================================================================

:- table reasonClassCallsMethod/2 as incremental.
:- table reasonClassCallsMethod_A/2 as incremental.
:- table reasonClassCallsMethod_B/2 as incremental.
:- table reasonClassCallsMethod_C/2 as incremental.
:- table reasonClassCallsMethod_D/2 as incremental.
:- table reasonClassCallsMethod_E/2 as incremental.
:- table reasonClassCallsMethod_F/2 as incremental.

reasonClassCallsMethod(Class, Method) :-
    or([reasonClassCallsMethod_A(Class, Method),
        reasonClassCallsMethod_B(Class, Method),
        reasonClassCallsMethod_C(Class, Method),
        reasonClassCallsMethod_D(Class, Method)
%        reasonClassCallsMethod_E(Class, Method),
%        reasonClassCallsMethod_F(Class, Method)
      ]).

% Because two methods are called on the same this-pointer in the same function.
% XXX: This rule is messed up because we don't know the directionality of the calling.  Cory and Ed discussed changing it into a guessing rule that guesses the direction of the relationship.
% PAPER: Call-1
reasonClassCallsMethod_A(Class1, Method2) :-
    thisPtrUsage(_, Function, ThisPtr, Method1),
    thisPtrUsage(_, Function, ThisPtr, Method2),
    iso_dif(Method1, Method2),
    find(Method1, Class1),
    % Don't propose assignments we already know.
    find(Method2, Class2),
    iso_dif(Class1, Class2),

    % Function could be a derived constructor calling Method1 (a base constructor) and Method2
    % (a method on Function's class).  This incorrectly concludes that Method2 is called from
    % Method1 unless it is blocked by a clause like this...  but what is really correct here?
    not((find(Function, FunctionClass), factObjectInObject(FunctionClass, Class1, 0))),

    % Functions that are methods can call base methods
    % Debugging
    %not(factClassCallsMethod(Class1, Method2)),
    %debug('reasonClassCallsMethod_A('),
    %debug(Function), debug(', '),
    %debug(Method1), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Method2), debugln(').'),
    true.

% Because the method appears in a vftable assigned in another method.
% PAPER: Call-2
reasonClassCallsMethod_B(Class1, Method2) :-
    factVFTableWrite(_Insn, Method1, 0, VFTable),
    not(factVFTableOverwrite(VFTable, _PrimaryVFTable, 0)),
    % And the method is in that virtual function table.
    factVFTableEntry(VFTable, _TableOffset, Entry2),
    dethunk(Entry2, Method2),
    iso_dif(Method1, Method2),
    not(purecall(Entry2)), % Never merge purecall methods into classes.
    not(purecall(Method2)), % Never merge purecall methods into classes.
    find(Method1, Class1),
    % Don't propose assignments we already know.
    find(Method2, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    %not(factClassCallsMethod(Class1, Method2)),
    %debug('reasonClassCallsMethod_B('),
    %debug(VFTable), debug(', '),
    %debug(Method1), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Method2), debugln(').'),
    true.

% Because one method calls another method on the same this-pointer.
% PAPER: Call-3
reasonClassCallsMethod_C(Class1, Method2) :-
    funcOffset(_Insn, Method1, Method2, 0),
    iso_dif(Method1, Method2),
    find(Method1, Class1),
    % Don't propose assignments we already know.
    find(Method2, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    %not(factClassCallsMethod(Class1, Method2)),
    %debug('reasonClassCallsMethod_C('),
    %debug(Method1), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Method2), debugln(').'),
    true.

% Because a method on an outer class calls a method on a known inner object.
reasonClassCallsMethod_D(InnerClass, InnerMethod) :-
    % An outer method calls and inner method on a this pointer.
    thisPtrUsage(_Insn, OuterMethod, InnerThisPtr, InnerMethod),
    % There's an offset from the outer this pointer to the inner this pointer.
    thisPtrOffset(_OuterThisPtr, Offset, InnerThisPtr),
    % BUG!!! We should really tie the OuterThisPtr to the OuterMethod, but we don't presently
    % export the facts required to do that, so we'll just assume they're related for right now.
    find(OuterMethod, OuterClass),
    % We must know that there's an object within an object at that offset.
    factObjectInObject(OuterClass, InnerClass, Offset),
    iso_dif(OuterClass, InnerClass),
    iso_dif(InnerClass, InnerMethod),
    % Debugging
    %not(factClassCallsMethod(InnerClass, InnerMethod)),
    %debug('reasonClassCallsMethod_D('),
    %debug(OuterClass), debug(', '),
    %debug(OuterMethod), debug(', '),
    %debug(InnerClass), debug(', '),
    %debug(InnerMethod), debugln(').'),
    true.

% This is basically a duplicate of the logic that made the cdecl functon a method in the first
% place.  Here we're just repeating the logic to associate it with the correct class.
reasonClassCallsMethod_E(Class, Method) :-
    factMethod(Proven),
    find(Proven, Class),
    thisCallMethod(Proven, ThisPtr, _Convention),
    callParameter(Insn, Proven, 0, ThisPtr),
    callTarget(Insn, Proven, Method),
    callingConvention(Method, '__cdecl'),
    % Debugging
    %not(factClassCallsMethod(Class, Method)),
    %debug('reasonClassCallsMethod_E('),
    %debug(Insn), debug(', '),
    %debug(Class), debug(', '),
    %debug(Method), debugln(').'),
    true.

% Know this-pointers passed from one method to another within a function.
reasonClassCallsMethod_F(Class, Method) :-
    % A ThisPtr is passed to a known method.
    callParameter(Insn1, Func, 0, ThisPtr),
    callTarget(Insn1, Func, Target1),
    dethunk(Target1, Proven),
    factMethod(Proven),
    find(Proven, Class),
    % Then the same this-pointer is passed to another method.
    callParameter(Insn2, Func, 0, ThisPtr),
    iso_dif(Insn1, Insn2),
    callTarget(Insn2, Func, Target2),
    dethunk(Target2, Method),
    callingConvention(Method, '__cdecl'),
    % Debugging
    %not(factClassCallsMethod(Class, Method)),
    %debug('reasonClassCallsMethod_F('),
    %debug(Insn1), debug(', '),
    %debug(Insn2), debug(', '),
    %debug(Class), debug(', '),
    %debug(Method), debugln(').'),
    true.

% --------------------------------------------------------------------------------------------
% So the reasonInstanceIndirectlyCallMethod rule turned out to be wrong.  I've kept the notes
% to think about it some more.  Something like this is needed to drive arbitrary method
% assignment.  Because otherwise we don't know that loosely connected methods are more
% associated with a class than any other.  This is basically transitivity of call relationships
% (e.g if A calls B and B calls C, then A calls C as well.)  But where I seem to have gone
% wrong was by including this rule in InstanceCallsMethod which appears to include some
% reasoning that doesn't account for this indirection.  Perhaps the other rule would be more
% clearly named InstanceImmediatelyCallsMethod.  The flaw in this rule is somehow related to
% embedded objects at offset zero transferring method instances to the embedded object in a way
% that makes other rules incorrect.

% --------------------------------------------------------------------------------------------
:- table reasonMergeClasses/2 as incremental.

% This is an attempt by Ed to avoid recomputing all of reasonMergeClasses when we invalidate
% the tables because of new facts.
:- table reasonMergeClasses_A/2 as incremental.
:- table reasonMergeClasses_B/2 as incremental.
:- table reasonMergeClasses_C/2 as incremental.
:- table reasonMergeClasses_D/2 as incremental.
:- table reasonMergeClasses_E/2 as incremental.
:- table reasonMergeClasses_F/2 as incremental.
:- table reasonMergeClasses_G/2 as incremental.
:- table reasonMergeClasses_H/2 as incremental.

reasonMergeClasses(C,M) :- or([reasonMergeClasses_A(C,M),
                               reasonMergeClasses_B(C,M),
                               reasonMergeClasses_C(C,M),
                               reasonMergeClasses_D(C,M),
                               reasonMergeClasses_E(C,M),
                               reasonMergeClasses_F(C,M),
                               reasonMergeClasses_G(C,M),
                               reasonMergeClasses_H(C,M)]).

% Because the classes have already been merged.
reasonMergeClasses_A(Method1, Method2) :-
    factMergeClasses(Method1, Method2).

% If a constructor and a real destructor share the same vtable, they must be the same class.
% We decided that reasonMergeClassesA was a special case of reasonMergeClassesD.
%% reasonMergeClassesA(Constructor, RealDestructor) :-
%%     factConstructor(Constructor),
%%     factRealDestructor(RealDestructor),
%%     factVFTableWrite(_CInsn, Constructor, ObjectOffset, VFTable),
%%     factVFTableWrite(_DInsn, RealDestructor, ObjectOffset, VFTable),
%%     methodsNOTOnSameClass(Constructor, RealDestructor).

% Because the method occurs in a VFTable of a class that has no base.
%reasonMergeClasses(Constructor, Method) :-
%    % Technically, this might match a destructor which is also correct.
%    factVFTableWrite(_Insn, Constructor, _ObjectOffset, VFTable),
%    find(Constructor, Class),
%    factClassHasNoBase(Class),
%    factVFTableEntry(VFTable, _VFTableOffset, Entry), dethunk(Entry, Method),
%    debug('************** reasonMergeClasses('),
%    debug(Constructor), debug(', '),
%    debug(Method), debugln(').').


% A large portion of this next rule used to be called "certainConflictedVirtualMethod".  Cory
% is very confused about whether that logic is useful on it's own or not, but until there's an
% actual example of where it's independently useful, I'm rolling it into this rule.  Part of
% the problem is that this rule is still dependent on constructors just because we haven't put
% VFTables in the class method list yet...  Wow!  This entire rule was a hot mess, and I'm not
% sure it's even needed.  After more analysis it appears to be a needlessly complicated version
% of reasonMergeClasses_F.

% Because the method occurs in a VFTable of a class that has no base.
reasonMergeClasses_B(BaseClass, MethodClass) :-
    % There's a base class that has no base of it's own.
    factClassHasNoBase(BaseClass),
    find(BaseConstructor, BaseClass),
    factConstructor(BaseConstructor),
    % That base class is in a dervied class relationship.
    factDerivedClass(DerivedClass, BaseClass, ObjectOffset),
    factConstructor(DerivedConstructor),
    find(DerivedConstructor, DerivedClass),

    % There are two entries in the vftables (at the same object offset) for those classes.
    % Those methods must
    factVFTableWrite(_BaseInsn, BaseConstructor, ObjectOffset, BaseVFTable),
    factVFTableEntry(BaseVFTable, _BaseVTableOffset, Entry1),
    factVFTableWrite(_DerivedInsn, DerivedConstructor, ObjectOffset, DerivedVFTable),
    factVFTableEntry(DerivedVFTable, _DerivedVTableOffset, Entry2),

    % With the addition of thunk reasoning, it's unclear whether the literally have to match,
    % or whether they simple need to thunk to the same location.   This logic implements the
    % previous behavior.
    dethunk(Entry1, Method),
    dethunk(Entry2, Method),
    not(purecall(Entry1)), % Never merge purecall methods into classes.
    not(purecall(Entry2)), % Never merge purecall methods into classes.
    not(purecall(Method)), % Never merge purecall methods into classes.

    % Finally check that the base class and method class are not already the same.
    find(Method, MethodClass),
    iso_dif(BaseClass, MethodClass),

    % Debugging.
    %debug('reasonMergeClasses_B('),
    %debug(BaseClass), debug(', '),
    %debug(MethodClass), debug(', '),
    %debug(Method), debugln(').'),
    true.

% If an object instance associated with the constructor calls the method, and it has no base
% class, the method must be on exactly the class associated with the constructor.  Wrong!  What
% we really mean is that it cannot be on the classes derived from this constructor, because
% base classes can't call derived methods, and if the constructor itself has no base class
% then...  It's either on exactly that class or the class embedded at offset zero.  For this
% rule to be correct we also need to exclude embedded objects at offset zero.  There's still
% confusion about whether we already know whether it's embedded or
% PAPER: Merging-2
reasonMergeClasses_C(Class, ExistingClass) :-
    factClassCallsMethod(Class, Method),
    not(purecall(Method)), % Never merge purecall methods into classes.
    % If we have no bases, it can't be on a base class.
    factClassHasNoBase(Class),
    % And if there's no object (embedded or base?) at offset zero...
    not(factObjectInObject(Class, _InnerClass, 0)),

    find(Method, ExistingClass),
    iso_dif(Class, ExistingClass),
    % Confusingly, the method's class must also have no base and no object at offset zero,
    % because the method being called could actually be the base class method...
    factClassHasNoBase(ExistingClass),
    not(factObjectInObject(ExistingClass, _InnerClass, 0)),

    %debug('reasonMergeClasses_C('),
    %debug(Class), debug(', '),
    %debug(ExistingClass), debugln(').'),
    true.

% PAPER: Merging-1
% ED_PAPER_INTERESTING
reasonMergeClasses_D(Method1, Method2) :-
    % There's some recurring confusion about _which_ tables must be the same.  In particular
    % when base class constructors are inlined and in multiple/virtual inheritance scenarios.
    % In the strictest form, this rule would require that both offsets be zero.  In the loosest
    % form, any two VFTable writes would be sufficient to merge them.  These rules need more
    % discussion about what the compiler might actually generate.  Currently, we require that
    % they match which is sort of midway inbetween.  Regardless of what the correct logic is,
    % it's important that this rule continue to match the constraint, since allowing the two to
    % be out of sync can result in excessive backtracking.
    factVFTableWrite(_Insn1, Method1, ObjectOffset, VFTable),
    factVFTableWrite(_Insn2, Method2, ObjectOffset, VFTable),

    % Method1 and Method2 cannot be purecall already.

    % And the VFTable we're basing this conclusion on is not an overwritten VFTable.
    not(factVFTableOverwrite(VFTable, _OtherVFTable, _OtherOffset)),

    % And the existing classes are not the same already, which is obviously wrong...
    find(Method1, Class1),
    find(Method2, Class2),
    iso_dif(Class1, Class2),

    % Also ensure that the two methods not in a class relationship already.  Merging them would
    % ultimately result in merging a class with it's own ancestor.
    not((
               reasonDerivedClassRelationship(Class1, Class2);
               reasonDerivedClassRelationship(Class2, Class1)
        )),

    % Finally there's what we now think is an optimization and inlining problem where the only
    % VFTable mentioned in the deleting destructor is a base class' VFTable.  This presumably
    % occurs because the base class destructor was inlined, and the compiler detected the
    % overwrite of the current class' VFTable with the base class' VFTable and optimized away
    % the currrent class' VFTable write.  If this same situation occurred in the constructor,
    % it would not affect this rule, because the VFTable write that was kept was the correct
    % one.  Therefore this logic only applies to destructors.  This problem is demonstrated by
    % 2010/Lite/oo bad_cast at 0x404046 and by codecvt at 0x402249.  Cory has tried several
    % variations of this clause, and sadly many produce different results.

    factConstructor(Method1),
    factConstructor(Method2),

    %not((
    %           (factNOTConstructor(Method1), not(factClassHasNoBase(Class1)));
    %           (factNOTConstructor(Method2), not(factClassHasNoBase(Class2)))
    %   )),

    %debug('reasonMergeClasses_D('),
    %debug(Method1), debug(', '),
    %debug(Method2), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% The constructors are certain to be on the exact same class.  The reasoning is that if there's
% two known classes, and they're both a base class of a single derived class (at the same
% offset) then the two base classes must be same class.  I think this is another way of saying
% a class can't inherit from the same base class twice, which I think is true. Also see the
% inverse rule under reasonNOTMergeClasses.
% PAPER: Merging-4
reasonMergeClasses_E(Class1, Class2) :-
    factDerivedClass(DerivedClass, Class1, ObjectOffset),
    factDerivedClass(DerivedClass, Class2, ObjectOffset),
    iso_dif(Class1, Class2),
    %debug('reasonMergeClasses_E('),
    %debug(DerivedClass), debug(', '),
    %debug(ObjectOffset), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% Because the Method2 appears in VFTable assocated with a class, and that class has no base, so
% all methods in the VFTable must be on the class.
% PAPER: Merging-16
% Ed comment: This rule seems too specialized. Another way of thinking about this rule is that any method in a virtual function table is on the class or its ancestor.  If there is no base, then obviously the method is on the class itself.
% ED_PAPER_INTERESTING
reasonMergeClasses_F(Class1, Class2) :-
    % Start with a method associated with a primary VFTable (offset zero).
    factVFTableWrite(_Insn, Method1, 0, VFTable),
    % The VFTable wasn't an overwritten VFTable.
    not(factVFTableOverwrite(VFTable, _OtherVFTable, _OtherOffset)),
    % There's a second method in that VFTable.
    factVFTableEntry(VFTable, _VFTableOffset, Entry),
    dethunk(Entry, Method2),
    % Method1 cannot be purecall already because of factVFTableWrite().
    not(purecall(Entry)), % Never merge purecall methods into classes.
    not(purecall(Method2)), % Never merge purecall methods into classes.
    find(Method1, Class1),
    % If the VFTable class has no base, the method must be on the class.
    factClassHasNoBase(Class1),
    find(Method2, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    %debug('reasonMergeClasses_F('),
    %debug(Method1), debug(', '),
    %debug(Method2), debug(', '),
    %debug(VFTable), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% Because the symbols tell us they're the same class.
% PAPER: XXX Symbols
reasonMergeClasses_G(Class1, Class2) :-
    symbolClass(Method1, ClassName, _MethodName1),
    symbolClass(Method2, ClassName, _MethodName2),
    iso_dif(Method1, Method2),
    find(Method1, Class1),
    find(Method2, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    %debug('reasonMergeClasses_G('),
    %debug(Method1), debug(', '),
    %debug(Method2), debug(', '),
    %debug(ClassName), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% Because additional methods in our VFTable must be ours.
% PAPER: Merging-17
% ED_PAPER_INTERESTING
reasonMergeClasses_H(DerivedClass, MethodClass) :-
    % There's a derived and base class, each with vftables.
    factDerivedClass(DerivedClass, BaseClass, _ObjectOffset),
    reasonPrimaryVFTableForClass(DerivedVFTable, DerivedClass),
    reasonPrimaryVFTableForClass(BaseVFTable, BaseClass),
    % We know the maximum size of the base vftable.
    factVFTableSizeLTE(BaseVFTable, BaseSize),
    % There's an entry in the derived vftable that's to big to be in the base vftable.
    factVFTableEntry(DerivedVFTable, VOffset, Entry),
    VOffset > BaseSize,
    dethunk(Entry, Method),
    find(Method, MethodClass),
    iso_dif(DerivedClass, MethodClass),
    % Debugging
    %debug('reasonMergeClasses_H('),
    %debug(DerivedVFTable), debug(', '),
    %debug(BaseVFTable), debug(', '),
    %debug(Method), debug(', '),
    %debug(DerivedClass), debug(', '),
    %debug(MethodClass), debugln(').'),
    true.


% Implement: Because they share a method and neither of them have base classes.  This may be
% needed to ensure that we actually merge the classes.

% Implement: Two object instances constructed with different constructors that both destruct
% using the same real destructor must be the same class, because there can only be one real
% destructor per class.

% --------------------------------------------------------------------------------------------
:- table reasonNOTMergeClasses/2 as incremental.

:- table reasonNOTMergeClasses_A/2 as incremental.
%:- table reasonNOTMergeClasses_B/2 as incremental.
:- table reasonNOTMergeClasses_C/2 as incremental.
%:- table reasonNOTMergeClasses_D/2 as incremental.
:- table reasonNOTMergeClasses_E/2 as incremental.
:- table reasonNOTMergeClasses_F/2 as incremental.
:- table reasonNOTMergeClasses_G/2 as incremental.
%:- table reasonNOTMergeClasses_H/2 as incremental.
:- table reasonNOTMergeClasses_I/2 as incremental.
:- table reasonNOTMergeClasses_J/2 as incremental.
:- table reasonNOTMergeClasses_K/2 as incremental.
:- table reasonNOTMergeClasses_L/2 as incremental.
:- table reasonNOTMergeClasses_M/2 as incremental.
:- table reasonNOTMergeClasses_N/2 as incremental.
:- table reasonNOTMergeClasses_O/2 as incremental.
:- table reasonNOTMergeClasses_P/2 as incremental.

reasonNOTMergeClasses(M1,M2) :-
    or([reasonNOTMergeClasses_A(M1,M2),
        reasonNOTMergeClasses_J(M1,M2),
        %reasonNOTMergeClasses_B(M1,M2),
        reasonNOTMergeClasses_C(M1,M2),
        %reasonNOTMergeClasses_D(M1,M2),
        reasonNOTMergeClasses_E(M1,M2),
        reasonNOTMergeClasses_F(M1,M2),
        reasonNOTMergeClasses_G(M1,M2),
        %reasonNOTMergeClasses_H(M1,M2),
        reasonNOTMergeClasses_I(M1,M2),
        reasonNOTMergeClasses_K(M1,M2),
        reasonNOTMergeClasses_L(M1,M2),
        reasonNOTMergeClasses_M(M1,M2),
        reasonNOTMergeClasses_N(M1,M2),
        reasonNOTMergeClasses_O(M1,M2),
        reasonNOTMergeClasses_P(M1,M2)
      ]).

% Because it's already true.
reasonNOTMergeClasses_A(Class1, Class2) :-
    (factNOTMergeClasses(Class1, Class2);
     factNOTMergeClasses(Class2, Class1)).

% Classes can't be their own bases.
% PAPER: Merging-5
% PAPER: XXX Should be a sanity check?
% XXX: Isn't this a special case of reasonNOTMergeClasses_J?
%% reasonNOTMergeClasses_B(DerivedClass, BaseClass) :-
%%     factDerivedClass(DerivedClass, BaseClass, _ObjectOffset),
%%     % Debugging
%%     not(factNOTMergeClasses(DerivedClass, BaseClass)),
%%     not(factNOTMergeClasses(BaseClass, DerivedClass)),
%%     debug('reasonNOTMergeClasses_B('),
%%     debug(DerivedClass), debug(', '),
%%     debug(BaseClass), debugln(').'),
%%     true.

% Any method on both base and derived is not on the derived class.  They don't have to be
% virtual methods.
% PAPER: Merging-6
% ED_PAPER_INTERESTING
reasonNOTMergeClasses_C(DerivedClass, MethodClass) :-
    factDerivedClass(DerivedClass, BaseClass, _ObjectOffset),
    factClassCallsMethod(DerivedClass, Method),
    factClassCallsMethod(BaseClass, Method),
    find(Method, MethodClass),

    % Turns out that deleting destructors is a common case where multiple implementations are
    % at the same address, and without the guard, the rule results in methods be forced into
    % the wrong classes.  See the case of 0x403659 in Lite/poly, where the vector deleting
    % destructor for std::out_of_range appears in it's PARENT virtual function table of
    % std::logic_error.   So this fix works, but technically for the wrong reasons.
    % not(factDeletingDestructor(Method)),

    % Debugging
    %not(factNOTMergeClasses(DerivedClass, MethodClass)),
    %not(factNOTMergeClasses(MethodClass, DerivedClass)),
    %debug('reasonNOTMergeClasses_C('),
    %debug(Method), debug(', '),
    %debug(BaseClass), debug(', '),
    %debug(DerivedClass), debug(', '),
    %debug(MethodClass), debugln(').'),
    true.

% Any two constructors that write _different_ vftables into the same offets in their objects
% cannot be the same class.
% PAPER: Merging-7
% ED_PAPER_INTERESTING
reasonNOTMergeClasses_E(Class1, Class2) :-
    % Two VFTables are written into the same object offsets in two different methods.  The
    % sterotypical case is of course two compeltely unrelated classes.  This rule applies
    % equally to constructors and destructors.
    factVFTableWrite(_Insn1, Method1, ObjectOffset, VFTable1),
    factVFTableWrite(_Insn2, Method2, ObjectOffset, VFTable2),
    iso_dif(Method1, Method2),
    iso_dif(VFTable1, VFTable2),
    % But one counter example that we need to protect against is the inlining of base class
    % VFTable writes.  The intention here is very similar to factVFTableOverwrite, but without
    % the complications of caring which value overwrote which otehr value.
    not(factVFTableWrite(_Insn3, Method1, ObjectOffset, VFTable2)),
    not(factVFTableWrite(_Insn4, Method2, ObjectOffset, VFTable1)),
    % Those methods cannot be on the same class.
    find(Method1, Class1),
    find(Method2, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_E('),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% The constructors are certain to not be on the exact same class.  The reasoning is the inverse
% of the "classes can't inherit from the same class twice" rules above.  If that rule is
% correct, so is this one.
% PAPER: Merging-8
% ED_PAPER_INTERESTING
reasonNOTMergeClasses_F(Class1, Class2) :-
    factDerivedClass(DerivedClass, Class1, ObjectOffset1),
    factDerivedClass(DerivedClass, Class2, ObjectOffset2),
    iso_dif(Class1, Class2),
    iso_dif(ObjectOffset1, ObjectOffset2),
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_F('),
    %debug(DerivedClass), debug(', '),
    %debug(ObjectOffset1), debug(', '),
    %debug(ObjectOffset2), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% The constructors are certain to not be on the exact same class.  The reasoning is that one
% class is inside the other.  These rules are little suspect because they probably really
% indicate that the classes should have been merged earlier (before the conclusion was reached
% that one was inside the other), but these rules are valid regardless, and should prevent us
% from generating more nonsense on the decision branch where we concluded that one class was
% inside the other.  Hopefully we'll backtrack to a better solution.
% PAPER: Merging-9
reasonNOTMergeClasses_G(Class1, Class2) :-
    %% find(_Constructor1, Class1),
    %% find(_Constructor2, Class2),
    factObjectInObject(Class1, Class2, _Offset),
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_G('),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% PAPER: Merging-9
%% reasonNOTMergeClasses_H(Class1, Class2) :-
%%     find(_Constructor1, Class1),
%%     find(_Constructor2, Class2),
%%     factObjectInObject(Class2, Class1, _Offset),
%%     % Debugging
%%     not(factNOTMergeClasses(Class1, Class2)),
%%     not(factNOTMergeClasses(Class2, Class1)),
%%     debug('reasonNOTMergeClasses_H('),
%%     debug(Class1), debug(', '),
%%     debug(Class2), debugln(').'),
%%     true.

% Because RTTI tells us that they're different classes.
% XXX PAPER: RTTI
reasonNOTMergeClasses_I(Class1, Class2) :-
    rTTIEnabled,
    rTTIValid,
    rTTITDA2Class(TDA1, Class1),
    rTTITDA2Class(TDA2, Class2),
    iso_dif(TDA1, TDA2),
    % This shouldn't be needed unless rTTITDA2Class() is misbehaving!
    iso_dif(Class1, Class2),
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_I('),
    %debug(TDA1), debug(', '),
    %debug(TDA2), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% PAPER: Merging-13
% ED_PAPER_INTERESTING
reasonNOTMergeClasses_J(Class1, Class2) :-
    reasonDerivedClassRelationship(Class1, Class2),
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_J('),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% Because symbols tell us so.
% PAPER: XXX?
reasonNOTMergeClasses_K(Class1, Class2) :-
    symbolClass(Method1, ClassName1, _MethodName1),
    symbolClass(Method2, ClassName2, _MethodName2),
    iso_dif(Method1, Method2),
    iso_dif(ClassName1, ClassName2),
    find(Method1, Class1),
    find(Method2, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_K('),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% Because both classes already have a real destructor.
% PAPER: Merging-14
% PAPER: XXX Shouldn't this be a sanity check?
reasonNOTMergeClasses_L(Class1, Class2) :-
    factRealDestructor(RealDestructor1),
    factRealDestructor(RealDestructor2),
    iso_dif(RealDestructor1, RealDestructor2),
    find(RealDestructor1, Class1),
    find(RealDestructor2, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_L('),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% Because the sizes are incomaptible.
% PAPER: Class size constraints
reasonNOTMergeClasses_M(Class1, Class2) :-
    factClassSizeGTE(Class1, Size1),
    factClassSizeLTE(Class2, Size2),
    iso_dif(Class1, Class2),
    Size2 < Size1,
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_M('),
    %debug(Size1), debug(', '),
    %debug(Size2), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% Because the sizes are incomaptible.
% PAPER: Class size constraints
reasonNOTMergeClasses_N(Class1, Class2) :-
    factClassSizeLTE(Class1, Size1),
    factClassSizeGTE(Class2, Size2),
    iso_dif(Class1, Class2),
    Size2 > Size1,
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_N('),
    %debug(Size1), debug(', '),
    %debug(Size2), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% Because the method accesses members that aren't there.
% PAPER: Merging-15
% ED_PAPER_INTERESTING
reasonNOTMergeClasses_O(Class1, Class2) :-
    % There's a class where we know the maximum size.
    factClassSizeLTE(Class1, Size1),
    % That calls a method (not really needed but avoids worthless conclusions?)
    factClassCallsMethod(Class1, Method),
    find(Method, Class2),
    iso_dif(Class1, Class2),
    % The method accesses a member too large for the class.
    validMethodMemberAccess(_Insn, Method, MemberOffset, MemberSize),
    Size2 is MemberSize + MemberOffset,
    Size2 > Size1,
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_N('),
    %debug(Size1), debug(', '),
    %debug(Size2), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

% Because we call a constructor or destructor on part of our object.
% PAPER: ??? NEW!
% The reasoning is here is basically that we can't contain ourselves, but passing an offset to
% ourself would imply exactly that.  It's not obvious that the merger is blocked by any other
% rule at present.
reasonNOTMergeClasses_P(Class1, Class2) :-
    factMethod(Caller),
    factMethod(Method),
    iso_dif(Method, Caller),
    funcOffset(_Insn, Caller, Method, Offset),
    iso_dif(Offset, 0),
    (factConstructor(Method); factDeletingDestructor(Method); factRealDestructor(Method)),
    find(Method, Class1),
    find(Caller, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    %not(factNOTMergeClasses(Class1, Class2)),
    %not(factNOTMergeClasses(Class2, Class1)),
    %debug('reasonNOTMergeClasses_P('),
    %debug(Caller), debug(', '),
    %debug(Method), debug(', '),
    %debug(Class1), debug(', '),
    %debug(Class2), debugln(').'),
    true.

reasonNOTMergeClassesSet(Constructor, Set) :-
    factConstructor(Constructor),
    setof(Method, reasonNOTMergeClasses(Constructor, Method), Set).

% ============================================================================================
% Shared Implementations
% ============================================================================================

% Sometimes multiple functions share the same implementation (address).  This appears to be
% some kind of compiler optimization the occurs when the compiler detects that multiple bits of
% generated code are indentical.  This happens most frequently with deleting destructors but
% also occasionally with other code.  It's unclear if it's always generated code, or whether it
% could happen with user implemented functions as well.  Most of the rule amounts to a specific
% case where a method is "assigned" to two classes.
:- table reasonSharedImplementation/2 as incremental.
reasonSharedImplementation(Method, Class1) :-
    % There are two classes
    factConstructor(Constructor1),
    factConstructor(Constructor2),
    iso_dif(Constructor1, Constructor2),
    factVFTableWrite(_Insn1, Constructor1, _Offset1, VFTable1),
    factVFTableWrite(_Insn2, Constructor2, _Offset2, VFTable2),
    iso_dif(VFTable1, VFTable2),
    factVFTableEntry(VFTable1, _, Entry1),
    factVFTableEntry(VFTable2, _, Entry2),
    % Now that we have thunk data, the real question is:  Do Entry1 and Entry2 differ?
    dethunk(Entry1, Method),
    dethunk(Entry2, Method),
    % Limiting this rule to deleting destructors is a cheap proxy for generated code. :-(
    factDeletingDestructor(Method),
    find(Constructor1, Class1),
    find(Constructor2, Class2),
    iso_dif(Class1, Class2),
    factNOTMergeClasses(Class1, Class2).

% ============================================================================================
% Member assignment
% ============================================================================================

% In this new approach, we'll collect evidence later.

% --------------------------------------------------------------------------------------------
% Tabling this causes failures...
:- table certainMemberOnClass/3 as incremental.

certainMemberOnClass(Class, Offset, Size) :-
    factMethod(Method),
    find(Method, Class),
    validMethodMemberAccess(_Insn, Method, Offset, Size).

certainMemberOnClassSet(Class, Set) :-
    setof(Offset, Size^certainMemberOnClass(Class, Offset, Size), Set).

% --------------------------------------------------------------------------------------------
:- table certainMemberNOTOnExactClass/3 as incremental.

% The member is certain to be NOT on the exact class specified.  This rule is FLAWED!  The
% reasoning is supposed to be that the member is not on the exact class because it is within
% the memory range allocaed to and embedded object or base class (including multiple
% inhertiance).  The flaw in the logic is that it does not account for virtual inheritance
% correctly.  Specfically, the reasonMinimumPossibleClassSize(InnerClass, InnerSize)
% unification fails to reduce InnerSize by the size of the shared virtual grandparent class.
% Currently this results in a fairly rare bug, but it manifests in OOEX8 as an incorrect
% assignment of a class member.  It is believed that we will need virtual base pointer table
% facts to correctly resolve this situation, and we do not currently.
certainMemberNOTOnExactClass(Class, Offset, Size) :-
    certainMemberOnClass(Class, Offset, Size),
    factObjectInObject(Class, InnerClass, InnerOffset),
    Offset >= InnerOffset,
    reasonMinimumPossibleClassSize(InnerClass, InnerSize),
    EndOfInnerObject is InnerOffset + InnerSize,
    Offset < EndOfInnerObject.

% --------------------------------------------------------------------------------------------
:- table certainMemberOnExactClass/3 as incremental.

certainMemberOnExactClass(Class, Offset, Size) :-
    certainMemberOnClass(Class, Offset, Size),
    % Exclude members that are actually on the embedded objects or base classes.
    not(certainMemberNOTOnExactClass(Class, Offset, Size)).

certainMemberOnExactClassSet(Class, Set) :-
    setof(Offset, Size^certainMemberOnExactClass(Class, Offset, Size), Set).

% --------------------------------------------------------------------------------------------

% ============================================================================================
% Rules for class size reasoning.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% The given class is certain to be of this size or greater.  This is the allocation size,
% including any padding, alignment, etc.  It also includes the size of any base classes (since
% they're part of the class).
:- table reasonClassSizeGTE/2 as incremental.

:- table reasonClassSizeGTE_A/2 as incremental.
:- table reasonClassSizeGTE_B/2 as incremental.
:- table reasonClassSizeGTE_C/2 as incremental.
:- table reasonClassSizeGTE_D/2 as incremental.
:- table reasonClassSizeGTE_E/2 as incremental.
:- table reasonClassSizeGTE_F/2 as incremental.
:- table reasonClassSizeGTE_G/2 as incremental.

reasonClassSizeGTE(Class, Size) :-
    or([reasonClassSizeGTE_A(Class, Size),
        reasonClassSizeGTE_B(Class, Size),
        reasonClassSizeGTE_C(Class, Size),
        reasonClassSizeGTE_D(Class, Size),
        reasonClassSizeGTE_E(Class, Size),
        reasonClassSizeGTE_F(Class, Size),
        reasonClassSizeGTE_G(Class, Size)
      ]).

% Because it is already known to be true.
% PAPER: NA
reasonClassSizeGTE_A(Class, Size) :-
    factClassSizeGTE(Class, Size).

% Because all classes must have a non-negative size.
% PAPER: CSize-0
reasonClassSizeGTE_B(Class, 0) :-
    % Constrain this rule to proven methods, so we don't go assigning class sizes to methods
    % that aren't even really methods.
    factMethod(Method),
    find(Method, Class).

% Because a derived class is always greater than or equal to the size of it's base class.
% Actually, this rule should sum the sizes of all base classes that are known to be different
% from each other -- but that's a bit trickier.
% PAPER: CSize-1
reasonClassSizeGTE_C(Class, Size) :-
    reasonDerivedClassRelationship(Class, BaseClass),
    factClassSizeGTE(BaseClass, Size).

% The given class (associated with the constructor) is certain to be of this exact size.  The
% reasoning is that we're able to track an allocation site with a known size to the constructor
% associated with the class.  There's a small bit of ambiguity about what the compiler will
% generate for arrays of objects and other unusual cases, but this rule is a good start.
% PAPER: CSize-2
% ED_PAPER_INTERESTING
reasonClassSizeGTE_D(Class, Size) :-
    factConstructor(Constructor),
    thisPtrUsage(_, Function, ThisPtr, Constructor),
    thisPtrAllocation(_, Function, ThisPtr, type_Heap, Size),
    % We sometimes get bad (zero) class sizes in allocations.  This should really be fixed in
    % the fact exporter, so that we don't have to deal with it here.
    Size \= 0,
    find(Constructor, Class).

% The given class is certain to be of this size or greater.  The reasoning for this rule is
% that if we're certain that there's a member at a given offset and size, then the object must
% be larger enough to contain that access.
% PAPER: CSize-3
reasonClassSizeGTE_E(Class, Size) :-
    factMethod(Method),
    find(Method, Class),
    validMethodMemberAccess(_Insn, Method, MemberOffset, MemberSize),
    Size is MemberOffset + MemberSize,
    %debug('reasonClassSizeGTE_E('),
    %debug(Insn), debug(', '),
    %debug(Class), debug(', '),
    %debug(Size), debugln(').'),
    true.

% The given class is certain to be of this size or greater.  The reasoning for this rule is the
% if we're certain that there's a member at a given offset, and that member is certain to be an
% instance of a certain class (either inherited or embedded) the the enclosing class must be
% large enough to accomodate the minimize size of the contained object instance
% PAPER: CSize-4
reasonClassSizeGTE_F(Class, Size) :-
    %% find(_Method, Class),
    factObjectInObject(Class, InnerClass, Offset),
    factClassSizeGTE(InnerClass, InnerClassSize),
    Size is Offset + InnerClassSize.

% Because a virtual function table is installed at a given offset in the object.
% PAPER: CSize-5
reasonClassSizeGTE_G(Class, Size) :-
    factVFTableWrite(_Insn, Method, ObjectOffset, _VFTable),
    find(Method, Class),
    Size is ObjectOffset + 4,
    factClassSizeGTE(Class, ExistingSize),
    Size > ExistingSize.

reasonMinimumPossibleClassSize(Class, Size) :-
    setof(S, factClassSizeGTE(Class, S), Set),
    list_max(Set, Size),
    %debug('reasonMinimumPossibleClassSize('),
    %debug(Class), debug(', '),
    %debug(Size), debugln(').'),
    true.

% --------------------------------------------------------------------------------------------
:- table reasonClassSizeLTE/2 as incremental.

% The given class is certain to be of this size or smaller.

:- table reasonClassSizeLTE_A/2 as incremental.
:- table reasonClassSizeLTE_B/2 as incremental.
:- table reasonClassSizeLTE_C/2 as incremental.
:- table reasonClassSizeLTE_D/2 as incremental.

reasonClassSizeLTE(Class, Size) :-
    or([reasonClassSizeLTE_A(Class, Size),
        reasonClassSizeLTE_B(Class, Size),
        reasonClassSizeLTE_C(Class, Size),
        reasonClassSizeLTE_D(Class, Size)
      ]).

% Because it is already known to be true.
% PAPER: NA
reasonClassSizeLTE_A(Class, Size) :-
    factClassSizeLTE(Class, Size).

% PAPER: CSize-0
reasonClassSizeLTE_B(Class, 0x0fffffff) :-
    factConstructor(Constructor),
    find(Constructor, Class).

% The given class (associated with the constructor) is certain to be of this exact size.  The
% reasoning is that we're able to track an allocation site with a known size to the constructor
% associated with the class.  There's a small bit of ambiguity about what the compiler will
% generate for arrays of objects and other unusual cases, but this rule is a good start.
% PAPER: CSize-2
reasonClassSizeLTE_C(Class, Size) :-
    factConstructor(Constructor),
    find(Constructor, Class),
    thisPtrUsage(_, Function, ThisPtr, Constructor),
    thisPtrAllocation(_, Function, ThisPtr, type_Heap, Size),
    % We sometimes get bad (zero) class sizes in allocations.  This should really be fixed in
    % the fact exporter, so that we don't have to deal with it here.
    Size \= 0.

% The given class is certain to be of this size or smaller.  The reasoning is that a base class
% must always be smaller than or equal in size to it's derived classes.
% PAPER: CSize-1
reasonClassSizeLTE_D(Class, Size) :-
    reasonDerivedClassRelationship(DerivedClass, Class),
    factClassSizeLTE(DerivedClass, Size).

reasonMaximumPossibleClassSize(Class, Size) :-
    setof(S, factClassSizeLTE(Class, S), Set),
    list_min(Set, Size).

% --------------------------------------------------------------------------------------------
% These rules are intended to make it easier to report the size constraints on a specific
% class.  In most rules it's easier to accumulate a set of non-revocable assertions about the
% minimum and maximum sizes of the classes, but humans like to know just the most recent or
% significant constraint.   Use list_min and list_max to make that prettier.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
