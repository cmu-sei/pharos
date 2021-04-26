% Copyright 2017-2020 Carnegie Mellon University.
% ============================================================================================
% Final reporting API.
% ============================================================================================

:- use_module(library(lists), [member/2, min_list/2, max_list/2]).

% Long ago, Ed wrote: A solution is <list of classes, a mapping of classes to methods, a
% mapping of classes to members, a mapping of each class to its immediate parents and offset, a
% list of vtables, mapping of vtables to class x offset x size, map of virtual function calls
% to classes and methods, special methods of class>.  Now it's more correct to say something
% like: "A solution is a list of finalXXX() predicates contained in this section".

% These rules are for formatting the results into "final" format.  These rules are not used for
% reasoning, and do not involve guessing or backtracking in any way.  As a consequence it's not
% obvious that they need to be tabled (although there's probably no harm in that).

% ejs: It sure would be nice if there was a consistent prolog library...

% ============================================================================================

% We've found that under some circumstances (see https://github.com/cmu-sei/pharos/issues/101)
% vftables can be reused on different classes.  We believe this is only when no methods are
% overridden. Here is an example.

%% Concluding factVFTableWrite(0x70d682, 0x70d650, 0, 0xa2c85c).
%% Concluding factVFTableWrite(0x70d147, 0x70d0a0, 0x16c, 0x9ae574).
%% Concluding factVFTableWrite(0x70d133, 0x70d0a0, 0, 0xa2c85c).

% Ed thought there were two possibilities:

%% 1. Both classes inherit from a common base class but don't override any functions. Class
%% 0x70d0a0 inherits from another class as well.

%% 2. Class 0x70d0a0 inherits from 0x70d650 and
%% another class, and does not override any methods from 0x70d650. Normally we'd see a vftable
%% overwrite, but since the vftables are the same we might not.

%% This predicate adds an extra check to make sure that there is exactly one class that claims
%% ownership of the VFTable.  Right now we only envision it being used in final.pl, hence the
%% name.
reasonPrimaryVFTableForClassFinal(V, C) :-
    nonvar(C),
    % Hey we found one!
    findVFTable(V, 0, C),
    !,
    % No one else better also claim it
    forall(findVFTable(V, 0, OC), C = OC).

% ============================================================================================
% Class Identification...
% ============================================================================================

% Once we've finished assigning methods to constructors, we can assign class identifiers.  This
% version of the rule is a bit nasty because we can't rely on multiple implementations of the
% rule and tabling to give us just one answer...   I think.

:- table classIdentifier/2 as opaque.

classIdentifier(Method, ID) :-
    var(Method),
    nonvar(ID),
    throw_with_backtrace(error(instantiation_error, classIdentifier/2)).

classIdentifier(Method, ID) :-
    find(Method, Class),
    ((
        % Must be the VFTable at offset zero to be the "master" table for the class.
        reasonPrimaryVFTableForClassFinal(VFTable, Class),
        logtraceln('Setting classID of ~Q to primary vftable ~Q', [Class, VFTable]),
        true
    )
    ->
        ID is VFTable
    ;
    % This will use any VFTable on the class as an identifier but only if there is a single
    % VFTable.
    (
        once((findVFTable(VFTable, Class),
              forall(findVFTable(OtherVFTable, Class),
                     VFTable = OtherVFTable),
              logtraceln('Setting classID of ~Q to only vftable ~Q', [Class, VFTable])))
    ) ->
        ID is VFTable
    ;
    (
        find(RealDestructor, Class),
        factRealDestructor(RealDestructor),
        logtraceln('Setting classID of ~Q to real destructuor ~Q', [Class, RealDestructor]),
        true
    )
    ->
        ID is RealDestructor
    ;
    (
        findallMethods(Class, MethodSet),
        %logwarnln('trying to pick class ID from method set1 ...'),
        %logwarnln('picking class ID from method set: ~Q', MethodSet),
        setof(C, (member(C, MethodSet), factConstructor(C)), ConstructorSet),
        %logwarnln('constructor set was: ~Q', ConstructorSet),
        min_list(ConstructorSet, MinimumConstructor),
        logtraceln('Setting classID of ~Q to minimum constructor ~Q', [Class, MinimumConstructor]),
        true
    )
    -> ID is MinimumConstructor
    ;
    (
        findallMethods(Method, MethodSet),
        %logwarnln('trying to pick class ID from method set2 ...'),
        %logwarnln('picking class ID from method set: ~Q', MethodSet),
        min_list(MethodSet, MinimumMethod),
        logtraceln('Setting classID of ~Q to minimum method ~Q', [Class, MinimumMethod]),
        true
    )
    -> ID is MinimumMethod).

% --------------------------------------------------------------------------------------------
% A helper for identifying "worthless" classes to reduce noise in the output.
:- table worthlessClass/1 as opaque.

% A class is useful if it appears in a relationship.
usefulClass(Class) :-
    factEmbeddedObject(_, Class, _);
    factEmbeddedObject(Class, _, _);
    factDerivedClass(_, Class, _);
    factDerivedClass(Class, _, _).

% A class is useful if it has a VFTable.
usefulClass(Class) :-
    findVFTable(_VFTable, Class).

% A class is useful if it is not size zero.
usefulClass(Class) :-
    reasonMinimumPossibleClassSize(Class, Size), Size > 0.

% A class containing a constructor is useful.
usefulClass(Class) :-
    findMethod(Method, Class),
    factConstructor(Method).

% A class containing a real destructor is useful.
usefulClass(Class) :-
    findMethod(Method, Class),
    factRealDestructor(Method).

% A class with more than one method is useful.
usefulClass(Class) :-
    findallMethods(Class, List),
    length(List, Len),
    Len > 1.

% We want to reject classes with no useful information.  In practice this means having a single
% method, and no other "useful" data like a real destructor, a vftable, etc.  Sadly the final
% class rule is pretty complicated, this rule is largely a copy of that rule.  Maybe in the
% future we can find some witty way to structure this that results in better code reuse.
worthlessClass(Class) :-
    var(Class),
    throw_with_backtrace(error(instantiation_error, worthlessClass/1)).

% A class is worthless if (1) it's not useful, or (2) consists only of purecall.
worthlessClass(Class) :-
    not(usefulClass(Class)),
    !,
    logtraceln('Rejecting worthless finalClass ~Q', [Class]).

worthlessClass(Class) :-
    purecall(Class),
    is_singleton(Class),
    !,

    logtraceln('Rejecting worthless finalClass ~Q because it contains purecall and is a singleton', [Class]).

finalFileInfo(FileMD5, Filename) :-
   fileInfo(FileMD5, Filename).

% --------------------------------------------------------------------------------------------
% This final result defines the existance of a class.   More details in results.txt.
%:- finalClass/6 as incremental.
finalClass(ClassID, VFTableOrNull, CSize, LSize, RealDestructorOrNull, MethodList) :-
    class(Class),
    not(worthlessClass(Class)),
    classIdentifier(Class, ClassID),
    % If there's a certain VFTableWrite, use the VFTable value from it.  On the other hand if
    % there is a single VFTable in the class, use that.  Otherwise return zero (null).
    ((findVFTable(VFTable, 0, Class);
      (findVFTable(VFTable, Class),
       forall(findVFTable(OtherVFTable, Class), VFTable = OtherVFTable)))
     ->
         VFTableOrNull=VFTable
     ;
     VFTableOrNull=0),
    % Get the certain and likely class sizes.
    reasonMinimumPossibleClassSize(Class, CSize),
    LSize is CSize,
    % Optionally find the the real destructor as well.
    ((find(RealDestructor, Class),
      factRealDestructor(RealDestructor))
     -> RealDestructorOrNull=RealDestructor; RealDestructorOrNull=0),
    findallMethods(Class, UnsortedMethodList),
    sort(UnsortedMethodList, MethodList).

% --------------------------------------------------------------------------------------------
% This final result defines the properties of a VFTable.   More details in results.txt.
%:- finalVFTable/5 as incremental.
finalVFTable(VFTable, CertainSize, LikelySize, RTTIAddressOrNull, RTTINameOrNull) :-
    factVFTable(VFTable),
    (reasonRTTIInformation(VFTable, RTTIAddress, RTTIName) ->
         RTTIAddressOrNull=RTTIAddress, RTTINameOrNull=RTTIName;
     RTTIAddressOrNull=0, RTTINameOrNull=''),
    findall(CertainOffset, factVFTableEntry(VFTable, CertainOffset, _Method), CertainOffsets),
    max_list(CertainOffsets, CertainMax),
    CertainSize is CertainMax + 4,
    % It's a little unclear what the likely size means in a proper guessing framework.
    LikelySize is CertainSize.

finalVFTableEntry(VFTable, Offset, Method) :-
    factVFTableEntry(VFTable, Offset, Method).

% --------------------------------------------------------------------------------------------
%:- finalVBTable/4 as incremental.
finalVBTable(VBTable, Class, Size, Offset) :-
    factVBTable(VBTable),
    factVBTableWrite(_Insn, Method, Offset, VBTable),
    findall(CertainOffset, factVBTableEntry(VBTable, CertainOffset, _Value), CertainOffsets),
    max_list(CertainOffsets, Size),
    classIdentifier(Method, Class).

finalVBTableEntry(VBTable, Offset, Value) :-
    factVBTableEntry(VBTable, Offset, Value).

% --------------------------------------------------------------------------------------------
%:- finalEmbeddedObject/4 as incremental.

% In the Outer class identifier at the specified offset is an object instance of the type
% specified by EmbeddedClass indeitifier.  The embedded object is not believed to be a base
% class (via an inheritance relationship), for that relationship see finalInheritance().
finalEmbeddedObject(OuterClass, Offset, EmbeddedClass, likely) :-
    factEmbeddedObject(OuterClass1, EmbeddedClass1, Offset),
    classIdentifier(OuterClass1, OuterClass),
    classIdentifier(EmbeddedClass1, EmbeddedClass),
    iso_dif(OuterClass, EmbeddedClass).

% --------------------------------------------------------------------------------------------
%:- finalInheritance/5 as incremental.

% In the Derived class at the specified offset is an object instance of the type specified by
% Base.  If the base class is not the first base class (non-zero offset) and the base class has
% a virtual function table, the VFTable field will contain the derived class instance of that
% virtual function table.
finalInheritance(DerivedClassID, BaseClassID, ObjectOffset, VFTableOrNull, false) :-
    factDerivedClass(DerivedClass, BaseClass, ObjectOffset),

    % The following line stops us from reporting inheritances from A to C if there is also a
    % relation from A to B and B to C.  We have this because virtual inheritance is known to
    % introduce "false" A to C relationships depending on the order that guessing occurs in.
    once((not((factDerivedClass(DerivedClass, OtherClass, _Off1), factDerivedClass(OtherClass, BaseClass, _Off2))),

          classIdentifier(DerivedClass, DerivedClassID),
          classIdentifier(BaseClass, BaseClassID),

          % Try to identify the relevant VFTable
          ((find(VFTable, DerivedClass),
            factVFTableWrite(_Insn, DerivedConstructor, ObjectOffset, VFTable),
            find(DerivedConstructor, DerivedClass))
           ->
               VFTableOrNull = VFTable
           ;
           VFTableOrNull is 0))).

% Cory's a little uncertain about this rule because it's unclear if we'll ever assert a certain
% inheritance relationship without the virtual table fact that would trigger the rule above.
% Specifically, there's currently no likelyDerivedConstructor() or likelyDerivedClass(), and
% it's unclear that there ever will be.  Perhaps we'll end up guessing based on knowing that
% both are constructors, and on calls the other, and there's no contradictory member access.
% Or something equally complicated.  For now, we'll just use the confidence field to indicate
% that there's not a virtual function table in this result, but I don't think this rule can
% ever trigger currently either.
%finalInheritance(DerivedClass, BaseClass, ObjectOffset, likely, 0) :-
%    certainDerivedClass(DerivedClass, BaseClass, ObjectOffset),
%    % Unify with a specific constructor to unify with the VFTable value.
%    classIdentifier(DerivedConstructor, DerivedClass),
%    not_exists(factVFTableWrite(_Insn, DerivedConstructor, ObjectOffset, _VFTable)).

% --------------------------------------------------------------------------------------------
%%:- certainMemberAccessEvidence/4 as incremental.

% Find all methods that access offsets in the class.
certainMemberAccessEvidence(Class, Offset, Size, Insn) :-
    certainMemberOnClass(Class, Offset, Size),
    find(Method, Class),
    factMethod(Method),
    validMethodMemberAccess(Insn, Method, Offset, Size).

% --------------------------------------------------------------------------------------------
%:- finalMemberAccess/4 as incremental.

% The member at Offset in Class was accessed using the given Size by the list of evidence
% instructions provided. The list of evidence instructions only contains instructions from the
% methods assigned to the class.  Other accesses of base class members will appear in the
% accesses for their respective classes.  There is no certainty field, which must be derived
% from the certainty of the method that the instruction is located in.  This certainty may vary
% for individual evidence instructions within the list.  Note that that presentation does not
% present knowledge about the class and subclass relationships particularly clearly.  For those
% opbservations refer to finalMember() instead.
finalMemberAccess(ClassID, Offset, Size, EvidenceList) :-
    certainMemberOnClass(Class, Offset, Size),
    not(worthlessClass(Class)),
    classIdentifier(Class, ClassID),
    setof(I, certainMemberAccessEvidence(Class, Offset, Size, I), UnsortedEvidenceList),
    sort(UnsortedEvidenceList, EvidenceList).

% --------------------------------------------------------------------------------------------
%:- finalMember/4 as incremental.

% The finalMember() result documents the existence of the definition of a member on a specific
% class.  The intention (possibly with a currently incorrect implementation) is that we will
% only report the members defined on the class from a C++ source code perspective.  The Class
% is specified with a class identifier (not a constructor address or other specific type of
% address).  Offset is the positive offset into the specified class (and not it's base or
% embedded classes).  Sizes is a list of all the different sizes through which the member has
% been accessed anywhere in the program.  The final field indicates our confidence in the
% existence of member, and may be 'certain' or 'likely'.  Embedded object and inherited bases
% are not listed again as finalMembers.  Instead they are list in the finalEmbeddedObject and
% finalInheritance results.
finalMember(ClassID, Offset, Sizes, certain) :-
    certainMemberOnExactClass(Class, Offset, EarlySize),
    not(worthlessClass(Class)),
    classIdentifier(Class, ClassID),
    setof(Size, certainMemberOnExactClass(Class, Offset, Size), UnsortedSizes),
    %subtract(UnsortedSizes, [0], FilteredSizes),
    %sort(FilteredSizes, Sizes).
    sort(UnsortedSizes, Sizes),
    % As a hack to prevent us from outputting a Class, Offset multiple times, only proceed if
    % EarlySize == Sizes[0]
    UnsortedSizes = [EarlySize|_].


% ============================================================================================
% Final Method Properties
% ============================================================================================

% --------------------------------------------------------------------------------------------
%:- finalMethodProperty/3 as incremental.
% In many cases, no qualifiers of any kind are required for specific methods.  However, there
% are multiple properties of a method that can all be determined at different confidence levels
% independently.


% This result marks that a method is certain to be a constructor.  The certain field is
% currently scheduled for elimination.
finalMethodProperty(Method, constructor, certain) :-
    factConstructor(Method),
    find(Method, Class),
    not(worthlessClass(Class)).

% --------------------------------------------------------------------------------------------
% This result marks that a method is certain to be a deleting destructor.  The certain field is
% currently scheduled for elimination..  The single method that is a real destructor for any
% given class is determined from the finalClass result.
finalMethodProperty(Method, deletingDestructor, certain) :-
    factDeletingDestructor(Method),
    find(Method, Class),
    not(worthlessClass(Class)).

% --------------------------------------------------------------------------------------------
% At one point I had though that this was duplicative, and therefore should not be included in
% the output.  After having been annoyed by it's absence repeatedly, we're going to at least
% try it with it on for a while.
finalMethodProperty(Method, realDestructor, certain) :-
    factRealDestructor(Method),
    find(Method, Class),
    not(worthlessClass(Class)).

% --------------------------------------------------------------------------------------------
% This result marks whether a method is believed to be virtual, and what our confidence in that
% assertion is.  It's likely that this is exactly equivalent to whether the method appears in
% any virtual function table, and what the confidence in that offset of that virtual function
% table is.  This fact may be equally easy to compute from the finalVFTable results after
% importation back into C++.   In that case, this result may be eliminated.

% The obvious rule is that if we're certain that the method is virtual, we should report so.
finalMethodProperty(Method, virtual, certain) :-
    % By unifying Method first, we make sure that we don't produce duplicate results.  It may
    % not be the most efficient thing to do here.
    factMethod(Method),
    once((symbolProperty(Method, virtual);
          (factMethodInVFTable(_VFTable, _Offset, Method), not(symbolProperty(Method, virtual))))),
    find(Method, Class),
    not(worthlessClass(Class)),
    not(purecall(Method)).

% Unimplemented rule: There might be a reasoning rule about transferring knowledge from one
% virtual function to another.  Specifically that the virtual function table of a Derived class
% must be as large (or larger than it's base class?)

% --------------------------------------------------------------------------------------------
%:- finalResolvedVirtualCall/3 as incremental.

% The call at Insn can be resolved to the Target through the virtual function table at VFTable.
% Most of the information describing a virtual function call is already avilable in C++ once
% you know the address of the call instruction.  This result communicates just the required
% information for simplicity and clarity.
finalResolvedVirtualCall(Insn, VFTable, Target) :-
    % Have we already confirmed that the Insn is legitimately a virtual function call?
    factVirtualFunctionCall(Insn, _Method, _ObjectOffset, VFTable, VFTableOffset),
    % Now actually resolve the call using the VftableOffset.
    factVFTableEntry(VFTable, VFTableOffset, Entry),
    dethunk(Entry, Target).

% --------------------------------------------------------------------------------------------
%:- table finalThunk/2 as incremental.
finalThunk(From, To) :-
    % First there needs to be a thunk.
    thunk(From, To),
    % But it also needs to appear in a finalVFTableEntry.
    once(finalVFTableEntry(_Address, _Offset, From)),
    % And the target needs to be associated with finalClass method.
    once((finalClass(_ClassID, _VFTable, _MinSize, _MaxSize, _RealDestructor, MethodList),
          member(To, MethodList))),

    % Is this approach more efficient?  Less accurate because of worthless classes?
    % find(To, _ClassID),
    true.

% --------------------------------------------------------------------------------------------
%:- table finalDemangledName/4 as incremental.
finalDemangledName(Address, MangledName, ClassName, '') :-
    rTTITypeDescriptor(TDA, _Unclear, MangledName, ClassName),
    rTTITDA2VFTable(TDA, Address),
    finalClass(_ClassID, Address, _MinSize, _MaxSize, _RealDestructor, _MethodList).
finalDemangledName(Address, MangledName, ClassName, MethodName) :-
    finalClass(_ClassID, _VFTable, _MinSize, _MaxSize, _RealDestructor, MethodList),
    member(Address, MethodList),
    symbolClass(Address, MangledName, ClassName, MethodName).

% --------------------------------------------------------------------------------------------

generateResults :-
    writeln('% Prolog results autogenerated by OOAnalyzer.'),
    (setof((M3, N2), finalFileInfo(M3, N2), _Set0); true),
    (setof((V1, C1, L1, A1, N1), finalVFTable(V1, C1, L1, A1, N1), _Set1); true),
    (setof((C2, V2, S2, L2, R2, M2), finalClass(C2, V2, S2, L2, R2, M2), _Set2); true),
    (setof((I3, V3, T3), finalResolvedVirtualCall(I3, V3, T3), _Set3); true),
    (setof((C4, O4, E4, X4), finalEmbeddedObject(C4, O4, E4, X4), _Set4); true),
    (setof((D5, B5, O5, C5, V5), finalInheritance(D5, B5, O5, C5, V5), _Set5); true),
    (setof((C6, O6, S6, L6), finalMember(C6, O6, S6, L6), _Set6); true),
    (setof((C7, O7, S7, E7), finalMemberAccess(C7, O7, S7, E7), _Set7); true),
    (setof((M8, P8, C8), finalMethodProperty(M8, P8, C8), _Set8); true),
    writeln('% Object detection reporting complete.'),
    reportStage('Complete'),
    ws_end.

%% Local Variables:
%% mode: prolog
%% End:
