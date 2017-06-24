% Copyright 2017 Carnegie Mellon University.
% ============================================================================================
% Final reporting API.
% ============================================================================================

% Long ago, Ed wrote: A solution is <list of classes, a mapping of classes to methods, a
% mapping of classes to members, a mapping of each class to its immediate parents and offset, a
% list of vtables, mapping of vtables to class x offset x size, map of virtual function calls
% to classes and methods, special methods of class>.  Now it's more correct to say something
% like: "A solution is a list of finalXXX() predicates contained in this section".

% These rules are for formatting the results into "final" format.  These rules are not used for
% reasoning, and do not involve guessing or backtracking in any way.  As a consequence it's not
% obvious that they need to be tabled (although there's probably no harm in that).

% ejs: It sure would be nice if there was a consistent prolog library...

include(Goal, List, Included) :-
    include_(List, Goal, Included).

include_([], _, []).
include_([X1|Xs1], P, Included) :-
    (   call(P, X1)
        ->  Included = [X1|Included1]
        ;   Included = Included1
    ),
    include_(Xs1, P, Included1).

findallMethods(C, O) :- findall(C, L), include(factMethod, L, O).

% ============================================================================================
% Class Identification...
% ============================================================================================

% Once we've finished assigning methods to constructors, we can assign class identifiers.  This
% version of the rule is a bit nasty because we can't rely on multiple implementations of the
% rule and tabling to give us just one answer...   I think.

classIdentifier(Method, ID) :-
    (
        % Must be the VFTable at offset zero to be the "master" table for the class.
        find(Method, Class),
        find(Master, Class),
        factVFTableWrite(_Insn, Master, 0, VFTable),
        not(factVFTableOverwrite(VFTable, _PrimaryVFTable, 0))
    )
    ->
        ID is VFTable
    ;
    (
        find(Method, Class),
        find(RealDestructor, Class),
        factRealDestructor(RealDestructor)
    )
    ->
        ID is RealDestructor
    ;
    (
        findall(Method, MethodSet),
        %writeln('trying to pick class ID from method set...'),
        %write('picking class ID from method set:'), writeln(MethodSet),
        setof(C, (member(C, MethodSet), factConstructor(C)), ConstructorSet),
        %write('constructor set was:'), writeln(ConstructorSet),
        list_min(ConstructorSet, MinimumConstructor)
        %write('picked class ID:'), writeln(MinimumConstructor)
    )
    -> ID is MinimumConstructor
    ;
    (
        findall(Method, MethodSet),
        %writeln('trying to pick class ID from method set...'),
        %write('picking class ID from method set:'), writeln(MethodSet),
        list_min(MethodSet, MinimumMethod)
        %write('picked class ID:'), writeln(MinimumMethod)
    )
    -> ID is MinimumMethod.

% --------------------------------------------------------------------------------------------
% This final result defines the existance of a class.   More details in results.txt.
:- table finalClass/6 as incremental.
finalClass(ClassID, VFTableOrNull, CSize, LSize, RealDestructorOrNull, MethodList) :-
    find(Method, Class),
    reasonMethod(Method),
    not(purecall(Method)),
    classIdentifier(Class, ClassID),
    % If there's a certain VFTableWrite, use the VFTable value from it -- if not use zero.
    % Always pick the VFTable at offset zero, because that's the "master" one.
    ((find(XMethod, Class),
      factVFTableWrite(_Insn, XMethod, 0, VFTable),
      not(factVFTableOverwrite(VFTable, _PrimaryVFTable, 0))
     ) -> VFTableOrNull=VFTable; VFTableOrNull=0),
    % Get the certain and likely class sizes.
    reasonMinimumPossibleClassSize(Class, CSize),
    LSize is CSize,
    % Optionally find the the real destructor as well.
    ((factRealDestructor(RealDestructor),
      find(RealDestructor, Class))
     -> RealDestructorOrNull=RealDestructor; RealDestructorOrNull=0),
    findallMethods(Class, UnsortedMethodList),
    sort(UnsortedMethodList, MethodList).

% --------------------------------------------------------------------------------------------
% This final result defines the properties of a VFTable.   More details in results.txt.
:- table finalVFTable/5 as incremental.
finalVFTable(VFTable, CertainSize, LikelySize, RTTIAddressOrNull, RTTINameOrNull) :-
    factVFTable(VFTable),
    (reasonRTTIInformation(VFTable, RTTIAddress, RTTIName) ->
         RTTIAddressOrNull=RTTIAddress, RTTINameOrNull=RTTIName;
     RTTIAddressOrNull=0, RTTINameOrNull=''),
    findall(CertainOffset, factVFTableEntry(VFTable, CertainOffset, _Method), CertainOffsets),
    list_max(CertainOffsets, CertainMax),
    CertainSize is CertainMax + 4,
    % It's a little unclear what the likely size means in a proper guessing framework.
    LikelySize is CertainSize.
    %findall(LikelyOffset, likelyVFTableEntry(VFTable, LikelyOffset, _Method), LikelyOffsets),
    %list_max(LikelyOffsets, LikelyMax),
    %LikelySize is LikelyMax + 4.

% --------------------------------------------------------------------------------------------
:- table finalEmbeddedObject/4 as incremental.

% In the Outer class identifier at the specified offset is an object instance of the type
% specified by EmbeddedClass indeitifier.  The embedded object is not believed to be a base
% class (via an inheritance relationship), for that relationship see finalInheritance().
finalEmbeddedObject(OuterClass, Offset, EmbeddedClass, likely) :-
    factEmbeddedObject(OuterClass1, EmbeddedClass1, Offset),
    classIdentifier(OuterClass1, OuterClass),
    classIdentifier(EmbeddedClass1, EmbeddedClass),
    iso_dif(OuterClass, EmbeddedClass).

% --------------------------------------------------------------------------------------------
:- table finalInheritance/5 as incremental.

% In the Derived class at the specified offset is an object instance of the type specified by
% Base.  If the base class is not the first base class (non-zero offset) and the base class has
% a virtual function table, the VFTable field will contain the derived class instance of that
% virtual function table.
finalInheritance(DerivedClassID, BaseClassID, ObjectOffset, certain, VFTableOrNull) :-
    factDerivedClass(DerivedClass, BaseClass, ObjectOffset),
    classIdentifier(DerivedClass, DerivedClassID),
    classIdentifier(BaseClass, BaseClassID),
    factConstructor(DerivedConstructor),
    find(DerivedConstructor, DerivedClass),
    % Unify with the derived constructor to unify with the VFTable value.  In the new world of
    % proper guessing, it's possible that we don't have a VFTable.
    (factVFTableWrite(_Insn, DerivedConstructor, ObjectOffset, VFTable) ->
         VFTableOrNull = VFTable ; VFTableOrNull is 0).

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
%    % Don't report discarded classes.
%    not(discardedClass(DerivedClass)),
%    not(discardedClass(BaseClass)),
%    % Unify with a specific constructor to unify with the VFTable value.
%    classIdentifier(DerivedConstructor, DerivedClass),
%    not_exists(factVFTableWrite(_Insn, DerivedConstructor, ObjectOffset, _VFTable)).

% --------------------------------------------------------------------------------------------
:- table reportableCertainMemberAccess/4 as incremental.

% If we're certain that the member is in the object instance, and that the method that accessed
% it is assigned to that specific class, then it meets the criteria for finalMemberAccess.
reportableCertainMemberAccess(Class, Offset, Size, Insn) :-
    certainMemberInObjectInstance(Class, Offset, Size, Insn),
    % Don't report discarded classes.
    not(discardedClass(Class)),
    validMethodMemberAccess(Insn, Method, Offset, Size),
    % Either certain or likely methods are acceptable.  What we really mean is "assigned to".
    certainMethodOnClass(Class, Method).


% --------------------------------------------------------------------------------------------
:- table certainMemberAccessEvidence/4 as incremental.

% This performs poorly!  Fortunately it only seems to be required during final reporting, not
% during sanity checking...
certainMemberAccessEvidence(Constructor, Offset, Size, Insn) :-
    factConstructor(Constructor),
    certainMemberOnConstructorClass(Constructor, Offset, Size),
    factMethod(Method),
    methodsOnSameClass(Constructor, Method, _Class),
    validMethodMemberAccess(Insn, Method, Offset, Size).

% --------------------------------------------------------------------------------------------
:- table finalMemberAccess/4 as incremental.

% The member at Offset in Class was accessed using the given Size by the list of evidence
% instructions provided. The list of evidence instructions only contains instructions from the
% methods assigned to the class.  Other accesses of base class members will appear in the
% accesses for their respective classes.  There is no certainty field, which must be derived
% from the certainty of the method that the instruction is located in.  This certainty may vary
% for individual evidence instructions within the list.  Note that that presentation does not
% present knowledge about the class and subclass relationships particularly clearly.  For those
% opbservations refer to finalMember() instead.
finalMemberAccess(Class, Offset, Size, EvidenceList) :-
    certainMemberOnConstructorClass(Constructor, Offset, Size),
    classIdentifier(Constructor, Class),
    setof(I, certainMemberAccessEvidence(Constructor, Offset, Size, I), UnsortedEvidenceList),
    sort(UnsortedEvidenceList, EvidenceList).

% --------------------------------------------------------------------------------------------
:- table reportableLikelyMember/4 as incremental.

reportableLikelyMember(Class, Offset, Size, Insn) :-
    certainMemberInObjectInstance(Class, Offset, Size, Insn),
    % Don't report discarded classes.
    not(discardedClass(Class)).
reportableLikelyMember(Class, Offset, Size, Insn) :-
    likelyMemberOnClass(Class, Offset, Size, Insn),
    % Don't report discarded classes.
    not(discardedClass(Class)).

% --------------------------------------------------------------------------------------------
:- table finalMember/4 as incremental.

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
finalMember(Class, Offset, Sizes, certain) :-
    factConstructor(Constructor),
    certainMemberOnExactConstructorClass(Constructor, Offset, _Size),
    classIdentifier(Constructor, Class),
    setof(Size, certainMemberOnExactConstructorClass(Constructor, Offset, Size), UnsortedSizes),
    %subtract(UnsortedSizes, [0], FilteredSizes),
    %sort(FilteredSizes, Sizes).
    sort(UnsortedSizes, Sizes).

% ============================================================================================
% Final Method Properties
% ============================================================================================

% --------------------------------------------------------------------------------------------
:- table finalMethodProperty/3 as incremental.
% In many cases, no qualifiers of any kind are required for specific methods.  However, there
% are multiple properties of a method that can all be determined at different confidence levels
% independently.


% This result marks that a method is certain to be a constructor.  The certain field is
% currently scheduled for elimination.
finalMethodProperty(Method, constructor, certain) :-
    factConstructor(Method).

% --------------------------------------------------------------------------------------------
% This result marks that a method is certain to be a deleting destructor.  The certain field is
% currently scheduled for elimination..  The single method that is a real destructor for any
% given class is determined from the finalClass result.
finalMethodProperty(Method, deletingDestructor, certain) :-
    factDeletingDestructor(Method).

% --------------------------------------------------------------------------------------------
% At one point I had though that this was duplicative, and therefore should not be included in
% the output.  After having been annoyed by it's absence repeatedly, we're going to at least
% try it with it on for a while.
finalMethodProperty(Method, realDestructor, certain) :-
    factRealDestructor(Method).

% --------------------------------------------------------------------------------------------
% This result marks whether a method is believed to be virtual, and what our confidence in that
% assertion is.  It's likely that this is exactly equivalent to whether the method appears in
% any virtual function table, and what the confidence in that offset of that virtual function
% table is.  This fact may be equally easy to compute from the finalVFTable results after
% importation back into C++.   In that case, this result may be eliminated.

% The obvious rule is that if we're certain that the method is virtual, we should report so.
finalMethodProperty(Method, virtual, certain) :-
    (factVFTableEntry(_VFTable, _Offset, Method); symbolProperty(Method, virtual)),
    % But don't report purecall as virtual, because official symbols do not.
    not(purecall(Method)).

% This version of the rule is a little more subtle.  It says that we only need to report the
% cases where there's no certainty, even if the entry is in a different virtual function table.
%finalMethodProperty(Method, virtual, likely) :-
%    likelyVFTableEntry(_VFTableLikely, _OffsetLikely, Method),
%    not_exists(factVFTableEntry(_VFTableCertain, _OffsetCertain, Method)).

% Unimplemented rule: The subtly of the last case suggests that there might be a reasoning rule
% about transferring knowledge from one virtual function to another.  Specifically that the
% virtual function table of a Derived class must be as large (or larger than it's base class?)

% --------------------------------------------------------------------------------------------
:- table finalResolvedVirtualCall/3 as incremental.

% The call at Insn can be resolved to the Target through the virtual function table at VFTable.
% Most of the information describing a virtual function call is already avilable in C++ once
% you know the address of the call instruction.  This result communicates just the required
% information for simplicity and clarity.
finalResolvedVirtualCall(Insn, VFTable, Target) :-
    % Have we already confirmed that the Insn is legitimately a virtual function call?
    factVirtualFunctionCall(Insn, _Method, _ObjectOffset, VFTable, VFTableOffset),
    % Now actually resolve the call using the VftableOffset.
    factVFTableEntry(VFTable, VFTableOffset, Target).

% --------------------------------------------------------------------------------------------
profileme(X) :-
    solve(X),
    generateResults.

generateResults :-
    writeln('% Prolog results autogenerated by Objdigger.'),
    (setof((V1, C1, L1, A1, N1), finalVFTable(V1, C1, L1, A1, N1), _Set1); true),
    (setof((C2, V2, S2, L2, R2, M2), finalClass(C2, V2, S2, L2, R2, M2), _Set2); true),
    (setof((I3, V3, T3), finalResolvedVirtualCall(I3, V3, T3), _Set3); true),
    (setof((C4, O4, E4, X4), finalEmbeddedObject(C4, O4, E4, X4), _Set4); true),
    (setof((D5, B5, O5, C5, V5), finalInheritance(D5, B5, O5, C5, V5), _Set5); true),
    (setof((C6, O6, S6, L6), finalMember(C6, O6, S6, L6), _Set6); true),
    (setof((C7, O7, S7, E7), finalMemberAccess(C7, O7, S7, E7), _Set7); true),
    (setof((M8, P8, C8), finalMethodProperty(M8, P8, C8), _Set8); true),
    writeln('% Object detection reporting complete.').

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
