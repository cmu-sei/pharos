% Copyright 2017-2020 Carnegie Mellon University.
% ============================================================================================
% Sanity checking rules
% ============================================================================================

% A virtual function table may not be assigned to two classes.
% PAPER: Sanity-VFTables
:- table insanityVFTableOnTwoClasses/0 as incremental.
insanityVFTableOnTwoClasses :-
    % There's some confusion about the object offset.  See the comments in rules.pl, and be
    % sure to keep this constraint in sync with the rule that merges classes.
    factVFTableWrite(_Insn1, Method1, ObjectOffset, VFTable),
    factVFTableWrite(_Insn2, Method2, ObjectOffset, VFTable),
    iso_dif(Method1, Method2),
    % I'm unsure why these are here...  I think to prevent premature triggering of this rule.
    % With the class-based rewrite of ClassHasNoBase, this entire rule may need rethinking.
    find(Method1, Class1),
    factClassHasNoBase(Class1),
    find(Method2, Class2),
    factClassHasNoBase(Class2),
    % Now there's yet another exception.  Inlined vftable writes from the base and derived
    % class in the same method.  Perhaps this sanity check rule isn't really what we want...
    not((possibleVFTableOverwrite(_, _, Method1, _, _, _);
         possibleVFTableOverwrite(_, _, Method2, _, _, _))),
    % If they're actually two constructors for the same class, that's ok.
    iso_dif(Class1, Class2),
    logwarnln('Consistency checks failed.'),
    logwarn('insanityVFTableOnTwoClasses failed:'),
    logwarn(' VFTable=~Q', VFTable),
    logwarn(' Method1=~Q', Method1),
    logwarnln(' Method2=~Q', Method2).

% A constructor may not be virtual.
% PAPER: Sanity-VirtualConstructor
:- table insanityConstructorInVFTable/0 as incremental.
insanityConstructorInVFTable :-
    factVFTableEntry(VFTable, Offset, Entry),
    dethunk(Entry, Constructor),
    factConstructor(Constructor),
    logwarnln('Consistency checks failed.'),
    logwarn('A constructor may not be virtual:'),
    logwarn(' VFTable=~Q', VFTable),
    logwarn(' Offset=~Q', Offset),
    logwarnln(' Ctor=~Q', Constructor).

% A class may not be derived from itself (even with intermediate classes).
% PAPER: Sanity-InheritanceLoop
:- table insanityInheritanceLoop/0 as incremental.
insanityInheritanceLoop :-
    reasonDerivedClassRelationship(DerivedClass, BaseClass),
    reasonDerivedClassRelationship(BaseClass, DerivedClass),
    logwarnln('Consistency checks failed.'),
    logwarn('A class may not be derived from itself:'),
    logwarn(' Class1=~Q', BaseClass),
    logwarnln(' Class2=~Q', DerivedClass).

% Classes may not have an invalid size.
% Perhaps this rule replaces all other size rules?
% PAPER: NA.  Handled by constraint system.
:- table insanityClassSizeInvalid/0 as incremental.
insanityClassSizeInvalid :-
    factClassSizeLTE(Class, LTESize),
    factClassSizeGTE(Class, GTESize),
    LTESize < GTESize,
    logwarnln('Consistency checks failed.'),
    logwarn('insanityClassSizeInvalid failed:'),
    logwarn(' Class=~Q', Class),
    logwarn(' LTESize=~Q', LTESize),
    logwarnln(' GTESize=~Q', GTESize).

% Roughly speaking, inheritance can only occur in an object when it is at offset zero, or there
% are inhertance objects that preceed it in the object layout.  It turns out that this rule was
% not true in cases of virtual inheritance, which can place ordinary members between the
% immediate base classes and the virtual base class, so this sanity check needed to be disabled
% again.  I've left the check in this file because the idea is still a good one, and the check
% probably just needs more refinement for the virtual inheritance case to be correct.
:- table insanityInheritanceAfterNonInheritance/0 as incremental.
insanityInheritanceAfterNonInheritance :-
    factDerivedClass(DerivedClass, BaseClass, Offset),
    not(
        (
            Offset = 0;
            factDerivedClass(DerivedClass, _LowerBaseClass, LowerOffset),
            LowerOffset < Offset
        )
    ),
    logwarnln('Consistency checks failed.'),
    logwarn('insanityInheritanceAfterInheritance failed:'),
    logwarn(' DerivedClass=~Q', DerivedClass),
    logwarn(' BaseClass=~Q', BaseClass),
    logwarnln(' Offset=~Q', Offset).

% VFTables may not have an invalid size.
% Perhaps this rule replaces all other size rules?
% PAPER: NA.  Handled by constraint system.
:- table insanityVFTableSizeInvalid/0 as incremental.
insanityVFTableSizeInvalid :-
    factVFTable(VFTable),
    factVFTableSizeLTE(VFTable, LTESize),
    factVFTableSizeGTE(VFTable, GTESize),
    LTESize < GTESize,
    logwarnln('Consistency checks failed.'),
    logwarn('insanityVFTableSizeInvalid failed:'),
    logwarn(' VFTable=~Q', VFTable),
    logwarn(' LTESize=~Q', LTESize),
    logwarnln(' GTESize=~Q', GTESize).

% The size of an embdded class may not exceed the size of the class it's in.
% PAPER: NA.  Handled by constraint system.
:- table insanityEmbeddedObjectLarger/0 as incremental.
insanityEmbeddedObjectLarger :-
    factEmbeddedObject(OuterClass1, InnerClass1, Offset),
    find(OuterClass1, OuterClass),
    find(InnerClass1, InnerClass),
    factClassSizeLTE(OuterClass, OuterSize),
    factClassSizeGTE(InnerClass, InnerSize),
    ComputedSize is Offset + InnerSize,
    OuterSize < ComputedSize,
    logwarnln('Consistency checks failed.'),
    logwarn('insanityEmbeddedObjectLarger failed:'),
    logwarn(' O_Class=~Q', OuterClass),
    logwarn(' O_Offset=~Q', Offset),
    logwarn(' O_Size=~Q', OuterSize),
    logwarn(' I_Class=~Q', InnerClass),
    logwarnln(' I_Size=~Q', InnerSize).

:- table insanityObjectCycle/0 as incremental.
insanityObjectCycle :-
    reasonClassRelationship(Class1, Class2),
    reasonClassRelationship(Class2, Class1),
    logwarnln('Consistency checks failed.'),
    logwarn('insanityObjectCycle failed:'),
    logwarn(' Class1=~Q', Class1),
    logwarnln(' Class2=~Q', Class2).

% PAPER: Sanity-EmbeddedLoop
% ejs: This is superseded by insanityObjectCycle
%% :- table insanityEmbeddedTrivialObjectCycle/0 as incremental.
%% insanityEmbeddedTrivialObjectCycle :-
%%     factObjectInObject(OuterClass, InnerClass, _Offset),
%%     find(OuterClass, SameClass),
%%     find(InnerClass, SameClass),
%%     logwarnln('Consistency checks failed.'),
%%     logwarn('insanityEmbeddedTrivialObjectCycle failed:'),
%%     logwarn(' Outer=~Q', OuterClass),
%%     logwarn(' Inner=~Q', InnerClass),
%%     logwarnln(' Same=~Q', SameClass).

% A member may not extend past the end of the object.
% PAPER: XXX Need to add member logic
:- table insanityMemberPastEndOfObject/0 as incremental.
insanityMemberPastEndOfObject :-
    certainMemberOnClass(Class, Offset, Size),
    ComputedSize is Offset + Size,
    factClassSizeLTE(Class, ObjectSize),
    ComputedSize > ObjectSize,
    logwarnln('Consistency checks failed.'),
    logwarn('insanityMemberPastEndObject failed:'),
    logwarn(' Class=~Q', Class),
    logwarn(' Offset=~Q', Offset),
    logwarn(' Size=~Q', Size),
    logwarnln(' ObjectSize=~Q', ObjectSize).

% The size of the virtual function table on a derived class may not be less than the size of
% the virtual function table on the base class.
% PAPER: Size-2
% XXX: Why isn't this a regular reasoning rule?
:- table insanityBaseVFTableLarger/0 as incremental.
insanityBaseVFTableLarger :-
    factVFTableWrite(_Insn1, DerivedConstructor, DerivedVFTable, ObjectOffset),
    factVFTableWrite(_Insn2, BaseConstructor, BaseVFTable, 0),
    find(DerivedConstructor, DerivedClass),
    find(BaseConstructor, BaseClass),
    factDerivedClass(DerivedClass, BaseClass, ObjectOffset),
    factVFTableSizeLTE(DerivedVFTable, DerivedSize),
    factVFTableSizeGTE(BaseVFTable, BaseSize),
    DerivedSize < BaseSize,
    logwarnln('Consistency checks failed.'),
    logwarnln('insanityBaseVFTableLarger failed:').

% A method may not be both a constructor and a real destructor.
% PAPER: Sanity-DoubleDuty
:- table insanityConstructorAndRealDestructor/0 as incremental.
insanityConstructorAndRealDestructor :-
    factConstructor(Method),
    factRealDestructor(Method),
    logwarnln('Consistency checks failed.'),
    logwarnln('A method may not be a constructor and real destructor:'),
    logwarnln(' Method=~Q', Method).


% A method may not be both a constructor and a deleting destructor.
% PAPER: Sanity-DoubleDuty
:- table insanityConstructorAndDeletingDestructor/0 as incremental.
insanityConstructorAndDeletingDestructor :-
    factConstructor(Method),
    factDeletingDestructor(Method),
    logwarnln('Consistency checks failed.'),
    logwarnln('A method may not be a constructor and deleting destructor:'),
    logwarnln(' Method=~Q', Method).

% A class may not have two real destructors.
% PAPER: Sanity-MultipleRealDestructors
:- table insanityTwoRealDestructorsOnClass/0 as incremental.
insanityTwoRealDestructorsOnClass :-
    factRealDestructor(Destructor1),
    factRealDestructor(Destructor2),
    iso_dif(Destructor1, Destructor2),
    find(Destructor1, Class),
    find(Destructor2, Class),
    logwarnln('Consistency checks failed.'),
    logwarnln('A class may not have more than one real destructor:'),
    logwarn(' Class=~Q', Class),
    logwarn(' Dtor1=~Q', Destructor1),
    logwarnln(' Dtor2=~Q', Destructor2).

% A method cannot be both merged and not merged into a class.
:- table insanityContradictoryMerges/0 as incremental.
insanityContradictoryMerges :-
    reasonMergeClasses(Method1, Method2),
    dynFactNOTMergeClasses(Method1, Method2),
    logwarnln('failed.'),
    logwarnln('Consistency checks failed.'),
    logwarn('Contradictory information about merging classes:'),
    logwarn(' Method1=~Q', Method1),
    logwarnln(' Method2=~Q', Method2).

:- table insanityEmbeddedAndNot/0 as incremental.
insanityEmbeddedAndNot :-
    factEmbeddedObject(A, B, C),
    factNOTEmbeddedObject(A, B, C),
    logwarnln('Consistency checks failed.'),
    logwarnln('Contradictory information about embedded objects: ~Q',
              factEmbeddedObject(A, B, C)).

:- table sanityChecks/0 as incremental.
sanityChecks :-
    not(insanityEmbeddedAndNot),
    not(insanityConstructorAndRealDestructor),
    %not(insanityVFTableOnTwoClasses),
    not(insanityConstructorInVFTable),
    not(insanityClassSizeInvalid),
    not(insanityVFTableSizeInvalid),
    not(insanityEmbeddedObjectLarger),
    not(insanityObjectCycle),
    %% not(insanityEmbeddedTrivialObjectCycle),
    not(insanityMemberPastEndOfObject),
    not(insanityBaseVFTableLarger),
    not(insanityConstructorAndDeletingDestructor),
    not(insanityInheritanceLoop),
    %not(insanityInheritanceAfterNonInheritance),
    not(insanityContradictoryMerges),
    not(insanityTwoRealDestructorsOnClass).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
