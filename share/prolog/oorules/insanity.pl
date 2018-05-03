% Copyright 2017 Carnegie Mellon University.
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
    debugln('failed.'),
    debug('insanityVFTableOnTwoClasses failed:'),
    debug(' VFTable='), debug(VFTable),
    debug(' Method1='), debug(Method1),
    debug(' Method2='), debug(Method2),
    debugln('').

% A constructor may not be virtual.
% PAPER: Sanity-VirtualConstructor
:- table insanityConstructorInVFTable/0 as incremental.
insanityConstructorInVFTable :-
    factVFTableEntry(VFTable, Offset, Entry),
    dethunk(Entry, Constructor),
    factConstructor(Constructor),
    debugln('failed.'),
    debugln('A constructor may not be virtual:'),
    debug(' VFTable='), debug(VFTable),
    debug(' Offset='), debug(Offset),
    debug(' Ctor='), debug(Constructor),
    debugln('').

% A class may not be derived from itself (even with intermediate classes).
% PAPER: Sanity-InheritanceLoop
:- table insanityInheritanceLoop/0 as incremental.
insanityInheritanceLoop :-
    reasonDerivedClassRelationship(DerivedClass, BaseClass),
    reasonDerivedClassRelationship(BaseClass, DerivedClass),
    debugln('failed.'),
    debugln('A class may not be derived from itself:'),
    debug(' Class1='), debug(BaseClass),
    debug(' Class2='), debug(DerivedClass),
    debugln('').

% Classes may not have an invalid size.
% Perhaps this rule replaces all other size rules?
% PAPER: NA.  Handled by constraint system.
:- table insanityClassSizeInvalid/0 as incremental.
insanityClassSizeInvalid :-
    factClassSizeLTE(Class, LTESize),
    factClassSizeGTE(Class, GTESize),
    LTESize < GTESize,
    debugln('failed.'),
    debug('insanityClassSizeInvalid failed:'),
    debug(' Class='), debug(Class),
    debug(' LTESize='), debug(LTESize),
    debug(' GTESize='), debug(GTESize),
    debugln('').

% VFTables may not have an invalid size.
% Perhaps this rule replaces all other size rules?
% PAPER: NA.  Handled by constraint system.
:- table insanityVFTableSizeInvalid/0 as incremental.
insanityVFTableSizeInvalid :-
    factVFTable(VFTable),
    factVFTableSizeLTE(VFTable, LTESize),
    factVFTableSizeGTE(VFTable, GTESize),
    LTESize < GTESize,
    debugln('failed.'),
    debug('insanityVFTableSizeInvalid failed:'),
    debug(' VFTable='), debug(VFTable),
    debug(' LTESize='), debug(LTESize),
    debug(' GTESize='), debug(GTESize),
    debugln('').

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
    debugln('failed.'),
    debug('insanityEmbeddedObjectLarger failed:'),
    debug(' O_Class='), debug(OuterClass),
    debug(' O_Offset='), debug(Offset),
    debug(' O_Size='), debug(OuterSize),
    debug(' I_Class='), debug(InnerClass),
    debug(' I_Size='), debug(InnerSize),
    debugln('').

% PAPER: Sanity-EmbeddedLoop
:- table insanityEmbeddedObjectCycle/0 as incremental.
insanityEmbeddedObjectCycle :-
    factObjectInObject(OuterClass, InnerClass, _Offset),
    find(OuterClass, SameClass),
    find(InnerClass, SameClass),
    debugln('failed.'),
    debug('insanityEmbeddedObjectCycle failed:'),
    debug(' Outer='), debug(OuterClass),
    debug(' Inner='), debug(InnerClass),
    debug(' Same='), debug(SameClass),
    debugln('').

% A member may not extend past the end of the object.
% PAPER: XXX Need to add member logic
:- table insanityMemberPastEndOfObject/0 as incremental.
insanityMemberPastEndOfObject :-
    certainMemberOnClass(Class, Offset, Size),
    ComputedSize is Offset + Size,
    factClassSizeLTE(Class, ObjectSize),
    ComputedSize > ObjectSize,
    debugln('failed.'),
    debug('insanityMemberPastEndObject failed:'),
    debug(' Class='), debug(Class),
    debug(' Offset='), debug(Offset),
    debug(' Size='), debug(Size),
    debug(' ObjectSize='), debug(ObjectSize),
    debugln('').

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
    debugln('failed.'),
    debug('insanityBaseVFTableLarger failed:'),
    debugln('').

% A method may not be both a constructor and a real destructor.
% PAPER: Sanity-DoubleDuty
:- table insanityConstructorAndRealDestructor/0 as incremental.
insanityConstructorAndRealDestructor :-
    factConstructor(Method),
    factRealDestructor(Method),
    debugln('failed.'),
    debugln('A method may not be a constructor and real destructor:'),
    debug(' Method='), debug(Method),
    debugln('').

% A method may not be both a constructor and a deleting destructor.
% PAPER: Sanity-DoubleDuty
:- table insanityConstructorAndDeletingDestructor/0 as incremental.
insanityConstructorAndDeletingDestructor :-
    factConstructor(Method),
    factDeletingDestructor(Method),
    debugln('failed.'),
    debugln('A method may not be a constructor and deleting destructor:'),
    debug(' Method='), debug(Method),
    debugln('').

% A class may not have two real destructors.
% PAPER: Sanity-MultipleRealDestructors
:- table insanityTwoRealDestructorsOnClass/0 as incremental.
insanityTwoRealDestructorsOnClass :-
    factRealDestructor(Destructor1),
    factRealDestructor(Destructor2),
    iso_dif(Destructor1, Destructor2),
    find(Destructor1, Class),
    find(Destructor2, Class),
    debugln('failed.'),
    debugln('A class may not have more than one real destructor:'),
    debug(' Class='), debug(Class),
    debug(' Dtor1='), debug(Destructor1),
    debug(' Dtor2='), debug(Destructor2),
    debugln('').

% A method cannot be both merged and not merged into a class.
:- table insanityContradictoryMerges/0 as incremental.
insanityContradictoryMerges :-
    reasonMergeClasses(Method1, Method2),
    (factNOTMergeClasses(Method1, Method2);
     factNOTMergeClasses(Method2, Method1)),
    debugln('failed.'),
    debug('Contradictory information about merging classes:'),
    debug(' Method1='), debug(Method1),
    debug(' Method2='), debugln(Method2).

:- table insanityEmbeddedAndNot/0 as incremental.
insanityEmbeddedAndNot :-
    factEmbeddedObject(A, B, C),
    factNOTEmbeddedObject(A, B, C),
    debugln('failed.'),
    debug('Contradictory information about embedded objects: factEmbeddedObject('),
    debug(A),
    debug(', '),
    debug(B),
    debug(', '),
    debug(C),
    debugln(')').

:- table sanityChecks/0 as incremental.
sanityChecks :-
    not(insanityEmbeddedAndNot),
    not(insanityConstructorAndRealDestructor),
    %not(insanityVFTableOnTwoClasses),
    not(insanityConstructorInVFTable),
    not(insanityClassSizeInvalid),
    not(insanityVFTableSizeInvalid),
    not(insanityEmbeddedObjectLarger),
    not(insanityEmbeddedObjectCycle),
    not(insanityMemberPastEndOfObject),
    not(insanityBaseVFTableLarger),
    not(insanityConstructorAndDeletingDestructor),
    not(insanityInheritanceLoop),
    not(insanityContradictoryMerges),
    not(insanityTwoRealDestructorsOnClass).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
