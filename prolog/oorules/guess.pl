% Copyright 2017 Carnegie Mellon University.
% ============================================================================================
% Guessing rules.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% Try guessing that a virtual function call is correctly interpreted.
% --------------------------------------------------------------------------------------------
guessVirtualFunctionCall :-
    likelyVirtualFunctionCall(Insn, Constructor, OOffset, VFTable, VOffset),
    not(factNOTConstructor(Constructor)),
    not(factVirtualFunctionCall(Insn, Constructor, OOffset, VFTable, VOffset)),
    not(factNOTVirtualFunctionCall(Insn, Constructor, OOffset, VFTable, VOffset)),
    (
        tryVirtualFunctionCall(Insn, Constructor, OOffset, VFTable, VOffset);
        tryNOTVirtualFunctionCall(Insn, Constructor, OOffset, VFTable, VOffset);
        debug('Something is wrong upstream: invalidVirtualFunctionCall('),
        debug(Insn), debugln(').'),
        fail
    ).

tryVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset) :-
    debug('Guessing factVirtualFunctionCall('),
    debug(Insn), debug(', '),
    debug(Method), debug(', '),
    debug(OOffset), debug(', '),
    debug(VFTable), debug(', '),
    debug(VOffset), debugln(') ... '),
    try_assert(factVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset)),
    try_assert(guessedVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset)).

tryNOTVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset) :-
    debug('Guessing factNOTVirtualFunctionCall('),
    debug(Insn), debug(', '),
    debug(Method), debug(', '),
    debug(OOffset), debug(', '),
    debug(VFTable), debug(', '),
    debug(VOffset), debugln(') ... '),
    try_assert(factNOTVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset)),
    try_assert(guessedNOTVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset)).

% --------------------------------------------------------------------------------------------
% Try guessing that a virtual function table is correctly identified.
% --------------------------------------------------------------------------------------------
guessVFTable :-
    % See the commentary at possibleVFTable for how this goal constrains our guesses (and
    % ordering).
    possibleVFTable(VFTable),
    not(factVFTable(VFTable)),
    not(factNOTVFTable(VFTable)),
    (
        tryVFTable(VFTable);
        tryNOTVFTable(VFTable);
        debug('Something is wrong upstream: invalidVFTable('),
        debug(VFTable), debugln(').'),
        fail
    ).

tryVFTable(VFTable) :-
    debug('Guessing factVFTable('), debug(VFTable), debugln(') ... '),
    try_assert(factVFTable(VFTable)),
    try_assert(guessedVFTable(VFTable)).

tryNOTVFTable(VFTable) :-
    debug('Guessing factNOTVFTable('), debug(VFTable), debugln(') ... '),
    try_assert(factNOTVFTable(VFTable)),
    try_assert(guessedNOTVFTable(VFTable)).

% --------------------------------------------------------------------------------------------
% Try guessing that a virtual function table entry is valid.
% --------------------------------------------------------------------------------------------
prioritizedVFTableEntry(VFTable, Offset, Method) :-
    % First establish that the guess meets minimal requirements.
    possibleVFTableEntry(VFTable, Offset, Method),
    factVFTable(VFTable),

    % We should really be able to enforce known methods here, but sadly in the current test
    % suite we cannot, because a few tests rely on guessing the last member of the VFTable. :-(
    % Probably the next thing to try is exporting thisCall(Method) facts from OOAnalyzer, so
    % that we know which guesses are better than garbage.  In other words, guess factMethod()
    % first based on something otehr than the VFtableEntry.  In the meantime leave it out.

    % (factMethod(Method); purecall(Method)),

    % Then that it's not already proved or disproved.
    not(factVFTableEntry(VFTable, Offset, Method)),
    not(reasonNOTVFTableEntry(VFTable, Offset, Method)).

% --------------------------------------------------------------------------------------------
guessVFTableEntry :-
    % Choose a prioritized VFTable entry to guess.
    prioritizedVFTableEntry(VFTable, Offset, Method),
    % Prioritize guessing the largest likely offset first.  This clause leads to make fewer
    % guesses that that imply all of the smaller offsets.  This turns out to be important from
    % a performance perspective because it reduces the number of times we need to check the
    % entire system against the valid solution constraints.
    not((prioritizedVFTableEntry(VFTable, LargerOffset, _OtherMethod), LargerOffset > Offset)),
    (
        tryVFTableEntry(VFTable, Offset, Method);
        tryNOTVFTableEntry(VFTable, Offset, Method);
        debug('Something is wrong upstream: invalidVFTableEntry('),
        debug(VFTable), debug(', '),
        debug(Offset), debug(', '),
        debug(Method), debugln(').'),
        fail
    ).

guessVFTableEntry :-
    % Choose a prioritized VFTable entry to guess.
    prioritizedVFTableEntry(VFTable, Offset, Method),
    % Prioritize guessing the largest likely offset first.  This clause leads us to make fewer
    % guesses that that imply all of the smaller offsets.  This turns out to be important from
    % a performance perspective because it reduces the number of times we need to check the
    % entire system against the valid solution constraints.  It works in part because
    % prioritizedVFTable entry is not tabled, and gradually block more choides based on
    % currently asserted facts.
    not((prioritizedVFTableEntry(VFTable, LargerOffset, _OtherMethod), LargerOffset > Offset)),
    tryVFTableEntryNOTVFTableEntry(VFTable, Offset, Method).

tryVFTableEntryNOTVFTableEntry(VFTable, Offset, Method) :-
    not(factVFTableEntry(VFTable, Offset, Method)),
    not(factNOTVFTableEntry(VFTable, Offset, Method)),
    (
        tryVFTableEntry(VFTable, Offset, Method);
        tryNOTVFTableEntry(VFTable, Offset, Method);
        debug('Something is wrong upstream: invalidVFTableEntry('),
        debug(VFTable), debug(', '),
        debug(Offset), debug(', '),
        debug(Method), debugln(').'),
        fail
    ).

tryVFTableEntry(VFTable, Offset, Method) :-
    debug('Guessing factVFTableEntry('),
    debug(VFTable), debug(', '),
    debug(Offset), debug(', '),
    debug(Method), debugln(') ... '),
    try_assert(factVFTableEntry(VFTable, Offset, Method)),
    try_assert(guessedVFTableEntry(VFTable, Offset, Method)).

tryNOTVFTableEntry(VFTable, Offset, Method) :-
    debug('Guessing factNOTVFTableEntry('),
    debug(VFTable), debug(', '),
    debug(Offset), debug(', '),
    debug(Method), debugln(') ... '),
    try_assert(factNOTVFTableEntry(VFTable, Offset, Method)),
    try_assert(guessedNOTVFTableEntry(VFTable, Offset, Method)).

% --------------------------------------------------------------------------------------------
% Try guessing that an embedded object offset zero is really an inheritance relationship.
% --------------------------------------------------------------------------------------------
guessDerivedClass :-
    % It's a little unclear if we want to limit this to offset zero, or accept all embedded
    % objects as base classes.  At present, we're back to accepting all classes.
    % Offset = 0,
    factObjectInObject(DerivedClass, BaseClass, Offset),
    not(factDerivedClass(DerivedClass, BaseClass, Offset)),
    not(factEmbeddedObject(DerivedClass, BaseClass, Offset)),
    (
        tryDerivedClass(DerivedClass, BaseClass, Offset);
        debug('Guess of DerivedClasss'), debug(DerivedClass), debug(', '),
        debug(BaseClass), debug(', '), debug(Offset), debugln(') failed!'),
        tryEmbeddedObject(DerivedClass, BaseClass, Offset);
        debug('Something is wrong upstream: invalidDerivedClass('),
        debug(DerivedClass), debug(', '),
        debug(BaseClass), debug(', '),
        debug(Offset), debugln(').'),
        fail
    ).

tryDerivedClass(DerivedClass, BaseClass, Offset) :-
    debug('Guessing factDerivedClass('),
    debug(DerivedClass), debug(', '),
    debug(BaseClass), debug(', '),
    debug(Offset), debugln(') ... '),
    try_assert(factDerivedClass(DerivedClass, BaseClass, Offset)),
    try_assert(guessedDerivedClass(DerivedClass, BaseClass, Offset)).

guessEmbeddedObject :-
    % It's very clear that we don't want to restrict embedded objects to offset zero.  Perhaps
    % we'll eventually find that this rule and guessDerivedClass are really the same.
    factObjectInObject(DerivedClass, BaseClass, Offset),
    not(factDerivedClass(DerivedClass, BaseClass, Offset)),
    not(factEmbeddedObject(DerivedClass, BaseClass, Offset)),
    (
        % Only here we're guessing embedded object first!
        tryEmbeddedObject(DerivedClass, BaseClass, Offset);
        tryDerivedClass(DerivedClass, BaseClass, Offset);
        debug('Something is wrong upstream: invalidEmbeddedObject('),
        debug(DerivedClass), debug(', '),
        debug(BaseClass), debug(', '),
        debug(Offset), debugln(').'),
        fail
    ).

tryEmbeddedObject(OuterClass, InnerClass, Offset) :-
    debug('Guessing factEmbeddedObject('),
    debug(OuterClass), debug(', '),
    debug(InnerClass), debug(', '),
    debug(Offset), debugln(') ... '),
    try_assert(factEmbeddedObject(OuterClass, InnerClass, Offset)),
    try_assert(guessedEmbeddedObject(OuterClass, InnerClass, Offset)).

% --------------------------------------------------------------------------------------------
% Try guessing that an address is really method.
% --------------------------------------------------------------------------------------------

guessMethod :-
    likelyMethod(Method),
    not(factMethod(Method)),
    not(factNOTMethod(Method)),
    debug('Proposing factMethod('), debug(Method), debugln(') ... '),
    tryMethodNOTMethod(Method).

tryMethodNOTMethod(Method):-
    not(factMethod(Method)),
    not(factNOTMethod(Method)),
    (
        tryMethod(Method);
        tryNOTMethod(Method);
        debug('Something is wrong upstream: invalidMethod('),
        debug(Method), debugln(').'),
        fail
    ).

tryMethod(Method) :-
    debug('Guessing factMethod('), debug(Method), debugln(') ... '),
    try_assert(factMethod(Method)),
    try_assert(guessedMethod(Method)).

tryNOTMethod(Method) :-
    debug('Guessing factNOTMethod('), debug(Method), debugln(') ... '),
    try_assert(factNOTMethod(Method)),
    try_assert(guessedNOTMethod(Method)).

% --------------------------------------------------------------------------------------------
% Try guessing that method is a constructor.
% --------------------------------------------------------------------------------------------

% Prefer guessing methods that have confirmed vftable writes first?  It's not clear that this
% was needed, but it doesn't seem harmful provided that we backtrack correctly (and not
% repeatedly, which is why I added the cut).

% We have three approximate indicators of constructor-ness:
%
% 1. The method appears in a _possible_ VFTable, which is strongly negative because we can't
%    presently propose any legitimate reason why that should happen if the method was truly a
%    constructor.
%
% 2. The method has VFTable writes which proves that it's either a constructor or destructor,
%    making our guess much better (at least 50/50) and probably even better if the next
%    indicator is also true.
%
% 3. The method has reads of members that it did not initialize.  This is not allowed for
%    constructors unless the method called the parent constructor which initialized the member.
%    While not impossible this situation is less likely (and probably eliminates many
%    destructors).  Guessing NOTConstructor based on uninitialized reads doesn't work because
%    we have test cases that initialize dervied members from base members.
%
% We're going to prioritize them in roughly that order...  There's still some debate about the
% optimal order of the latter two incicators based on various arguments which cases are more
% common and so forth...

% Perfect virtual case, not in a vftable, writes a vftable, and has no uninitalized reads.
guessConstructor :-
    likelyMethod(Method),
    possibleConstructor(Method),
    not(possibleVFTableEntry(_VFTable1, _VFTableOffset, Method)),
    factVFTableWrite(_Insn, Method, _ObjectOffset, _VFTable2),
    not(uninitializedReads(Method)),
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)),
    debug('Proposing factConstructor1('), debug(Method), debugln(') ... '),
    tryConstructorNOTConstructor(Method).

% Likely virtual case, not in a vftable, writes a vftable, but has unitialized reads.
guessConstructor :-
    likelyMethod(Method),
    possibleConstructor(Method),
    not(possibleVFTableEntry(_VFTable1, _VFTableOffset, Method)),
    factVFTableWrite(_Insn, Method, _ObjectOffset, _VFTable2),
    % We don't whether their were unitialized reads or not.  Presumably we called our parent
    % constructor (which kind of makes sense giving that we've already got virtual methods).
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)),
    debug('Proposing factConstructor2('), debug(Method), debugln(') ... '),
    tryConstructorNOTConstructor(Method).

% Normal non-virtual case, not in a vftable, doesn't write a vftable, and has no uninitialized
% reads.
guessConstructor :-
    likelyMethod(Method),
    possibleConstructor(Method),
    not(possibleVFTableEntry(_VFTable, _VFTableOffset, Method)),
    % This case is for constructors of non-virtual classes.
    not(uninitializedReads(Method)),
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)),
    debug('Proposing factConstructor3('), debug(Method), debugln(') ... '),
    tryConstructorNOTConstructor(Method).

% Unusual non-virtual case presumably with inheritance -- not in a vftable, doesn't write a
% vftable, but has uninitialized reads.  It's very likely that this class has a base, but we
% don't capture that implication well right now.
guessUnlikelyConstructor :-
    likelyMethod(Method),
    possibleConstructor(Method),
    not(possibleVFTableEntry(_VFTable, _VFTableOffset, Method)),
    % This case is for constructors of non-virtual classes with uninitalized reads.
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)),
    debug('Proposing factConstructor4('), debug(Method), debugln(') ... '),
    tryConstructorNOTConstructor(Method).

% Then guess all methods that might possibly be a constructor, without regard to the other
% indicators.  Technically we should probably order the cases with and without vftable writes
% and uninitialized reads, but's start with this simpler scheme.
guessUnlikelyConstructor :-
    possibleMethod(Method),
    possibleConstructor(Method),
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)),
    debug('Proposing factConstructor5('), debug(Method), debugln(') ... '),
    tryConstructorNOTConstructor(Method).

tryConstructorNOTConstructor(Method):-
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)),
    (
        tryConstructor(Method);
        tryNOTConstructor(Method);
        debug('Something is wrong upstream: invalidConstructor('),
        debug(Method), debugln(').'),
        fail
    ).

tryConstructor(Method) :-
    debug('Guessing factConstructor('), debug(Method), debugln(') ... '),
    try_assert(factConstructor(Method)),
    try_assert(guessedConstructor(Method)).

tryNOTConstructor(Method) :-
    debug('Guessing factNOTConstructor('), debug(Method), debugln(') ... '),
    try_assert(factNOTConstructor(Method)),
    try_assert(guessedNOTConstructor(Method)).

% --------------------------------------------------------------------------------------------
% Try guessing that constructor has no base class.
% --------------------------------------------------------------------------------------------

% First guess constructors with a single VFTable write...  Because constructors with multiple
% vftable writes are more likely to have base classes.
guessClassHasNoBase :-
    factConstructor(Constructor),
    find(Constructor, Class),

    factVFTableWrite(_Insn1, Constructor, 0, VFTable),
    not((
               factVFTableWrite(_Insn2, Constructor, _Offset, OtherVFTable),
               iso_dif(VFTable, OtherVFTable)
       )),

    not(factDerivedClass(Class, _BaseClass, _Offset)),
    not(factClassHasNoBase(Class)),
    not(factClassHasUnknownBase(Class)),
    debug('Proposing ClassHasNoBase1('),
    debug(Constructor), debug(', '),
    debug(VFTable), debug(', '),
    debug(Class), debugln(') ... '),
    (
        tryClassHasNoBase(Class);
        tryClassHasUnknownBase(Class);
        debug('Something is wrong upstream: invalidClassHasNoBase('),
        debug(Class), debugln(').'),
        fail
    ).

% Then guess classes regardless of their VFTable writes.
guessClassHasNoBase :-
    factConstructor(Constructor),
    find(Constructor, Class),
    not(factDerivedClass(Class, _BaseClass, _Offset)),
    not(factClassHasNoBase(Class)),
    not(factClassHasUnknownBase(Class)),
    debug('Proposing ClassHasNoBase2('),
    debug(Class), debugln(') ... '),
    (
        tryClassHasNoBase(Class);
        tryClassHasUnknownBase(Class);
        debug('Something is wrong upstream: invalidClassHasNoBase('),
        debug(Class), debugln(').'),
        fail
    ).

tryClassHasNoBase(Class) :-
    debug('Guessing factClassHasNoBase('), debug(Class), debugln(') ... '),
    try_assert(factClassHasNoBase(Class)),
    try_assert(guessedClassHasNoBase(Class)).

tryClassHasUnknownBase(Class) :-
    debug('Guessing factClassHasUnknownBase('), debug(Class), debugln(') ... '),
    try_assert(factClassHasUnknownBase(Class)),
    try_assert(guessedClassHasUnknownBase(Class)).

% --------------------------------------------------------------------------------------------
% Various rules for guessing method to class assignments...
% --------------------------------------------------------------------------------------------

% There's a very common paradigm where one constructor calls another constructor, and this
% represents either an embedded object or an inheritance relationship (aka ObjectInObject).
% This rule is strong enough that for a long time it was a forward reasoning rule, until Cory
% realized that technically the required condition was factNOTMergeClasses() instead of just
% currently being on different classes.  Because we needed to make this guess, the weaker logic
% was moved here.
guessNOTMergeClasses :-
    % We are certain that this member offset is passed to InnerConstructor.
    validFuncOffset(_CallInsn, OuterConstructor, InnerConstructor, _Offset),
    factConstructor(OuterConstructor),
    factConstructor(InnerConstructor),
    iso_dif(InnerConstructor, OuterConstructor),
    % They're not currently on the same class...
    find(InnerConstructor, InnerClass),
    find(OuterConstructor, OuterClass),
    iso_dif(OuterClass, InnerClass),

    % We've not already concluded that they're different classes.
    not(factNOTMergeClasses(OuterClass, InnerClass)),
    not(factNOTMergeClasses(InnerClass, OuterClass)),

    debug('Proposing factNOTMergeClasses('),
    debug(OuterConstructor), debug(', '),
    debug(InnerConstructor), debug(', '),
    debug(OuterClass), debug(', '),
    debug(InnerClass), debugln(') ... '),
    (
        tryNOTMergeClasses(OuterClass, InnerClass);
        % Cory is concerned about endless loops here because tryMergeClasses is non-standard.
        debug('Guessing (maybe) factMergeClasses('), debug(OuterClass), debug(', '),
        debug(InnerClass), debugln(') ... '),
        tryMergeClasses(OuterClass, InnerClass);
        debug('Something is wrong upstream: invalidNOTMergeClasses('),
        debug(OuterClass), debug(', '),
        debug(InnerClass), debugln(').'),
        fail
    ).

tryNOTMergeClasses(Class1, Class2) :-
    debug('Guessing factNOTMergeClasses('), debug(Class1), debug(', '),
    debug(Class2), debugln(') ... '),
    try_assert(factNOTMergeClasses(Class1, Class2)),
    try_assert(guessedNOTMergeClasses(Class1, Class2)).

% This is one of the strongest of several rules for guessing arbitrary method assignments.  We
% know that the method is very likely to be assigned to one of the two constructors, so we
% should guess both right now.  We don't technically know that it's assign to one or the other,
% because a method might be conflicted between multiple classes.  Perhaps a lot of conflicted
% methods with the same constructors should suggest a class merger between the constructors
% instead (for performance reasons)?
guessMergeClasses :-
    factMethod(Method),
    not(purecall(Method)), % Never merge purecall methods into classes.
    funcOffset(_Insn1, Constructor1, Method, 0),
    funcOffset(_Insn2, Constructor2, Method, 0),
    iso_dif(Constructor1, Constructor2),
    factConstructor(Constructor1),
    factConstructor(Constructor2),
    methodsNOTOnSameClass(Constructor1, Constructor2),
    find(Constructor1, Class),
    % This rule is symmetric because Prolog will try binding the same method to Constructor2 on
    % one evluation, and Constructor1 on the next evaluation, so even though the rule is also
    % true for Constructor2, that case will be handled when it's bound to Constructor.
    debug('Proposing factMergeClasses1('), debug(Class), debug(', '),
    debug(Method), debugln(') ... '),
    tryMergeClasses(Class, Method).

% Another good guessing heuristic is that if a virtual call was resolved through a specific
% VFTable, and there's nothing contradictory, try assigning the call to the class that it was
% resolved through.  Technically, I think this is a case of choosing arbitrarily between
% multiple valid solutions.  It might be possible to prove which constructor the method is on.
guessMergeClasses :-
    factMethod(Method1),
    not(purecall(Method1)), % Never merge purecall methods into classes.
    factVFTableWrite(_Insn, Method2, _ObjectOffset, VFTable),
    % The VFTable wasn't an overwritten VFTable.
    not(factVFTableOverwrite(VFTable, _OtherVFTable, _OtherOffset)),
    factVFTableEntry(VFTable, _VFTableOffset, Method1),
    % The method is not also is some other VFTable.
    not((
               factVFTableEntry(OtherVFTable, _OtherVFTableOffset, Method1),
               iso_dif(VFTable, OtherVFTable)
       )),
    find(Method1, Class1),
    find(Method2, Class2),
    debug('Proposing factMergeClasses2('),
    debug(Method1), debug(', '),
    debug(Method2), debug(', '),
    debug(VFTable), debug(', '),
    debug(Class1), debug(', '),
    debug(Class2), debugln(') ... '),
    tryMergeClasses(Class1, Class2).

% This rule makes guesses about whether to assign methods to the derived class or the base
% class.  Right now it's an arbitrary guess (try the derived class first), but we can probably
% add a bunch of rules using class sizes and vftable sizes once the size rules are cleaned up a
% litte.  These rules are not easily combined in the "problem upstream" pattern because of the
% way Constructor is unified with different parameters of factDerviedConstructor, and it's not
% certain that the method is assigned to eactly one of those two anyway.  There's still the
% possibilty that the method is on one of the base classes bases -- a scenario that we may not
% currently be making any guesses for.
guessMergeClasses :-
    factClassCallsMethod(Class, Method),
    not(purecall(Method)), % Never merge purecall methods into classes.
    factDerivedClass(Class, _BaseClass, _Offset),
    debug('Proposing factMergeClasses3('), debug(Class), debug(', '),
    debug(Method), debugln(') ... '),
    tryMergeClasses(Class, Method).

% If that didn't work, maybe the method belongs on the base instead.
guessMergeClasses :-
    factClassCallsMethod(Class, Method),
    not(purecall(Method)), % Never merge purecall methods into classes.
    factDerivedClass(_DerivedClass, Class, _Offset),
    debug('Proposing factMergeClasses4('), debug(Class), debug(', '),
    debug(Method), debugln(') ... '),
    tryMergeClasses(Class, Method).

% And finally just guess regardless of derived class facts.
guessMergeClasses :-
    factClassCallsMethod(Class, Method),
    not(purecall(Method)), % Never merge purecall methods into classes.
    debug('Proposing factMergeClasses5('), debug(Class), debug(', '),
    debug(Method), debugln(') ... '),
    tryMergeClasses(Class, Method).

tryMergeClasses(Method1, Method2) :-
    iso_dif(Method1, Method2),

    find(Method1, Class1),
    find(Method2, Class2),

    % And they're not already proven NOT to be on the same class.
    not(factNOTMergeClasses(Class1, Class2)),
    not(factNOTMergeClasses(Class2, Class1)),
    % And they're not already on the same class...
    methodsNOTOnSameClass(Class1, Class2),
    % Now derived relationships between the classes are not allowed either.
    not(reasonDerivedClassRelationship(Class1, Class2)),
    not(reasonDerivedClassRelationship(Class2, Class1)),

    debug('Guessing factMergeClasses('), debug(Class1), debug(', '),
    debug(Class2), debugln(') ... '),
    try_assert(factMergeClasses(Class1, Class2)),
    ((mergeClasses(Class1, Class2),
      try_assert(guessedMergeClasses(Class1, Class2)));
     (debug('merge failed, '),
      debug('guessing factNOTMergeClasses('), debug(Class1), debug(', '),
      debug(Class2), debugln(') ... '),
      try_assert(factNOTMergeClasses(Class1, Class2)),
      try_assert(guessedNOTMergeClasses(Class1, Class2)));
     (debug('Problem upstream in tryMergeClasses('),
      debug(Class1), debug(', '),
      debug(Class2), debugln(')'),
      fail)).

% --------------------------------------------------------------------------------------------
% Try guessing that method is a real destructor.
% --------------------------------------------------------------------------------------------
guessRealDestructor :-
    likelyDeletingDestructor(DeletingDestructor, Method),
    % Require that we've already confirmed the deleting destructor.
    factDeletingDestructor(DeletingDestructor),
    not(factRealDestructor(Method)),
    not(factNOTRealDestructor(Method)),
    (tryRealDestructor(Method);
     tryNOTRealDestructor(Method)).

tryRealDestructor(Method) :-
    debug('Guessing factRealDestructor('), debug(Method), debugln(') ... '),
    try_assert(factRealDestructor(Method)),
    try_assert(guessedRealDestructor(Method)).

tryNOTRealDestructor(Method) :-
    debug('Guessing factNOTRealDestructor('), debug(Method), debugln(') ... '),
    try_assert(factNOTRealDestructor(Method)),
    try_assert(guessedNOTRealDestructor(Method)).

% --------------------------------------------------------------------------------------------
% Try guessing that method is a deleting destructor.
% --------------------------------------------------------------------------------------------

% The criteria for guessing deleting destructors...
guessDeletingDestructor :-
    likelyDeletingDestructor(Method, _RealDestructor),
    not(factDeletingDestructor(Method)),
    not(factNOTDeletingDestructor(Method)),
    (
        tryDeletingDestructor(Method);
        tryNOTDeletingDestructor(Method);
        debug('Something is wrong upstream: invalidDeletingDestructor('),
        debug(Method), debugln(').'),
        fail
    ).

tryDeletingDestructor(Method) :-
    debug('Guessing factDeletingDestructor('), debug(Method), debugln(') ... '),
    try_assert(factDeletingDestructor(Method)),
    try_assert(guessedDeletingDestructor(Method)).

tryNOTDeletingDestructor(Method) :-
    debug('Guessing factDeletingDestructor('), debug(Method), debugln(') ... '),
    try_assert(factNOTDeletingDestructor(Method)),
    try_assert(guessedNOTDeletingDestructor(Method)).

% A helper for guessing deleting destructors.
likelyDeletingDestructor(DeletingDestructor, RealDestructor) :-
    % This indicates that the method met some basic criteria in C++.

    % This weaker criteria starts with just any old method...
    possibleMethod(DeletingDestructor),
    % That's not already certain to NOT be a deleting destructor.
    not(factNOTDeletingDestructor(DeletingDestructor)),
    % Deleting destructors must call the real destructor (we think).  Usually offset is zero,
    % but there are some unusual cases where there are multiple calls to real destructors, and
    % only one has offset zero and we missed it because we're not handling imported OO methods
    % correctly.  A cheap hack to just be a little looser here and accept any calls to
    % destructors.
    validFuncOffset(RealDestructorInsn, DeletingDestructor, RealDestructor, _Offset),
    % And while it's premature to require the real destructor to be certain, it shouldn't be
    % disproven.
    not(factNOTRealDestructor(RealDestructor)),
    % And the deleting destructotr must also call delete (we think), since that's what makes it
    % deleting.
    insnCallsDelete(DeleteInsn),
    % And just to be pedantic, the call to delete should come after the call to the real destructor.
    canpreceed(RealDestructorInsn, DeleteInsn).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
