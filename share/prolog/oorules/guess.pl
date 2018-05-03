% Copyright 2017 Carnegie Mellon University.
% ============================================================================================
% Guessing rules.
% ============================================================================================

:- import take/3 from lists.

tryBinarySearchInt(_PosPred, _NegPred, []) :-
    %debugln('tryBinarySearch empty.'),
    fail.

tryBinarySearchInt(PosPred, NegPred, L) :-
    length(L, 1),
    member(X, L),
    %debug('tryBinarySearch on '), debugln(L),
    !,
    (call(PosPred, X);
     call(NegPred, X)).

tryBinarySearchInt(PosPred, NegPred, List) :-
    length(List, ListLen),
    %debug('tryBinarySearch on '), debug(ListLen), debug(': '), debugln(List),
    % First try the positive guess on everything. If that fails, we want to retract all the
    % guesses and recurse on a subproblem.
    maplist(PosPred, List);

    % We failed! Recurse on first half of the list
    %debug('We failed! tryBinarySearch on '), debugln(List),
    length(List, ListLen),
    NewListLen is min(16, ListLen/2),

    take(NewListLen, List, NewList),

    tryBinarySearchInt(PosPred, NegPred, NewList).

tryBinarySearchInt(_PP, _NP, L) :-
    %debug('tryBinarySearch completely failed on '), debug(L), debugln(' and will now backtrack to fix an upstream problem.'),
    fail.

% This is a wrapper that limits the number of entries to assert at one time
tryBinarySearch(PP, NP, L, N) :-
    length(L, ListLen),
    ListLen >= N,
    take(N, L, Ltrim),
    !,
    tryBinarySearchInt(PP, NP, Ltrim).

tryBinarySearch(PP, NP, L, _N) :-
    tryBinarySearchInt(PP, NP, L).


:- dynamic numGroup/1.
:- assert(numGroup(1)).

trySetGroup(NewN) :-
    numGroup(OldN),
    retract(numGroup(OldN)),
    assert(numGroup(NewN)).

trySetGroup(NewN) :-
    % debugln(['setting group to', NewN, 'failed and setting to 1']),
    % We're backtracking!  Crap.
    retract(numGroup(NewN)),
    assert(numGroup(1)),
    fail.

tryBinarySearch(PP, NP, L) :-
    %debugln('Looking for numGroup......'),
    numGroup(NG),
    %debugln(['Old numGroup is ', NG]),
    !,
    tryBinarySearch(PP, NP, L, NG),
    %debugln('success?'),
    % We're successful.  Adjust numgroup.  We need to query again to see if NG changed.
    numGroup(NGagain),
    %debugln(['Old numGroup is again', NGagain]),
    length(L, ListLength),
    NGp is max(NGagain, min(ListLength, NGagain*2)),
    %debugln(['New numGroup is ', NGp]),
    trySetGroup(NGp).

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
        logwarn('Something is wrong upstream: invalidVirtualFunctionCall('),
        logwarn(Insn), logwarnln(').'),
        fail
    ).

tryVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset) :-
    loginfo('Guessing factVirtualFunctionCall('),
    loginfo(Insn), loginfo(', '),
    loginfo(Method), loginfo(', '),
    loginfo(OOffset), loginfo(', '),
    loginfo(VFTable), loginfo(', '),
    loginfo(VOffset), loginfoln(') ... '),
    try_assert(factVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset)),
    try_assert(guessedVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset)).

tryNOTVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset) :-
    loginfo('Guessing factNOTVirtualFunctionCall('),
    loginfo(Insn), loginfo(', '),
    loginfo(Method), loginfo(', '),
    loginfo(OOffset), loginfo(', '),
    loginfo(VFTable), loginfo(', '),
    loginfo(VOffset), loginfoln(') ... '),
    try_assert(factNOTVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset)),
    try_assert(guessedNOTVirtualFunctionCall(Insn, Method, OOffset, VFTable, VOffset)).

% --------------------------------------------------------------------------------------------
% Try guessing that a virtual function table is correctly identified.
% --------------------------------------------------------------------------------------------

guessVFTable :-
    % See the commentary at possibleVFTable for how this goal constrains our guesses (and
    % ordering).
    osetof(VFTable,
          (possibleVFTable(VFTable),
           not(factVFTable(VFTable)),
           not(factNOTVFTable(VFTable))),
          VFTableSet),
    length(VFTableSet, VFTableLen),
    debug('There are '), debug(VFTableLen), debugln(' VFTable Guesses to make.'),
    tryBinarySearch(tryVFTable, tryNOTVFTable, VFTableSet).

tryOrNotVFTable(VFTable) :-
    tryVFTable(VFTable);
    tryNOTVFTable(VFTable);
    logwarn('Something is wrong upstream: invalidVFTable('),
    logwarn(VFTable), logwarnln(').'),
    fail.

tryVFTable(VFTable) :-
    loginfo('Guessing factVFTable('), loginfo(VFTable), loginfoln(') ... '),
    try_assert(factVFTable(VFTable)),
    try_assert(guessedVFTable(VFTable)).

tryNOTVFTable(VFTable) :-
    loginfo('Guessing factNOTVFTable('), loginfo(VFTable), loginfoln(') ... '),
    try_assert(factNOTVFTable(VFTable)),
    try_assert(guessedNOTVFTable(VFTable)).


% --------------------------------------------------------------------------------------------
% Try guessing that a virtual base table is correctly identified.
% --------------------------------------------------------------------------------------------
guessVBTable :-
    validVBTableWrite(_Insn, Method, _Offset, VBTable),
    factMethod(Method),
    not(factVBTable(VBTable)),
    not(factNOTVBTable(VBTable)),
    (
        tryVBTable(VBTable);
        tryNOTVBTable(VBTable);
        logwarn('Something is wrong upstream: invalidVBTable('),
        logwarn(VBTable), logwarnln(').'),
        fail
    ).

tryVBTable(VBTable) :-
    loginfo('Guessing factVBTable('), loginfo(VBTable), loginfoln(') ... '),
    try_assert(factVBTable(VBTable)),
    try_assert(guessedVBTable(VBTable)).

tryNOTVBTable(VBTable) :-
    loginfo('Guessing factNOTVBTable('), loginfo(VBTable), loginfoln(') ... '),
    try_assert(factNOTVBTable(VBTable)),
    try_assert(guessedNOTVBTable(VBTable)).

% --------------------------------------------------------------------------------------------
% Try guessing that a virtual function table entry is valid.
% --------------------------------------------------------------------------------------------
prioritizedVFTableEntry(VFTable, Offset, Entry) :-
    % First establish that the guess meets minimal requirements.
    possibleVFTableEntry(VFTable, Offset, Entry),
    factVFTable(VFTable),

    % We should really be able to enforce known methods here, but sadly in the current test
    % suite we cannot, because a few tests rely on guessing the last member of the VFTable. :-(
    % Probably the next thing to try is exporting thisCall(Method) facts from OOAnalyzer, so
    % that we know which guesses are better than garbage.  In other words, guess factMethod()
    % first based on something other than the VFtableEntry.  In the meantime leave it out.

    % (factMethod(Entry); purecall(Entry)),

    % Then that it's not already proved or disproved.
    not(factVFTableEntry(VFTable, Offset, Entry)),
    not(reasonNOTVFTableEntry(VFTable, Offset, Entry)).

% --------------------------------------------------------------------------------------------
guessVFTableEntry(VFTable, Offset, Entry) :-
    % Choose a prioritized VFTable entry to guess.
    prioritizedVFTableEntry(VFTable, Offset, Entry),
    % Prioritize guessing the largest likely offset first.  This clause leads to make fewer
    % guesses that that imply all of the smaller offsets.  This turns out to be important from
    % a performance perspective because it reduces the number of times we need to check the
    % entire system against the valid solution constraints.
    not(factVFTableEntry(VFTable, Offset, Entry)),
    not(factNOTVFTableEntry(VFTable, Offset, Entry)),
    % ejs: TEMPORARY RULE.  If (V, O, E) is not an entry, then do not guess for any E' <
    % E. Otherwise we'll keep trying E-4, E-8, and so on.
    not((factNOTVFTableEntry(VFTable, Offset, OtherEntry), OtherEntry > Entry)),
    not((prioritizedVFTableEntry(VFTable, LargerOffset, _OtherEntry), LargerOffset > Offset)).

guessVFTableEntry :-
    osetof((VFTable, Offset, Entry),
          guessVFTableEntry(VFTable, Offset, Entry),
          TupleSet),
    tryBinarySearch(tryVFTableEntry, tryNOTVFTableEntry, TupleSet).

tryVFTableEntry((VFTable, Offset, Entry)) :- tryVFTableEntry(VFTable, Offset, Entry).
tryVFTableEntry(VFTable, Offset, Entry) :-
    loginfo('Guessing factVFTableEntry('),
    loginfo(VFTable), loginfo(', '),
    loginfo(Offset), loginfo(', '),
    loginfo(Entry), loginfoln(') ... '),
    try_assert(factVFTableEntry(VFTable, Offset, Entry)),
    try_assert(guessedVFTableEntry(VFTable, Offset, Entry)).

tryNOTVFTableEntry((VFTable, Offset, Entry)) :- tryNOTVFTableEntry(VFTable, Offset, Entry).
tryNOTVFTableEntry(VFTable, Offset, Entry) :-
    loginfo('Guessing factNOTVFTableEntry('),
    loginfo(VFTable), loginfo(', '),
    loginfo(Offset), loginfo(', '),
    loginfo(Entry), loginfoln(') ... '),
    try_assert(factNOTVFTableEntry(VFTable, Offset, Entry)),
    try_assert(guessedNOTVFTableEntry(VFTable, Offset, Entry)).

% --------------------------------------------------------------------------------------------
% Try guessing that an embedded object offset zero is really an inheritance relationship.
% ED_PAPER_INTERESTING
% --------------------------------------------------------------------------------------------
guessDerivedClass(DerivedClass, BaseClass, Offset) :-
    % It's a little unclear if we want to limit this to offset zero, or accept all embedded
    % objects as base classes.  At present, we're back to accepting all classes.
    % Offset = 0,
    factObjectInObject(DerivedClass, BaseClass, Offset),
    not(factDerivedClass(DerivedClass, BaseClass, Offset)),
    not(factEmbeddedObject(DerivedClass, BaseClass, Offset)).

guessDerivedClass :-
    osetof((DerivedClass, BaseClass, Offset),
          guessDerivedClass(DerivedClass, BaseClass, Offset),
          TupleSet),
    tryBinarySearch(tryDerivedClass, tryEmbeddedObject, TupleSet).

tryEmbeddedObject((OuterClass, InnerClass, Offset)) :- tryEmbeddedObject(OuterClass, InnerClass, Offset).
tryEmbeddedObject(OuterClass, InnerClass, Offset) :-
    loginfo('Guessing factEmbeddedObject('),
    loginfo(OuterClass), loginfo(', '),
    loginfo(InnerClass), loginfo(', '),
    loginfo(Offset), loginfoln(') ... '),
    try_assert(factEmbeddedObject(OuterClass, InnerClass, Offset)),
    try_assert(guessedEmbeddedObject(OuterClass, InnerClass, Offset)).

tryDerivedClass((DerivedClass, BaseClass, Offset)) :- tryDerivedClass(DerivedClass, BaseClass, Offset).
tryDerivedClass(DerivedClass, BaseClass, Offset) :-
    loginfo('Guessing factDerivedClass('),
    loginfo(DerivedClass), loginfo(', '),
    loginfo(BaseClass), loginfo(', '),
    loginfo(Offset), loginfoln(') ... '),
    try_assert(factDerivedClass(DerivedClass, BaseClass, Offset)),
    try_assert(guessedDerivedClass(DerivedClass, BaseClass, Offset)).

%% guessEmbeddedObject :-
%%     % It's very clear that we don't want to restrict embedded objects to offset zero.  Perhaps
%%     % we'll eventually find that this rule and guessDerivedClass are really the same.
%%     factObjectInObject(DerivedClass, BaseClass, Offset),
%%     not(factDerivedClass(DerivedClass, BaseClass, Offset)),
%%     not(factEmbeddedObject(DerivedClass, BaseClass, Offset)),
%%     (
%%         % Only here we're guessing embedded object first!
%%         tryEmbeddedObject(DerivedClass, BaseClass, Offset);
%%         tryDerivedClass(DerivedClass, BaseClass, Offset);
%%         logwarn('Something is wrong upstream: invalidEmbeddedObject('),
%%         logwarn(DerivedClass), logwarn(', '),
%%         logwarn(BaseClass), logwarn(', '),
%%         logwarn(Offset), logwarnln(').'),
%%         fail
%%     ).

% --------------------------------------------------------------------------------------------
% Try guessing that an address is really method.
% --------------------------------------------------------------------------------------------

% This guess is necessary because the "certain" attribute is not currently 100% accurate.  The
% problem that Cory explicitly found was that NOP instructions that look like object accesses
% result in the thiscall calling convention for trivial NOP functions.  This can probably be
% corrected upstream in fact generation, but for now an easy fix is to require at least a
% little other evidence that that convention detection was legitimate.  Requiring a
% validMethodMemberAccess is essentialy requiring that something in the object be accessed in
% the method.  The justification for using 100 as the limit for the offset size here is a bit
% complicated, but basically the thinking is that medium sized accesses are usually accompanied
% by at least one small access, and we can exclude a few more false positives by reducing the
% limit further beyond what would obviously be too limiting for validMethodMemberAccess.
guessMethodA(Method) :-
    thisCallMethod(Method, _ThisPtr, certain),
    validMethodMemberAccess(_Insn, Method, Offset, _Size),
    Offset < 100,
    not(factMethod(Method)),
    not(factNOTMethod(Method)).

guessMethod :-
    osetof(Method,
          guessMethodA(Method),
          MethodSet),
    logdebug('Proposing factMethod_A('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryMethod, tryNOTMethod, MethodSet).

guessMethodB(Method) :-
    factMethod(Caller),
    % We explicitly don't care about certainty here, because factMethod(Caller).
    thisCallMethod(Caller, ThisPtr1, _Certainty),
    thisPtrOffset(ThisPtr1, _Offset, ThisPtr2),
    thisPtrUsage(_Insn1, Caller, ThisPtr2, Method),
    not(factMethod(Method)),
    not(factNOTMethod(Method)).

% Guess that calls passed offsets into existing objects are methods.  This rule is not
% literally true, but objects are commonly in other objects.
guessMethod :-
    osetof(Method,
          guessMethodB(Method),
          MethodSet),
    logdebug('Proposing factMethod_B('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryMethod, tryNOTMethod, MethodSet).

% This guess is required (at least for our test suite) in cases where there's no certainty in
% the calling convention, and effectively no facts that would allow us to reach the conclusion
% logically.
% ED_PAPER_INTERESTING
guessMethodC(Method) :-
    thisCallMethod(Method, _ThisPtr, uncertain),
    validMethodMemberAccess(_Insn1, Method, Offset, _Size1),
    Offset < 100,
    funcOffset(_Insn2, Caller, Method, _Size2),
    factMethod(Caller),
    not(factMethod(Method)),
    not(factNOTMethod(Method)).

guessMethod :-
    osetof(Method,
          guessMethodC(Method),
          MethodSet),
    logdebug('Proposing factMethod_C('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryMethod, tryNOTMethod, MethodSet).

% More kludgy guessing rules. :-( This one is based on thre premise that a cluster of three or
% more nearly OO methods is not a conincidence. A better fix would be for at least one of the
% methods to be detected unambiguously as __thiscall, or to find dataflow from an already true
% method.
guessMethodD(Method) :-
    % This may need to be weakened past uncertain... :-(
    thisCallMethod(Method, _ThisPtr, uncertain),
    validMethodMemberAccess(_Insn0, Method, Offset, _Size0),
    Offset < 100,
    funcOffset(_Insn1, Caller1, Method, _Size1),
    funcOffset(_Insn2, Caller2, Method, _Size2),
    iso_dif(Caller1, Caller2),
    funcOffset(_Insn3, Caller3, Method, _Size3),
    iso_dif(Caller1, Caller3),
    not(factMethod(Method)),
    not(factNOTMethod(Method)).

guessMethod :-
    osetof(Method,
          guessMethodD(Method),
          MethodSet),
    logdebug('Proposing factMethod_D('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryMethod, tryNOTMethod, MethodSet).

% A variation of the previous rule using thisPtrUsage and passing around a this-pointer to
% multiple methods.  Just guess the first and the rest will follow...
guessMethodE(Method) :-
    % This may need to be weakened past uncertain... :-(
    thisCallMethod(Method, _ThisPtr, uncertain),
    validMethodMemberAccess(_Insn0, Method, Offset, _Size0),
    Offset < 100,
    thisPtrUsage(_Insn1, Caller, ThisPtr, Method),
    thisPtrUsage(_Insn2, Caller, ThisPtr, Method2),
    iso_dif(Method, Method2),
    thisPtrUsage(_Insn3, Caller, ThisPtr, Method3),
    iso_dif(Method, Method3),
    not(factMethod(Method)),
    not(factNOTMethod(Method)).


guessMethod :-
    osetof(Method,
          guessMethodE(Method),
          MethodSet),
    logdebug('Proposing factMethod_E('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryMethod, tryNOTMethod, MethodSet).

% Another case where we're trying to implement the reasoning that there's a lot of stuff
% suggesting that it's a method.  In this case, it's a possible constructor with memory
% accesses.
guessMethodF(Method) :-
    %thisCallMethod(Method, _ThisPtr, _Certainty),
    (thisCallMethod(Method, _ThisPtr, certain);
     thisCallMethod(Method, _ThisPtr, uncertain)),
    validMethodMemberAccess(_Insn1, Method, Offset, _Size1),
    Offset < 100,
    (possibleConstructor(Method); possibleDestructor(Method)),
    not(factMethod(Method)),
    not(factNOTMethod(Method)).

guessMethod :-
    osetof(Method,
          guessMethodF(Method),
          MethodSet),
    logdebug('Proposing factMethod_F('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryMethod, tryNOTMethod, MethodSet).

% Also guess possible constructors and destructors with calls from known methods.
guessMethodG(Method) :-
    %thisCallMethod(Method, _ThisPtr1, _Certainty),
    (thisCallMethod(Method, _ThisPtr1, certain);
     thisCallMethod(Method, _ThisPtr1, uncertain)),
    thisPtrUsage(_Insn, Caller, _ThisPtr2, Method),
    factMethod(Caller),
    (possibleConstructor(Method); possibleDestructor(Method)),
    not(factMethod(Method)),
    not(factNOTMethod(Method)).

guessMethod :-
    osetof(Method,
          guessMethodG(Method),
          MethodSet),
    logdebug('Proposing factMethod_G('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryMethod, tryNOTMethod, MethodSet).

tryMethodNOTMethod(Method):-
    not(factMethod(Method)),
    not(factNOTMethod(Method)),
    (
        tryMethod(Method);
        tryNOTMethod(Method);
        logwarn('Something is wrong upstream: invalidMethod('),
        logwarn(Method), logwarnln(').'),
        fail
    ).

tryMethod(Method) :-
    loginfo('Guessing factMethod('), loginfo(Method), loginfoln(') ... '),
    try_assert(factMethod(Method)),
    try_assert(guessedMethod(Method)),
    make(Method).

tryNOTMethod(Method) :-
    loginfo('Guessing factNOTMethod('), loginfo(Method), loginfoln(') ... '),
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

possiblyVirtual(Method):-
    possibleVFTableEntry(_VFTable1, _VFTableOffset, Entry),
    dethunk(Entry, Method).

% Perfect virtual case, not in a vftable, writes a vftable, and has no uninitalized reads.
% ED_PAPER_INTERESTING
guessConstructor1(Method) :-
    factMethod(Method),
    possibleConstructor(Method),
    not(possiblyVirtual(Method)),
    factVFTableWrite(_Insn, Method, _ObjectOffset, _VFTable2),
    not(uninitializedReads(Method)),
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)).

guessConstructor :-
    osetof(Method,
          guessConstructor1(Method),
          MethodSet),
    logdebug('Proposing factConstructor1('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryConstructor, tryNOTConstructor, MethodSet).

% Likely virtual case, not in a vftable, writes a vftable, but has unitialized reads.
guessConstructor2(Method) :-
    factMethod(Method),
    possibleConstructor(Method),
    not(possiblyVirtual(Method)),
    factVFTableWrite(_Insn, Method, _ObjectOffset, _VFTable2),
    % We don't whether their were unitialized reads or not.  Presumably we called our parent
    % constructor (which kind of makes sense giving that we've already got virtual methods).
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)).

guessConstructor :-
    osetof(Method,
          guessConstructor2(Method),
          MethodSet),
    logdebug('Proposing factConstructor2('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryConstructor, tryNOTConstructor, MethodSet).

% Normal non-virtual case, not in a vftable, doesn't write a vftable, and has no uninitialized
% reads.
% ED_PAPER_INTERESTING
guessConstructor3(Method) :-
    factMethod(Method),
    possibleConstructor(Method),
    not(possiblyVirtual(Method)),
    % This case is for constructors of non-virtual classes.
    not(uninitializedReads(Method)),
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)).

guessConstructor :-
    osetof(Method,
          guessConstructor3(Method),
          MethodSet),
    logdebug('Proposing factConstructor3('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryConstructor, tryNOTConstructor, MethodSet).

% Unusual non-virtual case presumably with inheritance -- not in a vftable, doesn't write a
% vftable, but has uninitialized reads.  It's very likely that this class has a base, but we
% don't capture that implication well right now.
guessConstructor4(Method) :-
    factMethod(Method),
    possibleConstructor(Method),
    not(possiblyVirtual(Method)),
    % This case is for constructors of non-virtual classes with uninitalized reads.
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)).

guessUnlikelyConstructor :-
    osetof(Method,
          guessConstructor4(Method),
          MethodSet),
    logdebug('Proposing factConstructor4('), logdebug(MethodSet), logdebugln(') ... '),
    tryBinarySearch(tryConstructor, tryNOTConstructor, MethodSet).

tryConstructorNOTConstructor(Method):-
    not(factConstructor(Method)),
    not(factNOTConstructor(Method)),
    (
        tryConstructor(Method);
        tryNOTConstructor(Method);
        logwarn('Something is wrong upstream: invalidConstructor('),
        logwarn(Method), logwarnln(').'),
        fail
    ).

tryConstructor(Method) :-
    loginfo('Guessing factConstructor('), loginfo(Method), loginfoln(') ... '),
    try_assert(factConstructor(Method)),
    try_assert(guessedConstructor(Method)).

tryNOTConstructor(Method) :-
    loginfo('Guessing factNOTConstructor('), loginfo(Method), loginfoln(') ... '),
    try_assert(factNOTConstructor(Method)),
    try_assert(guessedNOTConstructor(Method)).

% --------------------------------------------------------------------------------------------
% Try guessing that constructor has no base class.
% --------------------------------------------------------------------------------------------

% First guess constructors with a single VFTable write...  Because constructors with multiple
% vftable writes are more likely to have base classes.
% ED_PAPER_INTERESTING
guessClassHasNoBaseB(Class) :-
    factConstructor(Constructor),
    find(Constructor, Class),

    factVFTableWrite(_Insn1, Constructor, 0, VFTable),
    not((
               factVFTableWrite(_Insn2, Constructor, _Offset, OtherVFTable),
               iso_dif(VFTable, OtherVFTable)
       )),

    not(factDerivedClass(Class, _BaseClass, _Offset)),
    not(factClassHasNoBase(Class)),
    not(factClassHasUnknownBase(Class)).

guessClassHasNoBase :-
    osetof(Class,
          guessClassHasNoBaseB(Class),
          ClassSet),
    logdebug('Proposing ClassHasNoBase_B('), logdebug(ClassSet), logdebugln(') ... '),
    tryBinarySearch(tryClassHasNoBase, tryClassHasUnknownBase, ClassSet).

% Then guess classes regardless of their VFTable writes.
% ED_PAPER_INTERESTING
guessClassHasNoBaseC(Class) :-
    factConstructor(Constructor),
    find(Constructor, Class),
    not(factDerivedClass(Class, _BaseClass, _Offset)),
    not(factClassHasNoBase(Class)),
    not(factClassHasUnknownBase(Class)).

guessClassHasNoBase :-
    osetof(Class,
          guessClassHasNoBaseC(Class),
          ClassSet),
    logdebug('Proposing ClassHasNoBase_C('),
    logdebug(ClassSet), logdebugln(') ... '),
    tryBinarySearch(tryClassHasNoBase, tryClassHasUnknownBase, ClassSet).

tryClassHasNoBase(Class) :-
    loginfo('Guessing factClassHasNoBase('), loginfo(Class), loginfoln(') ... '),
    try_assert(factClassHasNoBase(Class)),
    try_assert(guessedClassHasNoBase(Class)).

tryClassHasUnknownBase(Class) :-
    loginfo('Guessing factClassHasUnknownBase('), loginfo(Class), loginfoln(') ... '),
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
% Ed: This is a guess because Constructor1 could be calling Constructor2 on the same class.
% ED_PAPER_INTERESTING
guessNOTMergeClasses(OuterClass, InnerClass) :-
    % We are certain that this member offset is passed to InnerConstructor.
    validFuncOffset(_CallInsn, OuterConstructor, InnerConstructor, _Offset),
    factConstructor(OuterConstructor),
    factConstructor(InnerConstructor),
    iso_dif(InnerConstructor, OuterConstructor),
    % They're not currently on the same class...
    find(InnerConstructor, InnerClass),
    find(OuterConstructor, OuterClass),
    iso_dif(OuterClass, InnerClass),

    not(uninitializedReads(InnerConstructor)),

    % We've not already concluded that they're different classes.
    not(factNOTMergeClasses(OuterClass, InnerClass)),
    not(factNOTMergeClasses(InnerClass, OuterClass)).

guessNOTMergeClasses :-
    osetof((OuterClass, InnerClass),
          guessNOTMergeClasses(OuterClass, InnerClass),
          ClassPairSets),
    tryBinarySearch(tryNOTMergeClasses, tryMergeClasses, ClassPairSets).

tryNOTMergeClasses((Class1, Class2)) :- tryNOTMergeClasses(Class1, Class2).
tryNOTMergeClasses(Class1, Class2) :-
    loginfo('Guessing factNOTMergeClasses('), loginfo(Class1), loginfo(', '),
    loginfo(Class2), loginfoln(') ... '),
    try_assert(factNOTMergeClasses(Class1, Class2)),
    try_assert(guessedNOTMergeClasses(Class1, Class2)).

% This is one of the strongest of several rules for guessing arbitrary method assignments.  We
% know that the method is very likely to be assigned to one of the two constructors, so we
% should guess both right now.  We don't technically know that it's assign to one or the other,
% because a method might be conflicted between multiple classes.  Perhaps a lot of conflicted
% methods with the same constructors should suggest a class merger between the constructors
% instead (for performance reasons)?
% Ed: Why does it matter that there are two constructors?
guessMergeClassesA(Class1, MethodClass) :-
    factMethod(Method),
    not(purecall(Method)), % Never merge purecall methods into classes.
    funcOffset(_Insn1, Constructor1, Method, 0),
    funcOffset(_Insn2, Constructor2, Method, 0),
    iso_dif(Constructor1, Constructor2),
    factConstructor(Constructor1),
    factConstructor(Constructor2),
    find(Constructor1, Class1),
    find(Constructor2, Class2),
    find(Method, MethodClass),
    iso_dif(Class1, Class2),
    iso_dif(Class1, Method),
    % This rule is symmetric because Prolog will try binding the same method to Constructor2 on
    % one evluation, and Constructor1 on the next evaluation, so even though the rule is also
    % true for Constructor2, that case will be handled when it's bound to Constructor.
    %logdebug('Proposing factMergeClasses_A('),
    %logdebug(Class1), logdebug(', '),
    %logdebug(Method), logdebugln(') ... '),
    checkMergeClasses(Class1, MethodClass).

guessMergeClasses :-
    osetof((Class, Method),
          guessMergeClassesA(Class, Method),
          TupleSet),
    logdebug('Proposing factMergeClasses_A('),
    logdebug(TupleSet), logdebugln(') ... '),
    tryBinarySearch(tryMergeClasses, tryNOTMergeClasses, TupleSet, 1).

% Another good guessing heuristic is that if a virtual call was resolved through a specific
% VFTable, and there's nothing contradictory, try assigning the call to the class that it was
% resolved through.  Technically, I think this is a case of choosing arbitrarily between
% multiple valid solutions.  It might be possible to prove which constructor the method is on.
guessMergeClassesB(Class1, Class2) :-
    % Start with a non-overwritten VFTable.
    factVFTableWrite(_Insn, Method2, _ObjectOffset, VFTable),
    not(factVFTableOverwrite(VFTable, _OtherVFTable, _OtherOffset)),
    factVFTableEntry(VFTable, _VFTableOffset, Entry1),
    dethunk(Entry1, Method1),
    factMethod(Method1),
    not(purecall(Entry1)), % Never merge purecall methods into classes.
    not(purecall(Method1)), % Never merge purecall methods into classes.

    % The method is not also is some other VFTable.  When adding thunk support, Cory decided to
    % allow the second entry to differ so long as it resolved to the same place.  It's unclear
    % if this is really correct.
    not((
               factVFTableEntry(OtherVFTable, _OtherVFTableOffset, Entry1A),
               dethunk(Entry1A, Method1),
               iso_dif(VFTable, OtherVFTable)
       )),

    % A further complication arose in this guessing heuristic.  It appears that if the method
    % in question is actually an import than this rule is not always true.  For example, in
    % 2010/Debug/ooex7, 0x41138e thunks to 0x414442 which thunks to 0x41d42c which is the
    % import for std::exception::what().  Blocking this guess prevents us from assigning it to
    % the wrong class, but it would be better to just assign it to the right class with a
    % strong reasoning rule.  We don't have one of those for this case yet because we don't
    % have the vftable for the method that's imported...
    not(symbolProperty(Method1, virtual)),

    find(Method1, Class1),
    find(Method2, Class2),
    %logdebug('Proposing factMergeClasses_B('),
    %logdebug(Method1), logdebug(', '),
    %logdebug(Method2), logdebug(', '),
    %logdebug(VFTable), logdebug(', '),
    %logdebug(Class1), logdebug(', '),
    %logdebug(Class2), logdebugln(') ... '),
    checkMergeClasses(Class1, Class2).

guessMergeClasses :-
    osetof((Class, Method),
          guessMergeClassesB(Class, Method),
          TupleSet),
    logdebug('Proposing factMergeClasses_B('),
    logdebug(TupleSet), logdebugln(') ... '),
    tryBinarySearch(tryMergeClasses, tryNOTMergeClasses, TupleSet, 1).


% This rule makes guesses about whether to assign methods to the derived class or the base
% class.  Right now it's an arbitrary guess (try the derived class first), but we can probably
% add a bunch of rules using class sizes and vftable sizes once the size rules are cleaned up a
% litte.  These rules are not easily combined in the "problem upstream" pattern because of the
% way Constructor is unified with different parameters of factDerviedConstructor, and it's not
% certain that the method is assigned to eactly one of those two anyway.  There's still the
% possibilty that the method is on one of the base classes bases -- a scenario that we may not
% currently be making any guesses for.
% ED_PAPER_INTERESTING
guessMergeClassesC(Class1, Class2) :-
    factClassCallsMethod(Class1, Method),
    not(purecall(Method)), % Never merge purecall methods into classes.
    factDerivedClass(Class1, _BaseClass, _Offset),
    %logdebug('Proposing factMergeClasses_C('), logdebug(Class), logdebug(', '),
    %logdebug(Method), logdebugln(') ... '),
    find(Method, Class2),
    checkMergeClasses(Class1, Class2).

guessMergeClasses :-
    osetof((Class, Method),
          guessMergeClassesC(Class, Method),
          TupleSet),
    logdebug('Proposing factMergeClasses_C('),
    logdebug(TupleSet), logdebugln(') ... '),
    tryBinarySearch(tryMergeClasses, tryNOTMergeClasses, TupleSet, 1).

% If that didn't work, maybe the method belongs on the base instead.
% ED_PAPER_INTERESTING
guessMergeClassesD(Class1, Class2) :-
    factClassCallsMethod(Class1, Method),
    not(purecall(Method)), % Never merge purecall methods into classes.
    factDerivedClass(_DerivedClass, Class1, _Offset),
    %logdebug('Proposing factMergeClasses_D('), logdebug(Class), logdebug(', '),
    %logdebug(Method), logdebugln(') ... '),
    find(Method, Class2),
    checkMergeClasses(Class1, Class2).

guessMergeClasses :-
    osetof((Class, Method),
          guessMergeClassesD(Class, Method),
          TupleSet),
    logdebug('Proposing factMergeClasses_D('),
    logdebug(TupleSet), logdebugln(') ... '),
    tryBinarySearch(tryMergeClasses, tryNOTMergeClasses, TupleSet, 1).

% And finally just guess regardless of derived class facts.
% ED_PAPER_INTERESTING
guessMergeClassesE(Class1, Class2) :-
    factClassCallsMethod(Class1, Method),
    not(purecall(Method)), % Never merge purecall methods into classes.
    % Same reasoning as in guessMergeClasses_B...
    not(symbolProperty(Method, virtual)),
    %logdebug('Proposing factMergeClasses_E('), logdebug(Class), logdebug(', '),
    %logdebug(Method), logdebugln(') ... '),
    find(Method, Class2),
    checkMergeClasses(Class1, Class2).

guessMergeClasses :-
    osetof((Class, Method),
          guessMergeClassesE(Class, Method),
          TupleSet),
    logdebug('Proposing factMergeClasses_E('),
    take(1, TupleSet, OneTuple),
    logdebug(OneTuple), logdebugln(') ... '),
    tryBinarySearch(tryMergeClasses, tryNOTMergeClasses, OneTuple).

% If we have VFTable that is NOT associated with a class because there's no factVFTableWrite,
% factClassCallsMethod is not true...  The problem here is that we don't which method call
% which other methods (the direction of the call).  But we still have a very strong suggestion
% that methods in the VFTable are related in someway.  As a guessing rule a reasonable
% compromize is to say that any class that is still assigned to itself, is better off (from an
% edit distance perspective) grouped with the otehr methods.
guessMergeClassesF(Class, Method1) :-
    % There are two different entries in the same VFTable...
    factVFTableEntry(VFTable, _Offset1, Entry1),
    factVFTableEntry(VFTable, _Offset2, Entry2),
    iso_dif(Entry1, Entry2),
    % Follow thunks for both entries.  What does it mean if the thunks differed but the methods
    % did not?  Cory's not sure right now, but this is what the original rule did.
    dethunk(Entry1, Method1),
    dethunk(Entry2, Method2),
    iso_dif(Method1, Method2),
    not(purecall(Entry1)), % Never merge purecall methods into classes.
    not(purecall(Entry2)), % Never merge purecall methods into classes.
    not(purecall(Method1)), % Never merge purecall methods into classes.
    not(purecall(Method2)), % Never merge purecall methods into classes.
    % One of the methods is in a class all by itself right now.
    % ejs: The prolog does not match the comment.
    find(Method1, Method1),
    % So go ahead and merge it into this class..
    find(Method2, Class),
    %logdebug('Proposing factMergeClasses_F('), logdebug(Class), logdebug(', '),
    %logdebug(Method1), logdebugln(') ... '),
    checkMergeClasses(Class, Method1).

guessMergeClasses :-
    osetof((Class, Method),
          guessMergeClassesF(Class, Method),
          TupleSet),
    logdebug('Proposing factMergeClasses_F('),
    logdebug(TupleSet), logdebugln(') ... '),
    tryBinarySearch(tryMergeClasses, tryNOTMergeClasses, TupleSet, 1).

checkMergeClasses(Method1, Method2) :-
    iso_dif(Method1, Method2),
    find(Method1, Class1),
    find(Method2, Class2),
    % They're not already on the same class...
    iso_dif(Class1, Class2),
    % They're not already proven NOT to be on the same class.
    not(factNOTMergeClasses(Class1, Class2)),
    not(factNOTMergeClasses(Class2, Class1)),
    % Now derived relationships between the classes are not allowed either.
    not(reasonDerivedClassRelationship(Class1, Class2)),
    not(reasonDerivedClassRelationship(Class2, Class1)).

tryMergeClasses((Method1, Method2)) :- tryMergeClasses(Method1, Method2).
% If we are merging classes that have already been merged, just ignore it.
tryMergeClasses(Method1, Method2) :-
    find(Method1, Class1),
    find(Method2, Class2),
    Class1 = Class2,
    !.
tryMergeClasses(Method1, Method2) :-
    find(Method1, Class1),
    find(Method2, Class2),
    loginfo('Guessing factMergeClasses('),
    loginfo(Class1), loginfo(', '),
    loginfo(Class2), loginfoln(') ... '),
    try_assert(factMergeClasses(Class1, Class2)),
    mergeClasses(Class1, Class2),
    try_assert(guessedMergeClasses(Class1, Class2)).

tryNOTMergeClasses(Method1, Method2) :-
    sanityChecks,
    find(Method1, Class1),
    find(Method2, Class2),
    loginfo('Guessing factNOTMergeClasses('),
    loginfo(Class1), loginfo(', '),
    loginfo(Class2), loginfoln(') ... '),
    try_assert(factNOTMergeClasses(Class1, Class2)),
    try_assert(guessedNOTMergeClasses(Class1, Class2)).

% --------------------------------------------------------------------------------------------
% Try guessing that method is a real destructor.
% --------------------------------------------------------------------------------------------
guessRealDestructor :-
    % possibleDestructor(Method),
    likelyDeletingDestructor(DeletingDestructor, Method),
    % Require that we've already confirmed the deleting destructor.
    factDeletingDestructor(DeletingDestructor),
    not(factRealDestructor(Method)),
    not(factNOTRealDestructor(Method)),
    (tryRealDestructor(Method);
     tryNOTRealDestructor(Method)).

% Establish that the candidate meets minimal requirements.
minimalRealDestructor(Method) :-
    possibleDestructor(Method),
    not(factRealDestructor(Method)),
    not(factNOTRealDestructor(Method)),

    % Trying a different approach to blocking singletons here.  Many singletons have no
    % interprocedural flow at all, and so also have no call before AND no calls after.
    % This causes a significant regression (at least by itself), F=0.43 -> F=0.36.
    % Even as an ordering rule this appears to be harmful... F=0.46 -> F=0.42 why?
    % not(noCallsBefore(Method)),

    % Destructors can't take multiple arguments (well except for when they have virtual bases),
    % but this should at least get us closer...
    not((
               funcParameter(Method, Position, _SV),
               iso_dif(Position, ecx)
       )),

    % There must be at least one other method besides this one on the class.  There's a strong
    % tendency to turn every singleton method into real destructor without this constraint.
    find(Method, Class),
    find(Other, Class),
    iso_dif(Other, Method),
    true.

% Prioritize methods called by deleteing destructors.
guessFinalRealDestructor :-
    minimalRealDestructor(Method),
    callTarget(_Insn, OtherDestructor, Method),
    factDeletingDestructor(OtherDestructor),
    (
        tryRealDestructor(Method);
        tryNOTRealDestructor(Method);
        logwarn('Something is wrong upstream: invalidRealDestructor('),
        logwarn(Method), logwarnln(').'),
        fail
    ).

% Prioritize methods that call other real destructors.
guessFinalRealDestructor :-
    minimalRealDestructor(Method),
    callTarget(_Insn, Method, OtherDestructor),
    factRealDestructor(OtherDestructor),
    (
        tryRealDestructor(Method);
        tryNOTRealDestructor(Method);
        logwarn('Something is wrong upstream: invalidRealDestructor('),
        logwarn(Method), logwarnln(').'),
        fail
    ).

% Prioritize methods that do not call delete to avoid confusion with deleting destructors.
% This eliminates a couple of false positives in the fast test suite.
guessFinalRealDestructor :-
    minimalRealDestructor(Method),
    not(insnCallsDelete(_Insn, Method, _SV)),
    (
        tryRealDestructor(Method);
        tryNOTRealDestructor(Method);
        logwarn('Something is wrong upstream: invalidRealDestructor('),
        logwarn(Method), logwarnln(').'),
        fail
    ).

% Guess if it meets the minimal criteria.
guessFinalRealDestructor :-
    minimalRealDestructor(Method),
    (
        tryRealDestructor(Method);
        tryNOTRealDestructor(Method);
        logwarn('Something is wrong upstream: invalidRealDestructor('),
        logwarn(Method), logwarnln(').'),
        fail
    ).

tryRealDestructor(Method) :-
    loginfo('Guessing factRealDestructor('), loginfo(Method), loginfoln(') ... '),
    try_assert(factRealDestructor(Method)),
    try_assert(guessedRealDestructor(Method)).

tryNOTRealDestructor(Method) :-
    loginfo('Guessing factNOTRealDestructor('), loginfo(Method), loginfoln(') ... '),
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
        logwarn('Something is wrong upstream: invalidDeletingDestructor('),
        logwarn(Method), logwarnln(').'),
        fail
    ).

guessFinalDeletingDestructor :-
    possibleDestructor(Method),
    not(factDeletingDestructor(Method)),
    not(factNOTDeletingDestructor(Method)),

    insnCallsDelete(_Insn2, Method, _SV),

    % Instead of requiring a call to a real destructor, allow deleting destructors that don't
    % call real destructors (just so long as they don't call anything else).  Net effect is a
    % tiny improvement on the fast portion of the test suite.
    not((
               callTarget(_Insn1, Method, Called),
               not(factRealDestructor(Called))
       )),

    %callTarget(_Insn1, Method, RealDestructor),
    %factRealDestructor(RealDestructor),
    (
        tryDeletingDestructor(Method);
        tryNOTDeletingDestructor(Method);
        logwarn('Something is wrong upstream: invalidDeletingDestructor('),
        logwarn(Method), logwarnln(').'),
        fail
    ).

%
guessFinalDeletingDestructor :-
    % Establish that the candidate meets minimal requirements.
    possibleDestructor(Method),
    not(factDeletingDestructor(Method)),
    not(factNOTDeletingDestructor(Method)),

    % The calls delete requirement was what was needed to keep false positives down.
    insnCallsDelete(_DeleteInsn, Method, _SV),

    % If the method occurs twice in a single VFTable, wildly guess that it's a deleting
    % destructor based entirely on a common phenomenon in the Visual Studio compiler.
    factVFTableEntry(VFTable, Offset1, Entry1),
    dethunk(Entry1, Method),
    factVFTableEntry(VFTable, Offset2, Entry2),
    iso_dif(Entry1, Entry2),
    iso_dif(Offset1, Offset2),
    dethunk(Entry1, Method),

    (
        tryDeletingDestructor(Method);
        tryNOTDeletingDestructor(Method);
        logwarn('Something is wrong upstream: invalidDeletingDestructor('),
        logwarn(Method), logwarnln(').'),
        fail
    ).

tryDeletingDestructor(Method) :-
    loginfo('Guessing factDeletingDestructor('), loginfo(Method), loginfoln(') ... '),
    try_assert(factDeletingDestructor(Method)),
    try_assert(guessedDeletingDestructor(Method)).

tryNOTDeletingDestructor(Method) :-
    loginfo('Guessing factDeletingDestructor('), loginfo(Method), loginfoln(') ... '),
    try_assert(factNOTDeletingDestructor(Method)),
    try_assert(guessedNOTDeletingDestructor(Method)).

% A helper for guessing deleting destructors.
likelyDeletingDestructor(DeletingDestructor, RealDestructor) :-
    % This indicates that the method met some basic criteria in C++.
    possibleDestructor(DeletingDestructor),
    % That's not already certain to NOT be a deleting destructor.
    not(factNOTDeletingDestructor(DeletingDestructor)),
    % Deleting destructors must call the real destructor (we think).  Usually offset is zero,
    % but there are some unusual cases where there are multiple calls to real destructors, and
    % only one has offset zero and we missed it because we're not handling imported OO methods
    % correctly.  A cheap hack to just be a little looser here and accept any calls to
    % destructors.
    validFuncOffset(_RealDestructorInsn, DeletingDestructor, RealDestructor, _Offset),
    % And while it's premature to require the real destructor to be certain, it shouldn't be
    % disproven.
    possibleDestructor(RealDestructor),
    not(factNOTRealDestructor(RealDestructor)),
    % And the deleting destructor must also call delete (we think), since that's what makes it
    % deleting.  Using this instead of the more complicated rule below led toa very slight
    % improvement in the fast test suite F=0.43 -> F=0.44.
    insnCallsDelete(_DeleteInsn, DeletingDestructor, _SV),

    % This condition is complicated.  We want to ensure that the thing actually being deleted
    % is the this-pointer passed to the deleting destructor.  But the detection of parameters
    % to delete is sometimes complicated, and a non-trivial number of our facts are still
    % reporting "invalid".  While the real fix is to always have correct parameter values for
    % delete(), in the mean time lets try accepting an fact-generation failure as well, but not
    % a pointer that's known to be unrelated).

    % RealDestructorChange! (comment out through true).
    thisCallMethod(DeletingDestructor, ThisPtr, _Certainty),
    (
        insnCallsDelete(_DeleteInsn, DeletingDestructor, ThisPtr);
        insnCallsDelete(_DeleteInsn, DeletingDestructor, invalid)
    ),
    true.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
