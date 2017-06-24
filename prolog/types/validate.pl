:- import member/2 from basics.
:- import length/2 from basics.

:- dynamic expectedSigned/2.
:- dynamic expectedPointer/2.
:- dynamic memaddr/1.
:- dynamic bitwidth/2.
:- dynamic value/2.


maplistm(Goal, List) :-
    maplistm2(List, Goal).

maplistm2([], _).
maplistm2([Elem|Tail], Goal) :-
    basics:append([Goal], Elem, GoalWithParamsList),
    GoalWithParams =.. GoalWithParamsList,
    call(GoalWithParams),
    maplistm2(Tail, Goal).

validateExpected :-
    validateMissingPointers, validateExtraPointers,
    validateExtraSigned, validateMissingSigned.

validateGeneralCounts :-
    countNotUsedInOp, countMissingBitwidth.

validateGeneralDetail :-
    validateNotUsedInOp, validateMissingBitwidth.

validate :- validateGeneralCounts, reportRawStats. %, validateGeneralDetail, validateExpected. 

% ==============================================================================
% This is a helper rul to find references to tree nodes.
% I put it in validate.pl because it shouldn't be needed except for debugging.

:- table usedInOp/1.

usedInOp(X) :- opAdd(X, _).
usedInOp(X) :- opAdd(_, L), member(X, L).

usedInOp(X) :- opAsr(X, _, _).
usedInOp(X) :- opAsr(_, X, _).
usedInOp(X) :- opAsr(_, _, X).

usedInOp(X) :- opBvAnd(X, _).
usedInOp(X) :- opBvAnd(_, L), member(X, L).

usedInOp(X) :- opBvOr(X, _).
usedInOp(X) :- opBvOr(_, L), member(X, L).

usedInOp(X) :- opBvXor(X, _).
usedInOp(X) :- opBvXor(_, L), member(X, L).

usedInOp(X) :- opConcat(X, _).
usedInOp(X) :- opConcat(_, L), member(X, L).

usedInOp(X) :- opExtract(X, _, _, _).
usedInOp(X) :- opExtract(_, X, _, _).
usedInOp(X) :- opExtract(_, _, X, _).
usedInOp(X) :- opExtract(_, _, _, X).

usedInOp(X) :- opInvert(X, _).
usedInOp(X) :- opInvert(_, X).

usedInOp(X) :- opIte(X, _, _, _).
usedInOp(X) :- opIte(_, X, _, _).
usedInOp(X) :- opIte(_, _, X, _).
usedInOp(X) :- opIte(_, _, _, X).

usedInOp(X) :- opSdiv(X, _, _).
usedInOp(X) :- opSdiv(_, X, _).
usedInOp(X) :- opSdiv(_, _, X).

usedInOp(X) :- opSextend(X, _, _).
usedInOp(X) :- opSextend(_, X, _).
usedInOp(X) :- opSextend(_, _, X).

usedInOp(X) :- opShl0(X, _, _).
usedInOp(X) :- opShl0(_, X, _).
usedInOp(X) :- opShl0(_, _, X).

usedInOp(X) :- opShl1(X, _, _).
usedInOp(X) :- opShl1(_, X, _).
usedInOp(X) :- opShl1(_, _, X).

usedInOp(X) :- opShr0(X, _, _).
usedInOp(X) :- opShr0(_, X, _).
usedInOp(X) :- opShr0(_, _, X).

usedInOp(X) :- opShr1(X, _, _).
usedInOp(X) :- opShr1(_, X, _).
usedInOp(X) :- opShr1(_, _, X).

usedInOp(X) :- opSmod(X, _, _).
usedInOp(X) :- opSmod(_, X, _).
usedInOp(X) :- opSmod(_, _, X).

usedInOp(X) :- opSmul(X, _, _).
usedInOp(X) :- opSmul(_, X, _).
usedInOp(X) :- opSmul(_, _, X).

usedInOp(X) :- opUdiv(X, _, _).
usedInOp(X) :- opUdiv(_, X, _).
usedInOp(X) :- opUdiv(_, _, X).

usedInOp(X) :- opUextend(X, _, _).
usedInOp(X) :- opUextend(_, X, _).
usedInOp(X) :- opUextend(_, _, X).

usedInOp(X) :- opUmod(X, _, _).
usedInOp(X) :- opUmod(_, X, _).
usedInOp(X) :- opUmod(_, _, X).

usedInOp(X) :- opUmul(X, _, _).
usedInOp(X) :- opUmul(_, X, _).
usedInOp(X) :- opUmul(_, _, X).

usedInOp(X) :- opRol(X, _, _).
usedInOp(X) :- opRol(_, X, _).
usedInOp(X) :- opRol(_, _, X).

usedInOp(X) :- opRor(X, _, _).
usedInOp(X) :- opRor(_, X, _).
usedInOp(X) :- opRor(_, _, X).

usedInOp(X) :- opZerop(X, _).
usedInOp(X) :- opZerop(_, X).

usedInData(X) :- usedInOp(X).
usedInData(X) :- value(X, _).
usedInData(X) :- memaddr(X).

%% ===================================================================
%% General validation.

notUsedInOp(X) :-
    bitwidth(X, _), tnot(usedInOp(X)).
notUsedInOp(X) :- value(X, _), tnot(usedInOp(X)).
notUsedInOp(X) :- memaddr(X), tnot(usedInOp(X)).

unreferencedMemConst(X) :- value(X, _), memaddr(X), tnot(usedInOp(X)).
unreferencedConstant(X) :- value(X, _), not(memaddr(X)), tnot(usedInOp(X)).
unreferencedMemaddr(X)  :- memaddr(X), not(value(X, _)), tnot(usedInOp(X)).
unreferencedBitwidth(X) :- bitwidth(X, _), not(usedInData(X)).

countNotUsedInOp :-
    setof(X, notUsedInOp(X), Set),
    length(Set, Len),
    write('*** There were '), write(Len), writeln(' treenodes that were not used in an operation.'),

    % amongst the things that weren't used in an operation, count the top pointers
    countPointerTops(Set, C),   
    write('*** There were '), write(C), writeln(' top pointer treenodes that were not used in an operation.'),

    % amongst the things that weren't used in an operation, count the top signedness
    countSignedTops(Set, D),   
    write('*** There were '), write(D), writeln(' top signed treenodes that were not used in an operation.')
    ;
    true.


countPointerTops([], 0).
% increment the pointer count recursively.
countPointerTops([H|T], C) :-
    (finalPointer(H, top), countPointerTops(T, X), C is X + 1); % If the list head is a top then increment pointer count
    (countPointerTops(T,C)).

countSignedTops([], 0).
% increment the signed count recursively.
countSignedTops([H|T], C) :-
    (finalSigned(H, top), countSignedTops(T, X), C is X + 1); % If the list head is a top then increment signed count
    (countSignedTops(T,C)).

statIsPointer :-
    findall(X, finalPointer(X, is), Xs),
    length(Xs, LenI),
    write('There are '), write(LenI), writeln(' IS pointers').

statIsNotPointer :-
    findall(X, finalPointer(X, isnot), Xs),
    length(Xs, LenN),
    write('There are '), write(LenN), writeln(' ISNOT pointers').

statTopPointer :-
    findall(X, finalPointer(X, top), Xs),
    length(Xs, LenT),
    write('There are '), write(LenT), writeln(' TOP pointers').

statBottomPointer :-
    findall(X, finalPointer(X, bottom), Xs),
    length(Xs, LenB),
    write('There are '), write(LenB), writeln(' BOTTOM pointers').

reportPointerStats :-   
    statIsPointer,
    statIsNotPointer,
    statTopPointer,
    statBottomPointer.

statIsSigned :-
    findall(X, finalSigned(X, is), Xs),
    length(Xs, Len),
    write('There are '), write(Len), writeln(' IS signed').

statIsNotSigned :-
    findall(X, finalSigned(X, isnot), Xs),
    length(Xs, Len),
    write('There are '), write(Len), writeln(' ISNOT signed').

statTopSigned :-
    findall(X, finalSigned(X, top), Xs),
    length(Xs, Len),
    write('There are '), write(Len), writeln(' TOP signed').

statBottomSigned :-
    findall(X, finalPointer(X, bottom), Xs),
    length(Xs, Len),
    write('There are '), write(Len), writeln(' BOTTOM signed').

reportSignedStats :-   
    statIsSigned,
    statIsNotSigned,
    statTopSigned,
    statBottomSigned.

reportRawStats :-
    writeln('---- Raw Counts ----'),
    reportPointerStats, reportSignedStats. 
    



reportNotUsedInOp(X) :-
    write('*** Treenode '), write(X), writeln(' was not used in an operation.').

validateNotUsedInOp :-
    setof([X], notUsedInOp(X), Set),
    maplistm(reportNotUsedInOp, Set)
    ;
    true.

missingBitwidth(X) :- usedInData(X), not(bitwidth(X, _)).

countMissingBitwidth :-
    setof(X, missingBitwidth(X), Set),
    length(Set, Len),
    write('*** There were '), write(Len), writeln(' treenodes that were missing bitwidths.')
    ;
    true.

reportMissingBitwidth(X) :-
    write('*** Treenode '), write(X), writeln(' was missing a bitwidth.').

validateMissingBitwidth :-
    setof([X], missingBitwidth(X), Set),
    maplistm(reportMissingBitwidth, Set)
    ;
    true.

%%  ==================================================================
%% Pointer validation

validateMissingPointers :-
    setof([T, L], expectedPointer(T, L), Set),
    maplistm(missingPointer, Set)
    ;
    true.

missingPointer(T, L) :-
    expectedPointer(T, L), not(finalPointer(T, L)),
    write('*** Could not find finalPointer for expectedPointer: treenode='), write(T),
    write(' pointerness='), writeln(L);
    true.

validateExtraPointers :-
    setof([T, L], finalPointer(T, L), Set),
    maplistm(extraPointer, Set)
    ;
    true.

extraPointer(T, L) :-
    finalPointer(T, L),
    not(expectedPointer(T, L)),
    write('*** Could not find expectedPointer for finalPointer: treenode='), write(T),
    write(' pointerness='), writeln(L);
    true.

%% ===================================================================
%% Signed validation

validateMissingSigned :-
    setof([T, L], expectedSigned(T, L), Set),
    maplistm(missingSigned, Set)
    ;
    true.

missingSigned(T, L) :-
    expectedSigned(T, L),
    not(finalSigned(T, L)),
    write('*** Could not find finalSigned for expectedSigned: treenode='), write(T),
    write(' signedness='), writeln(L);
    true.

validateExtraSigned :-
    setof([T, L], finalSigned(T, L), Set),
    maplistm(extraSigned, Set)
    ;
    true.

extraSigned(T, L) :-
    finalSigned(T, L),
    not(expectedSigned(T, L)),
    write('*** Could not find expectedSigned for finalSigned: treenode='), write(T), write(' signedness='), writeln(L);
    true.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
