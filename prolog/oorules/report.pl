% A module for reporting the results of object matching.  This probably won't be used in the
% production tool, but it should be useful for interactive debugging of the Prolog
% infrastructure, and perhaps more importantly, it serves to define what an "answer" is for
% when it comes time to import the results back into Objdigger.

:- import maplist/2 from swi.

writeHelper([]).
writeHelper([H|[]]) :-
    write(H).
writeHelper([H|T]) :-
    write(H), write(', '), writeHelper(T).
writeList(L) :-
    write('['), writeHelper(L), write(']').

% This definition of progress is for when we're NOT running from within Objdigger, which is
% probably the same circumstances where we want this reporting module.
progress(N) :-
  debug('There are '), debug(N), debugln(' known facts.').

% ============================================================================================
% Virtual Function Tables
% ============================================================================================

reportFinalVFTable((V, C, L, A, N)) :-
    %finalVFTable(V, C, L, A, N),
    write('finalVFTable('),
    write(V), write(', '),
    write(C), write(', '),
    write(L), write(', '),
    write(A), write(', '),
    write('\''), write(N), write('\''), writeln(').').

reportVFTables :-
    setof((V, C, L, A, N), finalVFTable(V, C, L, A, N), Set),
    maplist(reportFinalVFTable, Set).
reportVFTables :- true.

% ============================================================================================
% Class Definitions
% ============================================================================================

reportFinalClass((C, V, S, L, R, M)) :-
    %finalClass(C, V, S, L, R, M),
    write('finalClass('),
    write(C), write(', '),
    write(V), write(', '),
    write(S), write(', '),
    write(L), write(', '),
    write(R), write(', '),
    writeList(M), writeln(').').

reportClasses :-
    setof((C, V, S, L, R, M), finalClass(C, V, S, L, R, M), Set),
    maplist(reportFinalClass, Set).
reportClasses :- true.

% ============================================================================================
% Resolved Virtual Function Calls
% ============================================================================================

reportFinalResolvedVirtualCall((I, V, T)) :-
    write('finalResolvedVirtualCall('),
    write(I), write(', '),
    write(V), write(', '),
    write(T), writeln(').').

reportResolvedVirtualCalls :-
    setof((I, V, T), finalResolvedVirtualCall(I, V, T), Set),
    maplist(reportFinalResolvedVirtualCall, Set).
reportResolvedVirtualCalls :- true.

% ============================================================================================
% Embedded objects.
% ============================================================================================

reportFinalEmbeddedObject((C, O, E, X)) :-
    %finalEmbeddedObject(C, O, E, X),
    write('finalEmbeddedObject('),
    write(C), write(', '),
    write(O), write(', '),
    write(E), write(', '),
    write(X), writeln(').').

reportEmbeddedObjects :-
    setof((C, O, E, X), finalEmbeddedObject(C, O, E, X), Set),
    maplist(reportFinalEmbeddedObject, Set).
reportEmbeddedObjects :- true.

% ============================================================================================
% Inheritance relationships
% ============================================================================================

reportFinalInheritance((D, B, O, C, V)) :-
    %finalInheritance(D, B, O, C, V),
    write('finalInheritance('),
    write(D), write(', '),
    write(B), write(', '),
    write(O), write(', '),
    write(C), write(', '),
    write(V), writeln(').').

reportInheritances :-
    setof((D, B, O, C, V), finalInheritance(D, B, O, C, V), Set),
    maplist(reportFinalInheritance, Set).
reportInheritances :- true.

% ============================================================================================
% Definitions of members on classes.
% ============================================================================================

reportFinalMember((C, O, S, L)) :-
    % this call to finalMember is redundant
    % finalMember(C, O, S, L),
    write('finalMember('),
    write(C), write(', '),
    write(O), write(', '),
    writeList(S), write(', '),
    write(L), writeln(').').

reportMembers :-
    setof((C, O, S, L), finalMember(C, O, S, L), Set),
    maplist(reportFinalMember, Set).
reportMembers :- true.

% ============================================================================================
% Definitions of members on classes.
% ============================================================================================

reportFinalMemberAccess((C, O, S, E)) :-
    write('finalMemberAccess('),
    write(C), write(', '),
    write(O), write(', '),
    write(S), write(', '),
    writeList(E), writeln(').').

reportMemberAccesses :-
    setof((C, O, S, E), finalMemberAccess(C, O, S, E), Set),
    maplist(reportFinalMemberAccess, Set).
reportMemberAccesses :- true.

% ============================================================================================
% Method Properties
% ============================================================================================

reportFinalMethodProperty((M, P, C)) :-
    write('finalMethodProperty('),
    write(M), write(', '),
    write(P), write(', '),
    write(C), writeln(').').

reportMethodProperties :-
    setof((M, P, C), finalMethodProperty(M, P, C), Set),
    maplist(reportFinalMethodProperty, Set).
reportMethodProperties :- true.

% ============================================================================================
% The main reporting rule.
% ============================================================================================

reportResults :-
    reportGuessedStatistics,
    writeln('% Prolog results autogenerated by Objdigger.'),
    reportVFTables,
    reportClasses,
    reportResolvedVirtualCalls,
    reportEmbeddedObjects,
    reportInheritances,
    reportMembers,
    reportMemberAccesses,
    reportMethodProperties,
    % Cory would like for this line to go to stderr?
    writeln('% Object detection reporting complete.').

% ============================================================================================
% Rules for counting guesses at the end of execution.
% ============================================================================================

:- import length/2 from basics.

% Woot! Cory figured it out to count arbitary predicates all by himself! ;-)
count(Pred/Arity, N) :-
    functor(OldTerm, Pred, Arity),
    findall(1, OldTerm, L),
    length(L, N).

% Print how many conclusions were guessed versus how many were reasoned.  We could also report
% the actual specific guesssed facts if we wanted.
reportGuessedStatistics :-
    count(guessedMethod/1, GM), count(factMethod/1, FM),
    count(guessedNOTMethod/1, GNM), count(factNOTMethod/1, FNM),
    debug('Guessed methods '), debug(GM), debug(' of '), debug(FM),
    debug(', NOT: '), debug(GNM), debug(' of '), debugln(FNM),

    count(guessedConstructor/1, GC), count(factConstructor/1, FC),
    count(guessedNOTConstructor/1, GNC), count(factNOTConstructor/1, FNC),
    debug('Guessed constructors '), debug(GC), debug(' of '), debug(FC),
    debug(', NOT: '), debug(GNC), debug(' of '), debugln(FNC),

    count(guessedRealDestructor/1, GRD), count(factRealDestructor/1, FRD),
    count(guessedNOTRealDestructor/1, GNRD), count(factNOTRealDestructor/1, FNRD),
    debug('Guessed real destructors '), debug(GRD), debug(' of '), debug(FRD),
    debug(', NOT: '), debug(GNRD), debug(' of '), debugln(FNRD),

    count(guessedDeletingDestructor/1, GDD), count(factDeletingDestructor/1, FDD),
    count(guessedNOTDeletingDestructor/1, GNDD), count(factNOTDeletingDestructor/1, FNDD),
    debug('Guessed deleting destructors '), debug(GDD), debug(' of '), debug(FDD),
    debug(', NOT: '), debug(GNDD), debug(' of '), debugln(FNDD),

    count(guessedVirtualFunctionCall/5, GVFC), count(factVirtualFunctionCall/5, FVFC),
    count(guessedNOTVirtualFunctionCall/5, GNVFC), count(factNOTVirtualFunctionCall/5, FNVFC),
    debug('Guessed virtual function calls '), debug(GVFC), debug(' of '), debug(FVFC),
    debug(', NOT: '), debug(GNVFC), debug(' of '), debugln(FNVFC),

    count(guessedVFTable/1, GVFT), count(factVFTable/1, FVFT),
    count(guessedNOTVFTable/1, GNVFT), count(factNOTVFTable/1, FNVFT),
    debug('Guessed virtual function tables '), debug(GVFT), debug(' of '), debug(FVFT),
    debug(', NOT: '), debug(GNVFT), debug(' of '), debugln(FNVFT),

    count(guessedVFTableEntry/3, GVFTE), count(factVFTableEntry/3, FVFTE),
    count(guessedNOTVFTableEntry/3, GNVFTE), count(factNOTVFTableEntry/3, FNVFTE),
    debug('Guessed virtual function table entries '), debug(GVFTE), debug(' of '), debug(FVFTE),
    debug(', NOT: '), debug(GNVFTE), debug(' of '), debugln(FNVFTE),

    count(guessedDerivedClass/3, GDC), count(factDerivedClass/3, FDC),
    count(guessedNOTDerivedClass/3, GNDC), count(factNOTDerivedClass/3, FNDC),
    debug('Guessed derived classes '), debug(GDC), debug(' of '), debug(FDC),
    debug(', NOT: '), debug(GNDC), debug(' of '), debugln(FNDC),

    count(guessedEmbeddedObject/3, GEO), count(factEmbeddedObject/3, FEO),
    count(guessedNOTEmbeddedObject/3, GNEO), count(factNOTEmbeddedObject/3, FNEO),
    debug('Guessed embedded objects '), debug(GEO), debug(' of '), debug(FEO),
    debug(', NOT: '), debug(GNEO), debug(' of '), debugln(FNEO),

    count(guessedClassHasUnknownBase/1, GUBC), count(factClassHasUnknownBase/1, FUBC),
    count(guessedClassHasNoBase/1, GNBC), count(factClassHasNoBase/1, FNBC),
    debug('Guessed has a base class '), debug(GUBC), debug(' of '), debug(FUBC),
    debug(', NOT: '), debug(GNBC), debug(' of '), debugln(FNBC),

    count(guessedMergeClasses/2, GMC), count(factMergeClasses/2, FMC),
    count(guessedNOTMergeClasses/2, GNMC), count(factNOTMergeClasses/2, FNMC),
    debug('Guessed class mergers '), debug(GMC), debug(' of '), debug(FMC),
    debug(', NOT: '), debug(GNMC), debug(' of '), debugln(FNMC),

    true.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
