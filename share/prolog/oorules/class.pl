% ============================================================================================
% Rules for tracking which methods are assigned to which classes.
% ============================================================================================

:- use_module(library(apply), [maplist/2, include/3]).
:- use_module(library(lists), [member/2]).

make(M) :-
    try_assert(findint(M, M)).

unionhelp(Rold, Rnew, M) :-
    try_retract(findint(M, Rold)),
    try_assert(findint(M, Rnew)).

union(M1, M2) :-

    % Rnew is the new representative for everybody!
    find(M1, Rnew),
    % Rold is the old representative
    find(M2, Rold),

    % Let's move all the members in S2 to S1.
    findall(M2, S2),

    maplist(unionhelp(Rold, Rnew),
            S2).

makeIfNecessary(M) :-
    findint(M, _S) -> true;
    (make(M),
     logerror('Error: Unknown method '), logerrorln(M)).

find(M, R) :-
    findint(M, R).

findVFTable(V, R) :-
    findint(V, R),
    factVFTable(V).

findVFTable(VFTable, Offset, Class) :-
    findVFTable(VFTable, Class),
    factVFTableWrite(_Insn, Method, Offset, VFTable),
    find(Method, Class).

findMethod(M, R) :-
    findint(M, R),
    factMethod(M).

% Find all objects on M's class
findall(M, S) :-
    find(M, R),
    setof(X, find(X, R), S).

% Filter out non-methods...
findallMethods(C, O) :- findall(C, L), include(factMethod, L, O).

numberOfMethods(C, O) :- findallMethods(C, L),
                         length(L, O).

findAllClasses(S) :-
    setof(C, M^find(M, C), S).

class(C) :-
    findAllClasses(S),
    member(C, S).

is_singleton(M) :-
    find(M, M), % Quick check

    once(findnsols(2, OM, find(OM, M), L)),
    length(L, 1).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
