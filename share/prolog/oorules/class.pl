% ============================================================================================
% Rules for tracking which methods are assigned to which classes.
% ============================================================================================

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
     debug('Error: Unknown method '), debugln(M)).

find(M, R) :-
    findint(M, R).

findall(M, S) :-
    find(M, R),
    setof(X, find(X, R), S).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
