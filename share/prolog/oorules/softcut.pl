% Copyright 2017 Carnegie Mellon University.
% if_(I, T, E) implements the so-called soft cut, which has the
% following behavior.  If I can be proven, then if_(I, T, E) is
% equivalent to (I, T).  If I can not be proven, it is equivalent to
% (not(I), E).  Note that unlike the regular ->/2 operator,
% backtracking is performed inside of I, T, and E.

:- meta_predicate
   if_(0,0,0),
   or(:).

if_(If, Then, Else) :-
   (   '*->'(If, Then)                  % XSB compatible syntax
   ;   Else
   ).

or(M:List) :-
   or(M, List).

or(M, [H|T]) :-
    %(debug('Or: '), debugln(H), H);
   (   M:H
   ;   or(M:T)
   ).

user:goal_expansion(if_(If,Then,Else),
                    ('*->'(If, Then) ; Else)).


/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
