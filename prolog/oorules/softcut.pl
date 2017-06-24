% Copyright 2017 Carnegie Mellon University.
% if_(I, T, E) implements the so-called soft cut, which has the
% following behavior.  If I can be proven, then if_(I, T, E) is
% equivalent to (I, T).  If I can not be proven, it is equivalent to
% (not(I), E).  Note that unlike the regular ->/2 operator,
% backtracking is performed inside of I, T, and E.

:- dynamic(if_counter/1).

if_counter(0).

:- dynamic(no_if_answer/1).
if_(If_0, Then_0, Else_0) :-
   once(if_counter(Id)),
   Idx is Id+1,
   (  Idx > Id -> true
   ;  throw(error(representation_error(max_integer),
               'XSB misses ISO conforming integers'))
   ),
   retractall(if_counter(_)),
   asserta(if_counter(Idx)),
   asserta(no_if_answer(Id)),
   (  If_0,
      retractall(no_if_answer(Id)),
      Then_0
   ;  retract(no_if_answer(Id)) ->
      Else_0
   ).

commit([H|T]) :-
    %debug('Commit to '), debug(H), debugln('?'),
    if_(H, true, commit(T)).

or([H|T]) :-
    %(debug('Or: '), debugln(H), H);
    H;
    or(T).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
