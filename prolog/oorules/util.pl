% Copyright 2017 Carnegie Mellon University.
% ============================================================================================
% Basic utilities for Prolog.
% ============================================================================================

% This is a "safe" replacement for dif() for when tabling is enabled.
iso_dif(X, Y) :-
   X \== Y,
   ( X \= Y -> true
   ;
   machine:xsb_backtrace(B),
   error_handler:print_backtrace(B),
   write('X='), write(X), write(' Y='), writeln(Y),
   throw(error(instantiation_error,iso_dif/2))
   ).

% list_min([5,2,8,1,4], Min). unifies Min with 1.
list_min([], X, X). % Termination rule.
list_min([H|T], M, X) :- H =< M, list_min(T, H, X).
list_min([H|T], M, X) :- M < H, list_min(T, M, X).
list_min([H|T], X) :- list_min(T, H, X). % Starting rule.

% list_max([5,2,8,1,4], Max). unifies Max with 8.
list_max([], R, R). % Termination rule.
list_max([H|T], M, R):- H > M, list_max(T, H, R).
list_max([H|T], M, R):- H =< M, list_max(T, M, R).
list_max([H|T], R):- list_max(T, H, R). % Starting rule.

% ============================================================================================
% Replace an element in a list with a new value (if it matches)
% ============================================================================================

% Prepend initial reversed list to second list, resulting in third list
putback([], X, X).
putback([H|T], X, Y) :-
    putback(T, [H|X], Y).

% Handle invalid index (low)
replace_ith(_, _, X, _, _, _) :-
    X < 1, error_handler:domain_error(length, X, replace_ith/5, 2).
% Handle invalid index (high)
replace_ith(_, [], _, _, _, _) :-
    error_handler:domain_error(length, i, replace_ith/5, 2).
% Base case
replace_ith(R, [E|L], 1, E1, E2, L2) :-
    !, E = E1, putback(R, [E2|L], L2).
% Inductive case
replace_ith(R, [E|L], I, E1, E2, L2) :-
    N is I - 1,
    replace_ith([E|R], L, N, E1, E2, L2).

% replace in L1 the I-th element which unifies with E1 with E2 resulting in L2
% replace the I-th element in L1, which must be E1 with E2, returning the new list in L2
replace_ith(L1, I, E1, E2, L2) :-
    replace_ith([], L1, I, E1, E2, L2).

% ============================================================================================
% A multi-argument implementation of maplist.
% Implemented the way Cory would have liked the standard maplist to work.
% ============================================================================================

% Use it like this:
%   setof([X, Y], criteria(X, Y), Set),
%   maplistm(rule, Set).
% Where rule is:
%   rule(X, Y) :- ...

maplistm(Goal, List) :-
    maplistm2(List, Goal).

maplistm2([], _).
maplistm2([Elem|Tail], Goal) :-
    basics:append([Goal], Elem, GoalWithParamsList),
    GoalWithParams =.. GoalWithParamsList,
    call(GoalWithParams),
    maplistm2(Tail, Goal).

% ============================================================================================
% ============================================================================================

:- dynamic debuggingEnabled/0.
:- dynamic debuggingStoreEnabled/0.

debug(X) :-
    debuggingEnabled -> write(X) ; true.

debugln(X) :-
    debuggingEnabled -> writeln(X) ; true.

debug_time(X) :-
    debuggingEnabled ->
    scrptutl:date(date(_Year, _Month, _Day, Hour, Min, Sec)),
    HourSeconds is Hour * 3600,
    MinuteSeconds is Min * 60,
    Seconds is HourSeconds + MinuteSeconds + Sec,
    write(X), writeln(Seconds)
    ; true.

debug_store(X) :-
    debuggingStoreEnabled -> show_store(X) ; true.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
