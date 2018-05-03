% Copyright 2017 Carnegie Mellon University.
% ============================================================================================
% Basic utilities for Prolog.
% ============================================================================================

:- import append/3 from lists.
:- import member/2 from lists.

%% list_to_set from SWI prolog
%% Converts list to set but maintains order of left-most occurrences

:- import keysort/2 from setof.
:- import parsort/4 from machine.

list_to_set(List, Set) :-
    number_list(List, 1, Numbered),
    keysort(Numbered, ONum),
    remove_dup_keys(ONum, NumSet),
    parsort(NumSet, [asc(2)], 0, ONumSet),
    pairs_keys(ONumSet, Set).

number_list([], _, []).
number_list([H|T0], N, [H-N|T]) :-
    N1 is N+1,
    number_list(T0, N1, T).

remove_dup_keys([], []).
remove_dup_keys([H|T0], [H|T]) :-
    H = V-_,
    remove_same_key(T0, V, T1),
    remove_dup_keys(T1, T).

remove_same_key([V1-_|T0], V, T) :-
    V1 == V,
    !,
    remove_same_key(T0, V, T).
remove_same_key(L, _, L).

pairs_keys([], []).
pairs_keys([K-_|T0], [K|T]) :-
    pairs_keys(T0, T).

osetof(A, B, C) :-
    bagof(A, B, Cp),
    list_to_set(Cp, C).

%% end list_to_set

tuple_to_list((A,B), L) :-
    !,
    tuple_to_list(A, L0),
    tuple_to_list(B, L1),
    append(L0, L1, L).
tuple_to_list(A, [A]).

% Call all predicates in list
all([]).
all([H|T]) :-
    %write('I am now calling '), writeln(H),
    call(H),
    all(T).

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
% XWAM maximu integer sillyness.
% ============================================================================================

% XWAM files can't store 0xffffffff, or apparently anything larger than 0x7fffffff, so we have
% to do this at runtime.  We should probably rethink this so that it works for 32-bit and
% 64-bit values somehow.  Right now it returns 0xffffffff for negative(1, r), which was the
% immediate goal.

negative(N, R) :-
    R is 0x7fffffff + 0x7fffffff + 2 - N.

% ============================================================================================
% Debugging and printing.
% ============================================================================================

logfatal(X) :- log('FATAL', X).
logerror(X) :- log('ERROR', X).
logwarn(X) :- log('WARN', X).
loginfo(X) :- log('INFO', X).
logdebug(X) :- log('WHERE', X).
logtrace(X) :- log('TRACE', X).

logfatalln(X) :- logln('FATAL', X).
logerrorln(X) :- logln('ERROR', X).
logwarnln(X) :- logln('WARN', X).
loginfoln(X) :- logln('INFO', X).
logdebugln(X) :- logln('WHERE', X).
logtraceln(X) :- logln('TRACE', X).

writeHexList_([X|Rest]) :-
    writeHex(X),
    (Rest \= [] -> write(', '), writeHexList_(Rest) ; true).

writeHex(L) :-
    is_list(L), !,
    write('['),
    writeHexList_(L),
    write(']').

writeHex(T) :-
    functor(T, _, Arity), Arity > 0,
    !,
    T =.. [Functor|Arguments],
    write(Functor),
    write('('),
    writeHex(Arguments),
    write(')').

writeHex(X) :-
    (integer(X), iso_dif(X, 0)) ->
        fmt_write('0x%x', X)
    ;
    write(X).

writelnHex(X) :-
    writeHex(X),
    writeln('').

:- dynamic debuggingEnabled/0.
:- dynamic debuggingStoreEnabled/0.

debug(X) :-
    debuggingEnabled -> writeHex(X) ; true.

debugln(X) :-
    debuggingEnabled -> writelnHex(X) ; true.

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
