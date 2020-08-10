% Copyright 2017-2020 Carnegie Mellon University.
% ============================================================================================
% Basic utilities for Prolog.
% ============================================================================================

:- use_module(library(lists), [append/3]).

sort_tuple((A,B), (C,D)) :-
    (A < B -> (C=A, D=B); (C=B, D=A)).

list_to_set(List, Set) :-
    number_list(List, 1, Numbered),
    keysort(Numbered, ONum),
    remove_dup_keys(ONum, NumSet),
    sort(2, @=<, NumSet, ONumSet),
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
    list_to_set(Cp, Cp2),
    (deterministicEnabled -> sort(Cp2, C); C = Cp2).

minof(A, B) :-
    deterministicEnabled
    ->
        (bagof(A, B, Cp),
         sort(Cp, Cp2),
         nth0(1, Cp2, A))
    ;   B.

%% end list_to_set

% ejs: This is basically List.filter
include(Goal, List, Included) :-
    include_(List, Goal, Included).

include_([], _, []).
include_([X1|Xs1], P, Included) :-
    (   call(P, X1)
        ->  Included = [X1|Included1]
        ;   Included = Included1
    ),
    include_(Xs1, P, Included1).

tuple_to_list((A,B), L) :-
    !,
    tuple_to_list(A, L0),
    tuple_to_list(B, L1),
    append(L0, L1, L).
tuple_to_list(A, [A]).

% Call all predicates in list
all(L) :-
    all_int(L).

all_debug(L) :-
    length(L, Len),
    logtraceln('Call to all/1 with ~D elements...', Len),
    cputime(BeforeTime),
    all_int(L),
    cputime(AfterTime),
    DiffTime is AfterTime - BeforeTime,
    logtraceln('~@... took ~D seconds on ~D elements (~f seconds avg).',
               [Avg is DiffTime / (Len + 1), DiffTime, Len, Avg]).

all_int([]).
all_int([H|T]) :-
    %write('I am now calling '), writeln(H),
    call(H),
    all_int(T).

% This is a "safe" replacement for dif() for when tabling is enabled.
iso_dif(X, Y) :-
   X \== Y,
   ( X \= Y -> true
   ;
   write('X='), write(X), write(' Y='), writeln(Y),
   throw_with_backtrace(error(instantiation_error,iso_dif/2))
   ).

% list_min([5,2,8,1,4], Min). unifies Min with 1.
list_min([], X, X). % Termination rule.
list_min([H|T], M, X) :- H =< M, !, list_min(T, H, X).
list_min([H|T], M, X) :- M < H, list_min(T, M, X).
list_min([H|T], X) :- list_min(T, H, X). % Starting rule.

% list_max([5,2,8,1,4], Max). unifies Max with 8.
list_max([], R, R). % Termination rule.
list_max([H|T], M, R):- H > M, !, list_max(T, H, R).
list_max([H|T], M, R):- H =< M, list_max(T, M, R).
list_max([H|T], R):- list_max(T, H, R). % Starting rule.

% atmost(G, N) allows no more than N backtracks through G.

atmost(G, N) :-
    set_flag(atmost(G), 0),
    !,
    atmost_internal(G, N).

atmost_internal(G, Nmax) :-
    % Do the call
    call(G),
    (
        % Normal forward direction, don't need to do anything
        true
    ;
    (
        % We are backtracking here for another answer.  Check to see if we have hit our limit.

        get_flag(atmost(G), N),

        % If N < Nmax, we will fail and continue backtracking into G.
        % If N = Nmax, we will cut and will fail without backtracking.
        N = Nmax, !
    )),

    % Increment the flag and check the value
    get_flag(atmost(G), N),
    N < Nmax,
    flag(atmost(G), N, N+1).

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
    append([Goal], Elem, GoalWithParamsList),
    GoalWithParams =.. GoalWithParamsList,
    call(GoalWithParams),
    maplistm2(Tail, Goal).

% ============================================================================================
% XWAM maximum integer sillyness.
% ============================================================================================

% XWAM files can't store 0xffffffff, or apparently anything larger than 0x7fffffff, so we have
% to do this at runtime.  We should probably rethink this so that it works for 32-bit and
% 64-bit values somehow.  Right now it returns 0xffffffff for negative(1, r), which was the
% immediate goal.

negative(N, R) :-
    R is 0x7fffffff + 0x7fffffff + 2 - N.

% Bit mask testing.
bitmask_check(Value, BitMask) :-
    Result is Value /\ BitMask,
    Result == BitMask.


% ============================================================================================
% Load dynamic predicates from a file (basis of validated loading in facts.pl and results.pl)
% ============================================================================================

true_(_) :- true.

loadPredicates(File) :-
    loadPredicates(File, true_).

loadPredicates(File, Verifier) :-
    setup_call_cleanup(
        open(File, read, Stream),
        readPredicates(Stream, Verifier),
        close(Stream)).

readPredicates(Stream, Verifier) :-
    repeat,
    read(Stream, Pred),
    ( Pred = end_of_file -> !
    ; assertPredicate(Pred, Verifier), fail).


assertPredicate(Pred, Verifier) :- !,
    (call(Verifier, Pred) -> assert(Pred) ;
     (functor(Pred, Name, Arity),
      logfatalln('Invalid predicate: ~a/~d = ~Q', [Name, Arity, Pred]),
      % We should really learn how to throw and format the exception properly.
      %throw(error(bad_fact(Name/Arity))),
      halt(1)
     )
    ).

% ============================================================================================
% Miscellaneous.
% ============================================================================================

debug_time(X) :-
    scrptutl:date(date(_Year, _Month, _Day, Hour, Min, Sec)),
    HourSeconds is Hour * 3600,
    MinuteSeconds is Min * 60,
    Seconds is HourSeconds + MinuteSeconds + Sec,
    write(X), writeln(Seconds)
    ; true.

debug_store(X) :-
    debuggingStoreEnabled -> show_store(X) ; true.

show_progress :-
    logdebugln('-------------------------------------------'),
    statistics(cputime, T),
    get_flag(numfacts,FN),
    get_flag(guesses,GN),
    get_flag(reasonForwardSteps,RFN),
    logdebugln('total number of facts is'(FN,T)),
    logdebugln('total number of guesses is'(GN,T)),
    logdebugln('total number of reasoningForward steps is'(RFN,T)),
    statistics.


throw_with_backtrace(Throw) :-
    backtrace(100),
    throw(Throw).

shut_down :-
    show_progress, halt.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
