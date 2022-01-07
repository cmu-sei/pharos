% Copyright 2017-2020 Carnegie Mellon University.
% ============================================================================================
% Basic utilities for Prolog.
% ============================================================================================

:- use_module(library(lists), [append/3, nth1/4, list_to_set/2]).

sort_tuple((A,B), (C,D)) :-
    (A < B -> (C=A, D=B); (C=B, D=A)).

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
    BeforeTime is cputime,
    all_int(L),
    AfterTime is cputime,
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

% atmost(G, N) allows no more than N backtracks through G.

:- meta_predicate atmost(0, ?).
atmost(G, N) :-
    set_flag(atmost(G), 0),
    !,
    atmost_internal(G, N).

:- meta_predicate atmost_internal(0, ?).
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

% replace in L1 the I-th element which unifies with E1 with E2 resulting in L2
% replace the I-th element in L1, which must be E1 with E2, returning the new list in L2
replace_ith(L1, I, E1, E2, L2) :-
    nth1(I, L1, E1, R),
    nth1(I, L2, E2, R).

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
    GoalWithParams =.. [Goal|Elem],
    call(GoalWithParams),
    maplistm2(Tail, Goal).

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

loadPredicates(stream(Stream), Verifier) :-
    readPredicates(Stream, Verifier).

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
    get_time(SecondsFloat),
    Seconds is truncate(SecondsFloat),
    write(X), writeln(Seconds)
    ; true.

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
    get_prolog_backtrace(100, Backtrace, [goal_term_depth(100)]),
    print_prolog_backtrace(user_error, Backtrace),
    throw(Throw).

shut_down :-
    show_progress, halt.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
