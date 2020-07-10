% -*- Mode: Prolog -*-

% terms_compare(+FileA, +FileB)
%
% Main entry point.  Compare FileA to FileB.  Output the results.
% Returns 0 if the files are equivalant, 1 if terms have been added or
% removed, or 3 if a variable ambiguity is found.  In the latter case,
% it will report only one ambiguity with one piece of evidence.
terms_compare(FileA, FileB) :-
    %% Remove old mappings (useful when debugging)
    abolish_mappings,
    %% Load the terms
    load_terms(FileA, FileB),
    %% Determine the sv_ variable mapping
    map_vars(VarMap),
    %% Set up term -> term and var -> var mappings
    build_mappings(VarMap),
    %% Warn for ambiguous variable mappings
    check_duplicates(FileA, FileB, RV),
    %% Determine list of removed facts
    changes(filea, termmapba, Removed),
    %% Determine list of added facts
    changes(fileb, termmapab, Added),
    %% Report the results
    report_changes(Added, Removed),
    %% Output differing facts
    error_if_different(Added, Removed),
    halt(RV).

check_duplicates(FileA, FileB, 3) :-
    warn_duplicates(FileA, FileB, varmapab).
check_duplicates(FileA, FileB, 3) :-
    warn_duplicates(FileB, FileA, varmapba).
check_duplicates(_, _, 0).

is_xvar(X) :-
    atom(X),
    sub_atom(X, 0, 3, _, 'sv_').

% facts_equal(+FactA, +FactB, -[ListOfVariablePairs])
facts_equal(X, X, [Z]-Z) :-
    !.
facts_equal(X, Y, [pair(X, Y)|Z]-Z) :-
    is_xvar(X),
    is_xvar(Y),
    !.
facts_equal(X, Y, Z) :-
    compound(X),
    compound(Y),
    X =.. Xp,
    Y =.. Yp,
    fact_list_equal(Xp, Yp, Z),
    !.
fact_list_equal([], [], [C]-C).
fact_list_equal([Ha|Ta], [Hb|Tb], A-C) :-
    facts_equal(Ha, Hb, A-B),
    fact_list_equal(Ta, Tb, B-C).

% terms(+Filename, +Predicate)
%
% Reads terms from Filename and asserts Predicate/1 on each term
terms(File, Pred) :-
    open(File, read, Stream),
    read_terms(Stream, Pred),
    !,
    close(Stream).
handle_term(_, end_of_file, _) :- !.
handle_term(S, T, P) :-
    X =.. [P, T],
    assert(X),
    read_terms(S, P).
read_terms(S, P) :-
    read(S, T),
    handle_term(S, T, P).

map_vars(VarMap) :-
    findall(map(A, B, Vars),(filea(A),fileb(B),facts_equal(A, B, Vars)),VarMap).

reset(X) :-
    abolish(X),
    dynamic(X).

abolish_mappings :-
    reset(filea/1),
    reset(fileb/1),
    reset(varmapab/3),
    reset(varmapba/3),
    reset(termmapab/2),
    reset(termmapba/2).

build_mappings([]).
build_mappings([map(A, B, [Z]-Z)|R]) :-
    assert(termmapab(A, B)),
    assert(termmapba(B, A)),
    build_mappings(R).
build_mappings([map(A, B, [pair(Va, Vb)|Vr]-Z)|R]) :-
    assert(varmapab(Va, Vb, pair(A, B))),
    assert(varmapba(Vb, Va, pair(B, A))),
    build_mappings([map(A, B, Vr-Z)|R]).

load_terms(FileA, FileB) :-
    terms(FileA, filea),
    terms(FileB, fileb).

report_changes(Added, Removed) :-
    length(Added, LenA),
    length(Removed, LenB),
    write('% '),
    write(LenA),
    write(' facts added, '),
    write(LenB),
    writeln(' facts removed.').

error_if_different([], []).
error_if_different([], Removed) :-
    output_differences('Removed', Removed),
    halt(1).
error_if_different(Added, Removed) :-
    output_differences('Added', Added),
    error_if_different([], Removed),
    halt(1).

output_differences([]).
output_differences([F|R]) :-
    writeln_term(F),
    output_differences(R).

output_differences(Type, Facts) :-
    write('% '),
    writeln(Type),
    output_differences(Facts).

find_duplicate(P, A, B1, C1, B2, C2) :-
    X =.. [P, A, B1, C1],
    Y =.. [P, A, B2, C2],
    X,
    Y,
    B1 \= B2.

warn_duplicates(FileA, FileB, Map) :-
    find_duplicate(Map, A, B1, pair(F1a, F1b), B2, pair(F2a, F2b)),
    write('In '),
    write(FileA),
    writeln(','),
    write('the variable '),
    write(A),
    write(' maps to '),
    write(B1),
    write(' and '),
    writeln(B2),
    write('from '),
    write(FileB),
    writeln('.'),
    writeln('This is due to the following rules from '),
    write(FileA),
    writeln(':'),
    write('  '),
    writeln_term(F1a),
    write('  '),
    writeln_term(F2a),
    write('and these rules from '),
    write(FileB),
    writeln(':'),
    write('  '),
    writeln_term(F1b),
    write('  '),
    writeln_term(F2b),
    nl.

changes(List, Map, Result) :-
    L =.. [List, A],
    M =.. [Map, _, A],
    setof(A, (L, \+ M), Result).
changes(_, _, []).

integers_as_hex(0, _) :-
    !, false.
integers_as_hex(X, _) :-
    integer(X),
    (X < 0 ->
         (Y is X * -1, format('-0x~16r', [Y]));
     format('0x~16r', [X])).

writeln_term(X) :-
    write_term(X, [quoted(true), spacing(next_argument), fullstop(true),
                   nl(true), portray_goal(integers_as_hex)]).



