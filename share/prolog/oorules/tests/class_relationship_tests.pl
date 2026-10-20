% Copyright 2026 Carnegie Mellon University.

:- ensure_loaded('../setup').

setupRelationshipTests :-
    assertz(factObjectInObject(1, 2, 0)),
    assertz(factObjectInObject(2, 3, 0)),
    assertz(factObjectInObject(1, 4, 8)),
    assertz(factClassSizeLTE(1, 64)).

cleanupRelationshipTests :-
    retractall(factObjectInObject(_, _, _)),
    retractall(factClassSizeLTE(_, _)),
    abolish_all_tables.

:- begin_tests(class_relationship,
               [setup(setupRelationshipTests), cleanup(cleanupRelationshipTests)]).

test(bound_pair_reaches_transitive_base) :-
    once(reasonClassRelationship(1, 3)).

test(unrelated_pair, [fail]) :-
    reasonClassRelationship(4, 3).

test(enumerate_bases) :-
    setof(Base, reasonClassRelationship(1, Base), Bases),
    assertion(Bases == [2, 3, 4]).

test(enumerate_derived_classes) :-
    setof(Derived, reasonClassRelationship(Derived, 3), DerivedClasses),
    assertion(DerivedClasses == [1, 2]).

test(enumerate_pairs) :-
    setof(Derived-Base, reasonClassRelationship(Derived, Base), Pairs),
    assertion(Pairs == [1-2, 1-3, 1-4, 2-3]).

test(aliased_variables, [fail]) :-
    reasonClassRelationship(Class, Class).

test(reverse_query_propagates_size_limit) :-
    once(reasonClassSizeLTE_D(3, 64)).

test(bound_probes_reuse_table) :-
    abolish_all_tables,
    once(reasonClassRelationship(1, 3)),
    \+ reasonClassRelationship(1, 99),
    findall(Base, current_table(user:reasonClassRelationship_internal(1, Base), _), Tables),
    assertion(Tables = [_]),
    Tables = [Only],
    assertion(var(Only)).

test(incremental_updates) :-
    \+ reasonClassRelationship(1, 5),
    assertz(user:factObjectInObject(3, 5, 0)),
    once(reasonClassRelationship(1, 5)),
    retractall(user:factObjectInObject(3, 5, 0)),
    \+ reasonClassRelationship(1, 5).

:- end_tests(class_relationship).
