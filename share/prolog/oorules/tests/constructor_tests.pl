% Copyright 2026 Carnegie Mellon University.

:- ensure_loaded('../setup').

% Constructor candidacy depends on the ABI, so each block installs its own fileInfo/4.  The
% method facts are shared: every candidate has noCallsBefore, and they differ only in whether
% they return the this-pointer and whether they write a vftable.
setupConstructorTests(ABI) :-
    assertz(fileInfo('00000000000000000000000000000000', test_file, ABI, 0x4)),
    assertz(noCallsBefore(test_returns_self)),
    assertz(returnsSelf(test_returns_self)),
    assertz(noCallsBefore(test_vftable)),
    assertz(possibleVFTableWrite(test_insn_1, test_vftable, test_thisptr,
                                 0, test_thisptr, test_table)),
    assertz(noCallsBefore(test_returns_self_vftable)),
    assertz(returnsSelf(test_returns_self_vftable)),
    assertz(possibleVFTableWrite(test_insn_2, test_returns_self_vftable, test_thisptr,
                                 0, test_thisptr, test_table)),
    assertz(noCallsBefore(test_bare)),
    assertz(symbolProperty(test_symbol, constructor)).

cleanupConstructorTests :-
    retractall(fileInfo(_, test_file, _, _)),
    retractall(noCallsBefore(_)),
    retractall(returnsSelf(_)),
    retractall(possibleVFTableWrite(_, _, _, _, _, _)),
    retractall(symbolProperty(_, _)),
    abolish_all_tables.

:- begin_tests(possible_constructor_msvc,
               [setup(setupConstructorTests('MSVC_32')),
                cleanup(cleanupConstructorTests)]).

test(returns_self_is_a_candidate) :-
    assertion(possibleConstructor(test_returns_self)).

% Without returnsSelf a MSVC method is not a candidate, even though it writes a vftable.  This
% is the pre-existing behavior that issue #346 must not disturb.
test(vftable_write_alone_is_not_enough, [fail]) :-
    possibleConstructor(test_vftable).

test(bare_method_is_not_a_candidate, [fail]) :-
    possibleConstructor(test_bare).

test(symbol_is_a_candidate) :-
    assertion(possibleConstructor(test_symbol)).

:- end_tests(possible_constructor_msvc).

:- begin_tests(possible_constructor_itanium,
               [setup(setupConstructorTests('SYSV_64')),
                cleanup(cleanupConstructorTests)]).

% Itanium constructors usually return void, so a vftable write stands in for returnsSelf.
test(vftable_write_is_a_candidate) :-
    assertion(possibleConstructor(test_vftable)).

% An Itanium constructor may still leave the this-pointer in rax incidentally, so returnsSelf
% remains evidence here rather than being ABI-specific to MSVC.
test(returns_self_is_a_candidate) :-
    assertion(possibleConstructor(test_returns_self)).

test(returns_self_and_vftable_write_is_a_candidate) :-
    assertion(possibleConstructor(test_returns_self_vftable)).

test(bare_method_is_not_a_candidate, [fail]) :-
    possibleConstructor(test_bare).

test(symbol_is_a_candidate) :-
    assertion(possibleConstructor(test_symbol)).

:- end_tests(possible_constructor_itanium).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
