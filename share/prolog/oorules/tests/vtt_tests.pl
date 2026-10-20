% Copyright 2026 Carnegie Mellon University.

:- ensure_loaded('../setup').

% One VTT at 0x20000 naming three tables:
%
%   0x10000  installed table, has a possibleVFTableWrite.  Two entries, no leading NULLs.
%   0x10040  construction table A.  Two zeroed destructor slots, then two methods.
%   0x10060  construction table B, starting immediately after the last slot of A.
%
% The VTT slots themselves are never initialMemory facts, matching what the exporter emits.
setupVTTTests(ABI) :-
    assertz(fileInfo('00000000000000000000000000000000', test_file, ABI, 8)),

    assertz(possibleVFTableWrite(test_insn, test_ctor, test_thisptr, 0, test_thisptr, 0x10000)),
    assertz(initialMemory(0x10000, 0x2000)),
    assertz(initialMemory(0x10008, 0x2010)),

    assertz(initialMemory(0x10040, 0)),
    assertz(initialMemory(0x10048, 0)),
    assertz(initialMemory(0x10050, 0x2020)),
    assertz(initialMemory(0x10058, 0x2030)),

    assertz(initialMemory(0x10060, 0)),
    assertz(initialMemory(0x10068, 0x2040)),

    assertz(factVFTable(0x10000)),
    assertz(factMethod(0x2020)).

setupVTTTests(ABI, vtt) :-
    setupVTTTests(ABI),
    assertz(possibleVTTEntry(0x20000, 0, 0x10000)),
    assertz(possibleVTTEntry(0x20000, 8, 0x10040)),
    assertz(possibleVTTEntry(0x20000, 0x10, 0x10060)).

% Entry reasoning presupposes the table has already been proven.
setupVTTTests(ABI, vtt, proven) :-
    setupVTTTests(ABI, vtt),
    assertz(factVFTable(0x10040)).

% possibleVFTableEntry/3 is tabled, so solutions arrive in table order rather than by offset.
vFTableEntries(VFTable, Entries) :-
    findall(Offset-Entry, possibleVFTableEntry(VFTable, Offset, Entry), Unsorted),
    msort(Unsorted, Entries).

cleanupVTTTests :-
    retractall(fileInfo(_, test_file, _, _)),
    retractall(possibleVFTableWrite(_, _, _, _, _, _)),
    retractall(possibleVTTEntry(_, _, _)),
    retractall(initialMemory(_, _)),
    retractall(factVFTable(_)),
    retractall(factMethod(_)),
    abolish_all_tables.

:- begin_tests(vtt_seeded_vftables,
               [setup(setupVTTTests('SYSV_64', vtt)), cleanup(cleanupVTTTests)]).

% The construction table is seeded even though nothing writes its address, and the walk steps
% over the zeroed destructor slots to reach the methods behind them.
test(construction_table_is_seeded) :-
    assertion(possibleVFTableEntry(0x10040, 0x10, 0x2020)),
    assertion(possibleVFTableEntry(0x10040, 0x18, 0x2030)).

% The tables sit back to back, so without the VTT boundary guard A would absorb B.
test(walk_stops_at_the_next_vtt_table, [fail]) :-
    possibleVFTableEntry(0x10040, 0x20, _Entry).

% B is reached from its own VTT slot rather than by falling out of A.
test(second_construction_table_is_seeded) :-
    assertion(possibleVFTableEntry(0x10060, 8, 0x2040)).

% A zeroed destructor slot is stepped over, never reported.  Reporting it would reach
% reasonMethod_G and make address zero a method.
test(null_slots_are_not_entries, [fail]) :-
    possibleVFTableEntry(_VFTable, _Offset, 0).

% A VTT entry that also has a possibleVFTableWrite behaves exactly as it does today.
test(installed_table_is_unchanged) :-
    vFTableEntries(0x10000, Entries),
    assertion(Entries == [0-0x2000, 8-0x2010]).

test(construction_table_is_a_guess_candidate) :-
    assertion(possibleVFTable(0x10040)).

% Entry zero of the VTT is the most-derived class' own primary table, and it is already known
% to be one, so the rest of the group is corroborated.
test(construction_table_is_reasoned) :-
    assertion(reasonVFTable(0x10040)),
    assertion(reasonVFTable(0x10060)).

:- end_tests(vtt_seeded_vftables).

:- begin_tests(vtt_proven_vftable,
               [setup(setupVTTTests('SYSV_64', vtt, proven)), cleanup(cleanupVTTTests)]).

% The construction table has no offset zero entry to anchor on, so the lowest slot holding a
% method stands in for it.  Nothing anchors the slots above it yet -- those come from the
% larger-entry rule once a size is known, or from guessing.
test(entry_anchors_at_the_lowest_method_slot) :-
    assertion(reasonVFTableEntry(0x10040, 0x10, 0x2020)),
    assertion(not(reasonVFTableEntry(0x10040, 0x18, 0x2030))).

:- end_tests(vtt_proven_vftable).

:- begin_tests(vtt_absent,
               [setup(setupVTTTests('MSVC_32')), cleanup(cleanupVTTTests)]).

% Without any possibleVTTEntry facts none of the new clauses can fire, so the write-seeded
% table is seeded exactly as before and the tables no instruction names stay invisible.
test(installed_table_is_unchanged) :-
    vFTableEntries(0x10000, Entries),
    assertion(Entries == [0-0x2000, 8-0x2010]).

test(unwritten_table_is_not_seeded, [fail]) :-
    possibleVFTableEntry(0x10040, _Offset, _Entry).

test(unwritten_table_is_not_reasoned, [fail]) :-
    reasonVFTable(0x10040).

:- end_tests(vtt_absent).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
