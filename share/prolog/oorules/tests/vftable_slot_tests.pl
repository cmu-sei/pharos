% Copyright 2026 Carnegie Mellon University.

:- ensure_loaded('../setup').

% NULL slots reach Prolog through the ordinary write-seeded path, not just through a VTT: GCC
% zeroes the destructor pair of any abstract class, whose table its own constructor installs.
% Three written tables, separated by gaps in initialMemory so no walk runs into the next:
%
%   0x10000  the destructor pair sits in the middle, between two methods.
%   0x10100  the destructor was declared first, so the table opens on two NULLs.
%   0x10200  a displaced primary slot abuts a destructor pair, giving a run of three.
setupSlotTests(ABI) :-
    assertz(fileInfo('00000000000000000000000000000000', test_file, ABI, 8)),

    assertz(possibleVFTableWrite(test_insn_1, test_ctor_1, test_thisptr, 0, test_thisptr, 0x10000)),
    assertz(initialMemory(0x10000, 0x2000)),
    assertz(initialMemory(0x10008, 0)),
    assertz(initialMemory(0x10010, 0)),
    assertz(initialMemory(0x10018, 0x2010)),

    assertz(possibleVFTableWrite(test_insn_2, test_ctor_2, test_thisptr, 0, test_thisptr, 0x10100)),
    assertz(initialMemory(0x10100, 0)),
    assertz(initialMemory(0x10108, 0)),
    assertz(initialMemory(0x10110, 0x2020)),
    assertz(initialMemory(0x10118, 0x2030)),

    assertz(possibleVFTableWrite(test_insn_3, test_ctor_3, test_thisptr, 0, test_thisptr, 0x10200)),
    assertz(initialMemory(0x10200, 0x2040)),
    assertz(initialMemory(0x10208, 0)),
    assertz(initialMemory(0x10210, 0)),
    assertz(initialMemory(0x10218, 0)),
    assertz(initialMemory(0x10220, 0x2050)).

setupSlotTests(ABI, proven) :-
    setupSlotTests(ABI),
    assertz(factVFTable(0x10000)),
    assertz(factVFTable(0x10100)).

% The chain reasonNOTVFTableEntry_C walks has to cross the NULL pair at 0x10008 and 0x10010.
setupSlotTests(ABI, proven, disproved) :-
    setupSlotTests(ABI, proven),
    assertz(factNOTVFTableEntry(0x10000, 0, 0x2000)).

vFTableSlots(VFTable, Offsets) :-
    findall(Offset, possibleVFTableSlot(VFTable, Offset), Unsorted),
    msort(Unsorted, Offsets).

vFTableEntries(VFTable, Entries) :-
    findall(Offset-Entry, possibleVFTableEntry(VFTable, Offset, Entry), Unsorted),
    msort(Unsorted, Entries).

cleanupSlotTests :-
    retractall(fileInfo(_, test_file, _, _)),
    retractall(possibleVFTableWrite(_, _, _, _, _, _)),
    retractall(initialMemory(_, _)),
    retractall(factVFTable(_)),
    retractall(factNOTVFTableEntry(_, _, _)),
    abolish_all_tables.

:- begin_tests(itanium_null_slots,
               [setup(setupSlotTests('SYSV_64')), cleanup(cleanupSlotTests)]).

% The walk used to stop dead on the first NULL, losing every entry above it.
test(walk_crosses_an_interior_null_pair) :-
    vFTableSlots(0x10000, Slots),
    assertion(Slots == [0, 8, 0x10, 0x18]),
    vFTableEntries(0x10000, Entries),
    assertion(Entries == [0-0x2000, 0x18-0x2010]).

% Reporting a NULL as an entry would reach reasonMethod_G and make address zero a method.
test(null_slots_are_not_entries, [fail]) :-
    possibleVFTableEntry(_VFTable, _Offset, 0).

% The write-seeded clause used to apply no validity test, injecting possibleVFTableEntry(T,0,0).
test(offset_zero_null_is_not_an_entry, [fail]) :-
    possibleVFTableEntry(0x10100, 0, _Entry).

test(table_opening_on_nulls_still_finds_its_methods) :-
    vFTableEntries(0x10100, Entries),
    assertion(Entries == [0x10-0x2020, 0x18-0x2030]).

% Two of the three sources can abut, so a run is not bounded at two.
test(walk_crosses_a_run_of_three) :-
    vFTableEntries(0x10200, Entries),
    assertion(Entries == [0-0x2040, 0x20-0x2050]).

% Nothing bridges the gap in initialMemory between one table and the next.
test(walk_stops_at_the_end_of_initial_memory, [fail]) :-
    possibleVFTableSlot(0x10000, 0x20).

:- end_tests(itanium_null_slots).

:- begin_tests(itanium_null_slot_reasoning,
               [setup(setupSlotTests('SYSV_64', proven)), cleanup(cleanupSlotTests)]).

% Offset zero is the anchor whenever it holds a method.
test(anchor_is_offset_zero_when_it_is_an_entry) :-
    assertion(reasonVFTableEntry(0x10000, 0, 0x2000)).

% A table opening on NULLs has no entry at offset zero, so the lowest method slot anchors it.
test(anchor_moves_up_past_leading_nulls) :-
    assertion(reasonVFTableEntry(0x10100, 0x10, 0x2020)),
    assertion(not(reasonVFTableEntry(0x10100, 0x18, 0x2030))).

:- end_tests(itanium_null_slot_reasoning).

:- begin_tests(itanium_null_slot_invalidation,
               [setup(setupSlotTests('SYSV_64', proven, disproved)), cleanup(cleanupSlotTests)]).

% Stepping one pointer down from 0x18 lands on a NULL, which was never disproved because it is
% not an entry; contiguity is measured across slots, so the chain skips to 0.
test(invalidation_crosses_the_null_pair) :-
    assertion(precedingVFTableEntry(0x10000, 0x18, 0, 0x2000)),
    assertion(reasonNOTVFTableEntry_C(0x10000, 0x18, 0x2010)).

:- end_tests(itanium_null_slot_invalidation).

:- begin_tests(msvc_null_slots,
               [setup(setupSlotTests('MSVC_32')), cleanup(cleanupSlotTests)]).

% The same facts under MSVC, where a NULL still ends the table.  These prove the Itanium clause
% is genuinely gated rather than vacuously wider.
test(walk_truncates_at_the_first_null) :-
    vFTableSlots(0x10000, Slots),
    assertion(Slots == [0]),
    vFTableEntries(0x10000, Entries),
    assertion(Entries == [0-0x2000]).

test(table_opening_on_a_null_has_no_entries) :-
    vFTableEntries(0x10100, Entries),
    assertion(Entries == []).

test(run_of_three_is_not_crossed) :-
    vFTableEntries(0x10200, Entries),
    assertion(Entries == [0-0x2040]).

:- end_tests(msvc_null_slots).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
