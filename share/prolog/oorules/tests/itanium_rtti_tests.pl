% Copyright 2026 Carnegie Mellon University.

:- ensure_loaded('../setup').

% A hierarchy shaped like the one GCC emits, with the records at 0x30000 and the tables at
% 0x10000.  Base is a plain class; Left derives from it; Right is a second plain class; Multi
% derives from both, so its group has a primary table and a secondary one for the Right
% subobject eight bytes into the object.  Abstract has no table of its own -- only the
% construction vtable that Multi's group carries for it, which is how an abstract class
% normally appears.
%
%   0x30000  Base       class
%   0x30040  Left       si_class, base Base at 0
%   0x30080  Right      class
%   0x300c0  Multi      vmi_class, bases Left at 0 and Right at 8
%   0x30100  Abstract   class
setupRTTITests(ABI) :-
    assertz(fileInfo('00000000000000000000000000000000', test_file, ABI, 8)),
    assertz(rTTIEnabled),

    assertz(rTTITypeDescriptor(0x30000, 0x40000, '4Base', 'Base')),
    assertz(rTTIItaniumTypeInfo(0x30000, class)),
    assertz(rTTITypeDescriptor(0x30040, 0x40010, '4Left', 'Left')),
    assertz(rTTIItaniumTypeInfo(0x30040, si_class)),
    assertz(rTTIItaniumBaseTypeInfo(0x30040, 0x30000, 0, false, true)),
    assertz(rTTITypeDescriptor(0x30080, 0x40000, '5Right', 'Right')),
    assertz(rTTIItaniumTypeInfo(0x30080, class)),
    assertz(rTTITypeDescriptor(0x300c0, 0x40020, '5Multi', 'Multi')),
    assertz(rTTIItaniumTypeInfo(0x300c0, vmi_class)),
    assertz(rTTIItaniumBaseTypeInfo(0x300c0, 0x30040, 0, false, true)),
    assertz(rTTIItaniumBaseTypeInfo(0x300c0, 0x30080, 8, false, true)),
    assertz(rTTITypeDescriptor(0x30100, 0x40000, '8Abstract', 'Abstract')),
    assertz(rTTIItaniumTypeInfo(0x30100, class)),

    % Base and Left have ordinary tables.  Multi has a group of two.
    assertz(rTTIItaniumVFTableTypeInfo(0x10000, 0x30000, 0)),
    assertz(rTTIItaniumVFTableTypeInfo(0x10100, 0x30040, 0)),
    assertz(rTTIItaniumVFTableTypeInfo(0x10200, 0x300c0, 0)),
    assertz(rTTIItaniumVFTableTypeInfo(0x10280, 0x300c0, -8)),

    % Abstract's only table is a construction vtable, named by a VTT and written by nothing.
    assertz(rTTIItaniumVFTableTypeInfo(0x10300, 0x30100, 0)),
    assertz(possibleVTTEntry(0x10400, 8, 0x10300)),

    assertz(factVFTable(0x10000)),
    assertz(factVFTable(0x10200)),
    assertz(factVFTable(0x10280)).

cleanupRTTITests :-
    retractall(fileInfo(_, test_file, _, _)),
    retractall(rTTIEnabled),
    retractall(rTTITypeDescriptor(_, _, _, _)),
    retractall(rTTIItaniumTypeInfo(_, _)),
    retractall(rTTIItaniumVFTableTypeInfo(_, _, _)),
    retractall(rTTIItaniumBaseTypeInfo(_, _, _, _, _)),
    retractall(possibleVTTEntry(_, _, _)),
    retractall(initialMemory(_, _)),
    retractall(factVFTable(_)),
    abolish_all_tables.

tablesFor(TDA, VFTables) :-
    findall(V, rTTITDA2VFTable(TDA, V), Unsorted),
    msort(Unsorted, VFTables).

basesOf(TDA, Bases) :-
    findall(B-Offset, rTTIInheritsFrom(TDA, B, _A, Offset, 0xffffffff, 0), Unsorted),
    msort(Unsorted, Bases).

ancestorsOf(TDA, Ancestors) :-
    findall(A, rTTIAncestorOf(TDA, A), Unsorted),
    sort(Unsorted, Ancestors).

:- begin_tests(itanium_rtti,
               [setup(setupRTTITests('SYSV_64')), cleanup(cleanupRTTITests)]).

test(valid) :-
    assertion(rTTIValid).

% Every component of a group stands for the class, so that reasonMergeClasses_J can tie the
% primary and the secondary together.
test(group_tables) :-
    tablesFor(0x300c0, VFTables),
    assertion(VFTables == [0x10200, 0x10280]).

test(single_table) :-
    tablesFor(0x30000, VFTables),
    assertion(VFTables == [0x10000]).

% An abstract class is represented by its construction vtable, which is all it has.
test(construction_table) :-
    tablesFor(0x30100, VFTables),
    assertion(VFTables == [0x10300]).

test(no_base) :-
    assertion(rTTINoBase(0x30000)),
    assertion(rTTINoBase(0x30080)),
    assertion(\+ rTTINoBase(0x30040)),
    assertion(\+ rTTINoBase(0x300c0)).

test(direct_bases) :-
    basesOf(0x300c0, Bases),
    assertion(Bases == [0x30040-0, 0x30080-8]),
    basesOf(0x30040, LeftBases),
    assertion(LeftBases == [0x30000-0]).

% Only the direct bases are in the records, so the closure has to be taken.
test(ancestors) :-
    ancestorsOf(0x300c0, Ancestors),
    assertion(Ancestors == [0x30000, 0x30040, 0x30080]),
    assertion(\+ rTTIAncestorOf(0x30000, _)).

test(reason_vftable) :-
    assertion(reasonVFTable(0x10100)).

test(rtti_information) :-
    assertion(reasonRTTIInformation(0x10200, 0x300c0, '5Multi')),
    % Including the secondary component, so every table in a group gets named.
    assertion(reasonRTTIInformation(0x10280, 0x300c0, '5Multi')).

:- end_tests(itanium_rtti).

% A virtual base's record gives the position of the slot holding the real offset, not the
% offset.  The slot is below the address point, and those words are not exported as
% initialMemory yet (issue #356), so the fact is asserted here by hand.  This proves the rule
% before the exporter produces the fact.
setupVirtualBaseTests(ABI) :-
    setupRTTITests(ABI),
    assertz(rTTITypeDescriptor(0x30140, 0x40020, '8VDerived', 'VDerived')),
    assertz(rTTIItaniumTypeInfo(0x30140, vmi_class)),
    assertz(rTTIItaniumBaseTypeInfo(0x30140, 0x30000, -0x18, true, true)),
    assertz(rTTIItaniumVFTableTypeInfo(0x10500, 0x30140, 0)).

:- begin_tests(itanium_rtti_virtual_base,
               [setup(setupVirtualBaseTests('SYSV_64')), cleanup(cleanupRTTITests)]).

% Without the slot, nothing is known about where the base is.
test(unresolved) :-
    basesOf(0x30140, Bases),
    assertion(Bases == []),
    % It is still an ancestor, which is what reasonClassHasNoDerived needs.
    ancestorsOf(0x30140, Ancestors),
    assertion(Ancestors == [0x30000]).

:- end_tests(itanium_rtti_virtual_base).

% The same, with the slot readable.  0x10500 is VDerived's table and the record puts the slot
% 0x18 below its address point, so the offset lands at 0x104e8.
setupVirtualBaseTests(ABI, resolved) :-
    setupVirtualBaseTests(ABI),
    assertz(initialMemory(0x104e8, 8)).

:- begin_tests(itanium_rtti_virtual_base_resolved,
               [setup(setupVirtualBaseTests('SYSV_64', resolved)), cleanup(cleanupRTTITests)]).

test(resolved) :-
    basesOf(0x30140, Bases),
    assertion(Bases == [0x30000-8]).

:- end_tests(itanium_rtti_virtual_base_resolved).

% The kind of a record and its base classes have to agree, since the kind is what says how the
% record was read.  An si_class with two bases means it was read with the wrong layout.
setupInvalidTests(ABI) :-
    setupRTTITests(ABI),
    assertz(rTTIItaniumBaseTypeInfo(0x30040, 0x30080, 8, false, true)).

:- begin_tests(itanium_rtti_invalid,
               [setup(setupInvalidTests('SYSV_64')), cleanup(cleanupRTTITests)]).

test(invalid) :-
    assertion(\+ rTTIValid).

:- end_tests(itanium_rtti_invalid).

% The same facts under the MSVC ABI, which has no business reading them.  These prove the
% Itanium clauses are reached through the ABI and not merely through the facts.
:- begin_tests(itanium_rtti_msvc,
               [setup(setupRTTITests('MSVC_32')), cleanup(cleanupRTTITests)]).

% The MSVC validity checks need a type descriptor for every complete object locator, and there
% are no locators here at all, so validity cannot be established.
test(not_valid) :-
    assertion(\+ rTTIValid).

:- end_tests(itanium_rtti_msvc).
