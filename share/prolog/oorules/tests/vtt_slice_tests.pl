% Copyright 2026 Carnegie Mellon University.

:- ensure_loaded('../setup').

% One VTT at 0x20000 naming three tables, and four callees exercising the ways a call site can
% look.  Every callee is __sysv64call, so its this-pointer arrives in rdi and any slice in rsi.
%
%   test_ctor          rsi holds VTT+8.  The write we want, at the lower of its two offset zero
%                      accesses -- the second stands in for a later dispatch read.
%   test_this_is_slice rdi holds VTT+0x10.  A this-pointer is not a slice however it looks.
%   test_not_vtt       rsi holds a constant that is not on a VTT slot.
%   test_shared        called twice with different slices, as a base of two derived classes is.
setupSliceTests(ABI) :-
    assertz(fileInfo('00000000000000000000000000000000', test_file, ABI, 8)),

    assertz(callingConvention(test_ctor, '__sysv64call')),
    assertz(funcParameter(test_ctor, rdi, test_ctor_this)),
    assertz(callTarget(test_call_1, test_caller, test_ctor)),
    assertz(callParameter(test_call_1, test_caller, rdi, test_obj)),
    assertz(callParameter(test_call_1, test_caller, rsi, test_slice_1)),
    assertz(thisPtrDefinition(test_slice_1, 0x20008, test_call_1, test_caller)),
    assertz(methodMemberAccess(0x1000, test_ctor, 0, 8)),
    assertz(methodMemberAccess(0x1010, test_ctor, 0, 8)),

    assertz(callingConvention(test_this_is_slice, '__sysv64call')),
    assertz(funcParameter(test_this_is_slice, rdi, test_slice_2)),
    assertz(callTarget(test_call_2, test_caller, test_this_is_slice)),
    assertz(callParameter(test_call_2, test_caller, rdi, test_slice_2)),
    assertz(thisPtrDefinition(test_slice_2, 0x20010, test_call_2, test_caller)),
    assertz(methodMemberAccess(0x2000, test_this_is_slice, 0, 8)),

    assertz(callingConvention(test_not_vtt, '__sysv64call')),
    assertz(funcParameter(test_not_vtt, rdi, test_not_vtt_this)),
    assertz(callTarget(test_call_3, test_caller, test_not_vtt)),
    assertz(callParameter(test_call_3, test_caller, rdi, test_obj3)),
    assertz(callParameter(test_call_3, test_caller, rsi, test_constant)),
    assertz(thisPtrDefinition(test_constant, 0x30000, test_call_3, test_caller)),
    assertz(methodMemberAccess(0x3000, test_not_vtt, 0, 8)),

    assertz(callingConvention(test_shared, '__sysv64call')),
    assertz(funcParameter(test_shared, rdi, test_shared_this)),
    assertz(callTarget(test_call_4, test_caller, test_shared)),
    assertz(callParameter(test_call_4, test_caller, rsi, test_slice_1)),
    assertz(callTarget(test_call_5, test_other_caller, test_shared)),
    assertz(callParameter(test_call_5, test_other_caller, rsi, test_slice_3)),
    assertz(thisPtrDefinition(test_slice_3, 0x20010, test_call_5, test_other_caller)),
    assertz(methodMemberAccess(0x4000, test_shared, 0, 8)).

setupSliceTests(ABI, vtt) :-
    setupSliceTests(ABI),
    assertz(possibleVTTEntry(0x20000, 0, 0x10000)),
    assertz(possibleVTTEntry(0x20000, 8, 0x10040)),
    assertz(possibleVTTEntry(0x20000, 0x10, 0x10060)).

setupSliceTests(ABI, notmerge) :-
    setupSliceTests(ABI),
    setupNotMergeWrites.

setupSliceTests(ABI, notconstructor) :-
    setupSliceTests(ABI),
    setupVariantClass.

% certainConstructorOrDestructor and possibleConstructor need the conclusions that the write
% itself would otherwise have to earn through the whole forward reasoning pass.
setupSliceTests(ABI, vtt, proven) :-
    setupSliceTests(ABI, vtt),
    assertz(factVFTableWrite(0x1000, test_ctor, 0, 0x10040)),
    assertz(noCallsBefore(test_ctor)).

setupSliceTests(ABI, vtt, notmerge) :-
    setupSliceTests(ABI, vtt),
    setupNotMergeWrites.

setupSliceTests(ABI, vtt, notconstructor) :-
    setupSliceTests(ABI, vtt),
    setupVariantClass.

% The class #354 asks for, with both constructor variants on it: test_complete_ctor installs the
% class' own table with a constant store, and test_ctor installs the construction vtable that the
% VTT slice names.  test_opeq is on the class and installs nothing at all.
setupVariantClass :-
    maplist(make, [test_complete_ctor, test_ctor, test_opeq, 0x10000, 0x10040]),
    maplist(assertFactMethod, [test_complete_ctor, test_ctor, test_opeq]),
    maplist(assertFactVFTable, [0x10000, 0x10040]),
    assertz(possibleVFTableWrite(0x7000, test_complete_ctor, test_complete_this, 0,
                                 test_complete_this, 0x10000)),
    maplist(union(test_complete_ctor), [test_ctor, test_opeq, 0x10000, 0x10040]).

assertFactMethod(Method) :- assertz(factMethod(Method)).
assertFactVFTable(VFTable) :- assertz(factVFTable(VFTable)).

% Three offset zero writes of three different tables: test_ctor's comes from a VTT slice, the
% other two are ordinary constant stores.  Each method is its own class to start with, so the
% classes reasonNOTMergeClasses_E reports are the methods themselves.
setupNotMergeWrites :-
    make(test_ctor),
    make(test_other_ctor),
    make(test_third_ctor),
    assertz(factVFTableWrite(0x1000, test_ctor, 0, 0x10040)),
    assertz(factVFTableWrite(0x5000, test_other_ctor, 0, 0x10000)),
    assertz(factVFTableWrite(0x6000, test_third_ctor, 0, 0x10080)).

cleanupSliceTests :-
    retractall(fileInfo(_, test_file, _, _)),
    retractall(callingConvention(_, _)),
    retractall(funcParameter(_, _, _)),
    retractall(callTarget(_, _, _)),
    retractall(callParameter(_, _, _, _)),
    retractall(thisPtrDefinition(_, _, _, _)),
    retractall(methodMemberAccess(_, _, _, _)),
    retractall(possibleVTTEntry(_, _, _)),
    retractall(factVFTableWrite(_, _, _, _)),
    retractall(possibleVFTableWrite(_, _, _, _, _, _)),
    retractall(factMethod(_)),
    retractall(factVFTable(_)),
    retractall(noCallsBefore(_)),
    retractall(findint(_, _)),
    abolish_all_tables.

vFTableWrites(Method, Writes) :-
    findall(Insn-VFTable,
            possibleVFTableWrite(Insn, Method, _ThisPtr, 0, VFTable),
            Unsorted),
    msort(Unsorted, Writes).

:- begin_tests(vtt_slice_writes,
               [setup(setupSliceTests('SYSV_64', vtt)),
                cleanup(cleanupSliceTests)]).

% The slice names the table, and the write lands on the lower of the two offset zero accesses.
test(slice_yields_a_write) :-
    assertion(vFTableWrites(test_ctor, [0x1000-0x10040])).

test(write_carries_the_callees_own_thisptr) :-
    assertion(possibleVFTableWrite(0x1000, test_ctor, test_ctor_this, 0, 0x10040)).

% A this-pointer that happens to hold a VTT slot address is still a this-pointer.
test(this_pointer_is_not_a_slice, [fail]) :-
    vttSlice(_Insn, test_this_is_slice, _VFTable).

test(constant_off_the_vtt_is_not_a_slice, [fail]) :-
    vttSlice(_Insn, test_not_vtt, _VFTable).

% A base shared by two derived classes is handed a different slice by each.  Both writes name
% the one store instruction, which is what keeps them from reading as an overwrite.
test(two_slices_share_one_instruction) :-
    assertion(vFTableWrites(test_shared, [0x4000-0x10040, 0x4000-0x10060])).

test(two_slices_are_not_an_overwrite, [fail]) :-
    possibleVFTableOverwrite(_I1, _I2, test_shared, 0, _VFTable1, _VFTable2).

:- end_tests(vtt_slice_writes).

:- begin_tests(vtt_slice_reasoning,
               [setup(setupSliceTests('SYSV_64', vtt, proven)),
                cleanup(cleanupSliceTests)]).

% What issue #344 is actually after: the base-object variant stops looking like a function that
% writes no vftables.
test(slice_receiver_is_a_constructor_or_destructor) :-
    assertion(certainConstructorOrDestructor(test_ctor)).

test(slice_receiver_is_a_constructor_candidate) :-
    assertion(possibleConstructor(test_ctor)).

:- end_tests(vtt_slice_reasoning).

% The classes reasonNOTMergeClasses_E pairs with the write named by Insn, Method and VFTable.
notMergeClasses(Insn, Method, VFTable, Classes) :-
    findall(Class2,
            reasonNOTMergeClasses_E(_Class1, Class2, Insn, Method, 0, VFTable),
            Unsorted),
    msort(Unsorted, Classes).

:- begin_tests(vtt_slice_notmerge,
               [setup(setupSliceTests('SYSV_64', vtt, notmerge)),
                cleanup(cleanupSliceTests)]).

% A base-object constructor installs whichever table its caller's VTT slice names, so the table
% is evidence about the object being built and not about the callee's class.
test(slice_write_is_not_class_evidence) :-
    assertion(notMergeClasses(0x1000, test_ctor, 0x10040, [])).

% Withheld from the other direction too, but still concluded between the ordinary writes.
test(slice_receiver_is_not_separated_from_ordinary_classes) :-
    assertion(notMergeClasses(0x5000, test_other_ctor, 0x10000, [test_third_ctor])).

:- end_tests(vtt_slice_notmerge).

:- begin_tests(vtt_slice_construction,
               [setup(setupSliceTests('SYSV_64', vtt, notconstructor)),
                cleanup(cleanupSliceTests)]).

% Only a constant store says the writer's own class owns the table, so the tables a VTT names
% and no instruction writes are the construction vtables.
test(vtt_named_table_without_a_constant_write_is_a_construction_vftable) :-
    assertion(possibleConstructionVFTable(0x10040)),
    assertion(possibleConstructionVFTable(0x10060)).

test(vtt_entry_zero_is_the_owners_own_table, [fail]) :-
    possibleConstructionVFTable(0x10000).

:- end_tests(vtt_slice_construction).

:- begin_tests(vtt_slice_notconstructor,
               [setup(setupSliceTests('SYSV_64', vtt, notconstructor)),
                cleanup(cleanupSliceTests)]).

% The base-object variant installs whatever its caller's VTT names, and never the class' own
% complete-object table.  Missing that table is the ABI, not evidence against being a
% constructor.
test(base_object_variant_may_miss_the_complete_object_table, [fail]) :-
    reasonNOTConstructor_H(test_ctor).

% And the complete-object variant never installs the construction vtable.
test(complete_object_variant_may_miss_the_construction_table, [fail]) :-
    reasonNOTConstructor_H(test_complete_ctor).

% Withheld from the variants, not disabled: a method on the class that installs nothing at all
% is still rejected, which is what the rule was written for.
test(a_method_installing_nothing_is_still_not_a_constructor) :-
    assertion(reasonNOTConstructor_H(test_opeq)).

:- end_tests(vtt_slice_notconstructor).

% And without a VTT there are no construction vtables, so the base-object variant has no write
% at all and the rule reaches its ordinary conclusion.
:- begin_tests(vtt_slice_msvc_notconstructor,
               [setup(setupSliceTests('MSVC_32', notconstructor)),
                cleanup(cleanupSliceTests)]).

test(no_vtt_means_no_construction_vftable, [fail]) :-
    possibleConstructionVFTable(_VFTable).

test(no_vtt_means_the_missing_write_is_evidence) :-
    assertion(reasonNOTConstructor_H(test_ctor)).

:- end_tests(vtt_slice_msvc_notconstructor).

% MSVC has no VTTs, so the exporter emits no possibleVTTEntry and the clause cannot fire.  The
% same call sites and member accesses are asserted here to show that nothing else carries it.
:- begin_tests(vtt_slice_msvc,
               [setup(setupSliceTests('MSVC_32')),
                cleanup(cleanupSliceTests)]).

test(no_vtt_means_no_slice, [fail]) :-
    vttSlice(_Insn, _Callee, _VFTable).

test(no_vtt_means_no_write, [fail]) :-
    possibleVFTableWrite(_Insn, _Method, _ThisPtr, _Offset, _VFTable).

:- end_tests(vtt_slice_msvc).

% And without a VTT the exemption cannot fire, so all three writes separate all three classes.
:- begin_tests(vtt_slice_msvc_notmerge,
               [setup(setupSliceTests('MSVC_32', notmerge)),
                cleanup(cleanupSliceTests)]).

test(no_vtt_means_the_write_is_class_evidence) :-
    assertion(notMergeClasses(0x1000, test_ctor, 0x10040,
                              [test_other_ctor, test_third_ctor])).

test(no_vtt_separates_in_both_directions) :-
    assertion(notMergeClasses(0x5000, test_other_ctor, 0x10000,
                              [test_ctor, test_third_ctor])).

:- end_tests(vtt_slice_msvc_notmerge).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
