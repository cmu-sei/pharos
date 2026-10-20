% ============================================================================================
% Runtime type information reasoning.
% ============================================================================================

:- use_module(library(aggregate), [aggregate_all/3]).
:- use_module(library(apply), [maplist/2, exclude/3]).
:- use_module(library(lists), [member/2]).

bogusName('MISSING').

% Given a TypeDescriptor address, return Name.  Return a "bogus" nbame if needed to prevent
% this predicate from failing since it's hard to debug when the failure is caused by attempting
% to report the details of a problem.
:- table rTTIName/2 as opaque.
rTTIName(TDA, Name) :-
    rTTITypeDescriptor(TDA, _TIVTable, Name, _DName) -> true ; bogusName(Name).

:- table rTTITDA2VFTable/2 as opaque.
rTTITDA2VFTable(TDA, VFTable) :-
    rTTITypeDescriptor(TDA, _TIVTable, _Name, _DName),
    rTTIMSVCCompleteObjectLocator(Pointer, _COLA, TDA, _CHDA, _Offset, _O2),
    pointerSize(PtrSize),
    VFTable is Pointer + PtrSize.

% Under the Itanium ABI the table points at the record directly, with no locator in between.
% Every component of the class' virtual table group names the same record -- the primary, the
% secondaries, and the construction vtables that other classes carry for the class -- and the
% offset-to-top is ignored here for the same reason the MSVC clause above ignores the locator's
% Offset: a table is a table of its class wherever in the object it is installed.  Taking all of
% them is what lets reasonMergeClasses_J tie a group together, and what gives an abstract class
% an identity at all, since such a class often has no table but the construction vtables.
rTTITDA2VFTable(TDA, VFTable) :-
    rTTIItaniumVFTableTypeInfo(VFTable, TDA, _OffsetToTop).

% This rule must be tabled incremental because of the find() clause.
:- table rTTITDA2Class/2 as incremental.
rTTITDA2Class(TDA, Class) :-
    % First turn the TypeDescriptor address into a VFTable address.
    rTTITDA2VFTable(TDA, VFTable),

    find(VFTable, Class).

% In each class definition, there's supposed to be one circular loop of pointers that describes
% casting a class into itself.  This rule finds that set of pointers, tying together a type
% descriptor, a complete object locator, a class heirarchy descriptor, a base class descriptor,
% a primary virtual function table address, and a class name.

:- table rTTISelfRef/6 as opaque.
rTTISelfRef(TDA, COLA, CHDA, BCDA, VFTable, Name) :-
    rTTITypeDescriptor(TDA, _TIVTable, Name, _DName),
    rTTIMSVCCompleteObjectLocator(Pointer, COLA, TDA, CHDA, _O1, _CDOffset),
    % CDOffset is usually zero, but we've found at least one case (mysqld) where it was 4.  It
    % appears that this rule is too strict if it limits the CDOffset to zero.
    pointerSize(PtrSize),
    VFTable is Pointer + PtrSize,
    rTTIMSVCClassHierarchyDescriptor(CHDA, _HierarchyAttributes, Bases),
    member(BCDA, Bases),

    %logtraceln('Evaluating TDA=~Q COLA=~Q CHDA=~Q BCDA=~Q', [TDA, COLA, CHDA, BCDA]),

    % We're primarly checking that TDA points back to the original type descriptor.  But also,
    % if (and only if) BaseAttributes is has the bcd_has_CHD_pointer bit set, then the optional
    % BCHDA field should also point to the same class hierarchy descriptor.
    rTTIMSVCBaseClassDescriptor(BCDA, TDA, _NumBases, 0, 0xffffffff, 0, BaseAttributes, BCHDA),
    bcd_has_CHD_pointer(BitMask),
    (bitmask_check(BaseAttributes, BitMask) -> BCHDA is CHDA; true),

    %logtraceln('Case:  BHCDA: ~Q TDA: ~Q CHDA: ~Q BCDA: ~Q',
    %           [BaseAttributes, BCHDA, TDA, CHDA, BCDA]),

    % Debugging.
    %logtraceln('debug-~Q.', rTTISelfRef(TDA, COLA, CHDA, BCDA, VFTable, Name)),
    true.

:- table rTTINoBase/1 as opaque.
rTTINoBase(TDA) :-
    rTTITypeDescriptor(TDA, _TIVTable, _Name, _DName),
    rTTIMSVCBaseClassDescriptor(_BCDA, TDA, 0, _M, _P, _V, _BaseAttributes, _ECHDA).

% The Itanium ABI says so outright.  A class with no base classes is described by a plain
% __class_type_info, which is the only kind of record that has nowhere to put one.  This is
% what the exported kind is for: it separates a class that provably has no bases from a record
% we were unable to read.
rTTINoBase(TDA) :-
    rTTIItaniumTypeInfo(TDA, class).

:- table rTTIAncestorOf/2 as opaque.
rTTIAncestorOf(DerivedTDA, AncestorTDA) :-
    rTTIMSVCCompleteObjectLocator(_Pointer, _COLA, DerivedTDA, CHDA, _Offset, _O2),
    rTTIMSVCClassHierarchyDescriptor(CHDA, _HierarchyAttributes, Bases),
    member(BCDA, Bases),
    rTTIMSVCBaseClassDescriptor(BCDA, AncestorTDA, _NumBases, _M, _P, _V, _BaseAttributes, _ECHDA),
    AncestorTDA \= DerivedTDA.

% An Itanium record lists only the direct base classes, where a class hierarchy descriptor
% lists every ancestor, so the closure has to be taken explicitly.  Completeness matters more
% than usual here, because reasonClassHasNoDerived uses this predicate negatively.
rTTIAncestorOf(DerivedTDA, AncestorTDA) :-
    rTTIItaniumBaseTypeInfo(DerivedTDA, AncestorTDA, _Offset, _Virtual, _Public),
    AncestorTDA \= DerivedTDA.

rTTIAncestorOf(DerivedTDA, AncestorTDA) :-
    rTTIItaniumBaseTypeInfo(DerivedTDA, MiddleTDA, _Offset, _Virtual, _Public),
    rTTIAncestorOf(MiddleTDA, AncestorTDA),
    AncestorTDA \= DerivedTDA.

:- table rTTIInheritsIndirectlyFrom/2 as opaque.
rTTIInheritsIndirectlyFrom(DerivedTDA, AncestorTDA) :-
    rTTIAncestorOf(DerivedTDA, BaseTDA),
    rTTIAncestorOf(BaseTDA, AncestorTDA).

:- table rTTIInheritsDirectlyFrom/6 as opaque.
rTTIInheritsDirectlyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V) :-
    % _ColM is the offset of the vftable pointer within the complete object; this is NOT the
    % same as M (mdisp = subobject offset from derived this-pointer) in the BCD.  They only
    % coincide when M=0, i.e., when the vftable is at the start of the object (no vbptr before
    % the vftable).  Classes that directly virtually inherit something have a vbptr-first layout,
    % putting the vftable at a non-zero offset, so _ColM != M for their direct non-virtual bases.
    rTTIMSVCCompleteObjectLocator(_Pointer, _COLA, DerivedTDA, CHDA, _ColM, _O2),
    rTTIMSVCClassHierarchyDescriptor(CHDA, Attributes, Bases),
    member(BCDA, Bases),
    rTTIMSVCBaseClassDescriptor(BCDA, AncestorTDA, _NumBases, M, P, V, AttrValue, _ECHDA),
    % Check that virtual inheritance attribute flag is NOT set.
    bcd_virtual_base_of_contained_object(BitMask),
    not(bitmask_check(AttrValue, BitMask)),
    AncestorTDA \= DerivedTDA,

    % Cory has still not found a more obvious way to determine whether the inheritance is
    % direct using P, V, or other flags.  This approach raises questions about what happens in
    % cases where the base class is inherited both directly and indirectly.  Will this
    % algorithm miss the direct base if it's also a base of a base?
    not(rTTIInheritsIndirectlyFrom(DerivedTDA, AncestorTDA)),

    %logtrace('debug-~Q.',
    %         rTTIInheritsDirectlyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V, BCDA),
    true.

:- table rTTIInheritsVirtuallyFrom/6 as opaque.
rTTIInheritsVirtuallyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V) :-
    % Same reasoning as rTTIInheritsDirectlyFrom: _ColM is the vftable pointer offset, not mdisp.
    rTTIMSVCCompleteObjectLocator(_Pointer, _COLA, DerivedTDA, CHDA, _ColM, _O2),
    rTTIMSVCClassHierarchyDescriptor(CHDA, Attributes, Bases),
    member(BCDA, Bases),
    rTTIMSVCBaseClassDescriptor(BCDA, AncestorTDA, _NumBases, M, P, V, AttrValue, _ECHDA),
    % Check that virtual inheritance attribute flag is set.
    bcd_virtual_base_of_contained_object(BitMask),
    bitmask_check(AttrValue, BitMask),
    AncestorTDA \= DerivedTDA,

    not(rTTIInheritsIndirectlyFrom(DerivedTDA, AncestorTDA)),

    % Is M always zero in virtual inheritance?

    % Debugging.
    %logtrace('debug-~Q.',
    %         rTTIInheritsVirtuallyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V, BCDA)),
    true.


% Which offset a virtual base lands at depends on the complete object being built, so the
% Itanium ABI keeps it in the virtual table rather than in the type information record, and the
% record gives the position of the slot that holds it.  Read the slot.  It has to be read from
% the class' own primary component: a construction vtable for B-in-D holds the offset of the
% virtual base within a D, not within a B.
%
% The words below an address point are not exported as initialMemory yet (issue #358), so this
% finds nothing today.  Virtual inheritance starts being recovered when they are, with no
% further change here.
:- table rTTIItaniumVirtualBaseOffset/3 as opaque.
rTTIItaniumVirtualBaseOffset(DerivedTDA, AncestorTDA, Offset) :-
    rTTIItaniumBaseTypeInfo(DerivedTDA, AncestorTDA, SlotOffset, true, _Public),
    rTTIItaniumVFTableTypeInfo(VFTable, DerivedTDA, 0),
    not(possibleConstructionVFTable(VFTable)),
    SlotAddress is VFTable + SlotOffset,
    % BUG these are not currently exported #358
    initialMemory(SlotAddress, Offset).

:- table rTTIInheritsFrom/6 as opaque.
rTTIInheritsFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V) :-
    (rTTIInheritsDirectlyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V);
     rTTIInheritsVirtuallyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V)).

% An Itanium record states the direct base classes outright, so there is no directness to work
% out and no hierarchy descriptor to walk.  A non-virtual base's offset is already the offset of
% the subobject; a virtual base's has to be read out of the table first.
%
% Both are reported with the MSVC encoding for "not reached through a virtual base table",
% because by this point they are the same thing: factDerivedClass and finalInheritance record
% only an offset, and this keeps reasonDerivedClass_E and reasonVBTableEntry from matching a
% virtual base against a virtual base table that the Itanium ABI does not have.
rTTIInheritsFrom(DerivedTDA, AncestorTDA, 0, Offset, 0xffffffff, 0) :-
    rTTIItaniumBaseTypeInfo(DerivedTDA, AncestorTDA, Offset, false, _Public),
    AncestorTDA \= DerivedTDA.

rTTIInheritsFrom(DerivedTDA, AncestorTDA, 0, Offset, 0xffffffff, 0) :-
    rTTIItaniumVirtualBaseOffset(DerivedTDA, AncestorTDA, Offset),
    AncestorTDA \= DerivedTDA.

% When RTTI is enabled, valid, and reports an inheritance relationship, this is a particularly
% strong assertion.  In particular, it represents a rare opportunity to make confident negative
% assertions -- this class is NOT derived from that class because the relationship wasn't in
% the RTTI data.  Because the conclusion is based entirely off of RTTI data, we cane compute
% these facts once at the beginning of the run, and be done with this rule for the rest of the
% analysis.  Additionally, this rule may be used efficiently in places where we would normally
% rely on sanity checking to detect contradictions because of the primacy of RTTI conclusions.
% The only catch is that the RTTI data only gives us VFTables, not class ids, so we'll have to
% call findVFTable(VFTable, 0, Class) later to map these facts to get the correct class ids.
:- table rTTIDerivedClass/3 as opaque.
rTTIDerivedClass(DerivedVFTable, BaseVFTable, Offset) :-
    rTTIEnabled,
    rTTIValid,
    rTTIInheritsFrom(DerivedTDA, BaseTDA, _Attributes, Offset, 0xffffffff, 0),
    rTTITDA2VFTable(DerivedTDA, DerivedVFTable),
    rTTITDA2VFTable(BaseTDA, BaseVFTable).

% --------------------------------------------------------------------------------------------
:- table reasonRTTIInformation/3 as incremental.

% This rule is only used in final.pl to obtain a class name now.  Perhaps it should be
% rewritten.
% PAPER: XXX
reasonRTTIInformation(VFTableAddress, Pointer, RTTIName) :-
    rTTIMSVCCompleteObjectLocator(Pointer, _COLAddress, TDAddress, _CHDAddress, _O1, _O2),
    rTTITypeDescriptor(TDAddress, _VFTableCheck, RTTIName, _DName),
    pointerSize(PtrSize),
    VFTableAddress is Pointer + PtrSize,
    factVFTable(VFTableAddress).

% The Itanium equivalent, where the record address is what there is to report -- there is no
% locator, and the record is what the table points at.  Every component of a group is named,
% not just the primary, so each table reports the class it serves.
reasonRTTIInformation(VFTableAddress, TDAddress, RTTIName) :-
    rTTIItaniumVFTableTypeInfo(VFTableAddress, TDAddress, _OffsetToTop),
    rTTITypeDescriptor(TDAddress, _VFTableCheck, RTTIName, _DName),
    factVFTable(VFTableAddress).

% ============================================================================================
% Validation
% ============================================================================================

% Base Class Descriptor (BCD) attribute flags.

% BCD_NOTVISIBLE
bcd_notvisible(0x01).

% BCD_AMBIGUOUS
bcd_ambiguous(0x02).

% BCD_PRIVORPROTINCOMPOBJ
bcd_private_or_protected_in_composite_object(0x04).

% BCD_PRIVORPROTBASE
bcd_private_or_protected_base(0x08).

% BCD_VBOFCONTOBJ
bcd_virtual_base_of_contained_object(0x10).

% BCD_NONPOLYMORPHIC
bcd_nonpolymorphic(0x20).

% BCD_HASPCHD
% BCD has an extra pointer trailing the structure to the ClassHierarchyDescriptor.
bcd_has_CHD_pointer(0x40).

% --------------------------------------------------------------------------------------------
rttiwarninvalid(Message, Args) :-
    logwarn('RTTI Information is invalid because ~@~n', format(Message, Args)).

rTTIInvalidBaseAttributes :-
    rTTIMSVCBaseClassDescriptor(BCDA, _TDA, _NumBases, _M, _P, _V, Attributes, _CHDA),
    % See Base Class Descriptor (BCD) attribute flags above for details of each bit.
    (Attributes >= 0x80; Attributes < 0x0),
    rttiwarninvalid('BaseClassDescriptor at ~Q has attributes = ~Q', [BCDA, Attributes]).

rTTIInvalidDirectInheritanceP :-
    rTTIInheritsDirectlyFrom(_DerivedTDA, _AncestorTDA, _Attributes, _M, P, _V),
    P \= 0xffffffff,
    rttiwarninvalid('InheritsDirectlyFrom P = ~Q', [P]).

rTTIInvalidDirectInheritanceV :-
    rTTIInheritsDirectlyFrom(_DerivedTDA, _AncestorTDA, _Attributes, _M, _P, V),
    V \= 0x0,
    rttiwarninvalid('InheritsDirectlyFrom V = ~Q', [V]).

rTTIInvalidHierarchyAttributes :-
    rTTIMSVCClassHierarchyDescriptor(CHDA, HierarchyAttributes, _Bases),

    % Attributes 0x0 means a normal inheritance (non multiple/virtual)
    HierarchyAttributes \= 0x0,

    % Attributes 0x1 means multiple inheritance
    HierarchyAttributes \= 0x1,

    % Attributes 0x2 is not believed to be possible since it would imply virtual inheritance
    % without multiple inheritance.

    % Attributes 0x3 means multiple virtual inheritance
    HierarchyAttributes \= 0x3,

    % Attributes 0x5 means ???
    HierarchyAttributes \= 0x5,

    % Attributes 0x7 means ???
    HierarchyAttributes \= 0x7,

    rttiwarninvalid('CHD at ~Q has attributes = ~Q', [CHDA, HierarchyAttributes]).

:- table rTTIShouldHaveSelfRef/1 as opaque.
rTTIShouldHaveSelfRef(TDA) :-
    rTTITypeDescriptor(TDA, _VFTableCheck, _RTTIName, _DName),
    rTTIMSVCCompleteObjectLocator(_Pointer, _COLA, TDA, _CHDA, _O1, _O2).

:- table rTTIHasSelfRef/1 as opaque.
rTTIHasSelfRef(TDA) :-
    rTTISelfRef(TDA, _COLA, _CHDA, _BCDA, _VFTable, _Name) -> true;
    rttiwarninvalid('missing self-reference for TDA at address ~Q', [TDA]),
    false.

:- table rTTIAllTypeDescriptors/1 as opaque.
rTTIAllTypeDescriptors(TDA) :-
    rTTITypeDescriptor(TDA, _VFTableCheck, _RTTIName, _DName).

rTTIAllTypeDescriptors(TDA) :-
    rTTIMSVCCompleteObjectLocator(_Pointer, _Address, TDA, _CHDAddress, _Offset, _CDOffset).

rTTIAllTypeDescriptors(TDA) :-
    rTTIMSVCBaseClassDescriptor(_Address, TDA, _NumBases, _M, _P, _V, _Attr, _CHDA).

:- table rTTIHasTypeDescriptor/1 as opaque.
rTTIHasTypeDescriptor(TDA) :-
    rTTITypeDescriptor(TDA, _VFTableCheck, _RTTIName, _DName) -> true;
    rttiwarninvalid('missing type descriptor for TDA at address ~Q', [TDA]),
    false.


findNone(Pred) :-
    findall(true, Pred, R), R = [].

% --------------------------------------------------------------------------------------------
% Itanium ABI validation.

% Which of the three __cxxabiv1 classes describes a record is decided by how many base classes
% it has and what they are, so the kind and the bases have to agree.  A disagreement means we
% read the record with the wrong layout, which makes every offset in it meaningless.

rTTIItaniumInvalidClass :-
    rTTIItaniumTypeInfo(TDA, class),
    rTTIItaniumBaseTypeInfo(TDA, BaseTDA, _Offset, _Virtual, _Public),
    rttiwarninvalid('__class_type_info at ~Q has a base class at ~Q', [TDA, BaseTDA]).

rTTIItaniumInvalidSIClass :-
    rTTIItaniumTypeInfo(TDA, si_class),
    % An __si_class_type_info exists precisely for the case of one public, non-virtual base at
    % offset zero.  Anything else would have been emitted as an __vmi_class_type_info, so
    % collect every base before judging the shape rather than only the ones that fit.
    findall(BaseTDA-Offset-Virtual-Public,
            rTTIItaniumBaseTypeInfo(TDA, BaseTDA, Offset, Virtual, Public), Bases),
    not(Bases = [_OneBase-0-false-true]),
    rttiwarninvalid('__si_class_type_info at ~Q has bases ~Q', [TDA, Bases]).

rTTIItaniumInvalidVMIClass :-
    rTTIItaniumTypeInfo(TDA, vmi_class),
    not(rTTIItaniumBaseTypeInfo(TDA, _BaseTDA, _Offset, _Virtual, _Public)),
    rttiwarninvalid('__vmi_class_type_info at ~Q has no base classes', [TDA]).

rTTIItaniumInvalidCycle :-
    rTTIItaniumTypeInfo(TDA, _Kind),
    rTTIAncestorOf(TDA, TDA),
    rttiwarninvalid('type information at ~Q is its own ancestor', [TDA]).

% Every record a virtual function table names should have been reported.  A base class whose
% record is in another shared object is a different matter, and is not an error: the pointer to
% it is a relocation that the dynamic linker was going to fill in, and there is nothing to read.
rTTIItaniumMissingTypeDescriptor :-
    rTTIItaniumVFTableTypeInfo(VFTable, TDA, _OffsetToTop),
    not(rTTITypeDescriptor(TDA, _VFTable, _Name, _DName)),
    rttiwarninvalid('table at ~Q names type information at ~Q, which is missing',
                    [VFTable, TDA]).

% --------------------------------------------------------------------------------------------
% Is the RTTI information internally consistent?
%
% Branching on the ABI rather than making each check tolerant of its facts being absent, so
% that an MSVC binary reaches exactly the checks it always did.  The MSVC list requires its
% setof goals to succeed, which is why an Itanium binary could never pass it.
:- table rTTIValid/0 as opaque.
rTTIValid :-
    rTTIEnabled,
    itaniumABI,
    % There has to be something to be valid.  The MSVC list below requires this implicitly,
    % since its setof goals fail when there are no type descriptors, and without the same
    % requirement here a binary built with -fno-rtti would vacuously pass and switch on every
    % rule that asks whether the RTTI can be trusted.
    rTTIItaniumTypeInfo(_TDA, _Kind),
    exclude(call, [findNone(rTTIItaniumInvalidClass),
                   findNone(rTTIItaniumInvalidSIClass),
                   findNone(rTTIItaniumInvalidVMIClass),
                   findNone(rTTIItaniumInvalidCycle),
                   findNone(rTTIItaniumMissingTypeDescriptor)],
            Results),
    Results = [].

rTTIValid :-
    rTTIEnabled,
    msvcABI,
    exclude(call, [setof(TDA, rTTIAllTypeDescriptors(TDA), TDASet1),
                   exclude(rTTIHasTypeDescriptor, TDASet1, R1), R1 = [],
                   setof(TDA, rTTIShouldHaveSelfRef(TDA), TDASet2),
                   exclude(rTTIHasSelfRef, TDASet2, R2), R2 = [],
                   findNone(rTTIInvalidBaseAttributes),
                   findNone(rTTIInvalidHierarchyAttributes),
                   findNone(rTTIInvalidDirectInheritanceP),
                   findNone(rTTIInvalidDirectInheritanceV)],
            Results),
    Results = [].

% ============================================================================================
% Reporting
% ============================================================================================

reportNoBase((A)) :-
    logdebugln('~@~Q.', [rTTIName(A, AName), rTTINoBaseName(A, AName)]).
reportNoBase :-
    setof((A), rTTINoBase(A), Set),
    maplist(reportNoBase, Set).
reportNoBase :- true.

reportAncestorOf((D, A)) :-
    logdebugln('~@~@~Q.', [rTTIName(D, DName), rTTIName(A, AName),
                           rTTIAncestorOfName(D, A, DName, AName)]).
reportAncestorOf :-
    setof((D, A), rTTIAncestorOf(D, A), Set),
    maplist(reportAncestorOf, Set).
reportAncestorOf :- true.

reportInheritsDirectlyFrom((D, A, H, M, P, V)) :-
    logdebugln('~@~@~Q.', [rTTIName(D, DName), rTTIName(A, AName),
                         rTTIInheritsDirectlyFromName(D, A, H, M, P, V, DName, AName)]).
reportInheritsDirectlyFrom :-
    setof((D, A, H, M, P, V), rTTIInheritsDirectlyFrom(D, A, H, M, P, V), Set),
    maplist(reportInheritsDirectlyFrom, Set).
reportInheritsDirectlyFrom :- true.

reportInheritsVirtuallyFrom((D, A, H, M, P, V)) :-
    logdebugln('~@~@~Q.', [rTTIName(D, DName), rTTIName(A, AName),
                         rTTIInheritsVirtuallyFromName(D, A, H, M, P, V, DName, AName)]).
reportInheritsVirtuallyFrom :-
    setof((D, A, H, M, P, V), rTTIInheritsVirtuallyFrom(D, A, H, M, P, V), Set),
    maplist(reportInheritsVirtuallyFrom, Set).
reportInheritsVirtuallyFrom :- true.


reportSelfRef((T, L, C, B, V, N)) :-
    logdebugln('~Q.', rTTISelfRef(T, L, C, B, V, N)).
reportSelfRef :-
    setof((T, L, C, B, V, N), rTTISelfRef(T, L, C, B, V, N), Set),
    maplist(reportSelfRef, Set).
reportSelfRef :- true.

rTTISolve(X) :-
    loadInitialFacts(X),
    reportRTTIResults.

rTTIPresent(Count) :-
    aggregate_all(count, rTTITypeDescriptor(_, _, _, _), Count1),
    aggregate_all(count, rTTIMSVCCompleteObjectLocator(_, _, _, _, _, _), Count2),
    aggregate_all(count, rTTIMSVCBaseClassDescriptor(_, _, _, _, _, _, _, _), Count3),
    aggregate_all(count, rTTIMSVCClassHierarchyDescriptor(_, _, _), Count4),
    aggregate_all(count, rTTIItaniumTypeInfo(_, _), Count5),
    aggregate_all(count, rTTIItaniumVFTableTypeInfo(_, _, _), Count6),
    aggregate_all(count, rTTIItaniumBaseTypeInfo(_, _, _, _, _), Count7),
    Count is Count1 + Count2 + Count3 + Count4 + Count5 + Count6 + Count7.

reportRTTIResults :-
    % Always enable RTTI before attempting to report on it.
    % assert(rTTIEnabled),

    % First determine whether RTTI was present or not.
    rTTIPresent(Count),
    (Count > 0 ->
         % If RTTI facts were present, always report that.
         (loginfoln('RTTI was present, found ~D predicates.', [Count]),
          (rTTIValid -> loginfoln('RTTI was valid.') ; logerrorln('RTTI was invalid.')),
          ((logLevel(Level), Level > 4) ->
               (reportNoBase,
                reportSelfRef,
                reportAncestorOf,
                reportInheritsDirectlyFrom,
                reportInheritsVirtuallyFrom,
                loginfoln('RTTI report complete.')
               ); true)
         )
     ;
     loginfoln('RTTI was not present.')
    ).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
