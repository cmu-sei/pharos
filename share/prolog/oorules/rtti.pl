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
    rTTICompleteObjectLocator(Pointer, _COLA, TDA, _CHDA, _Offset, _O2),
    VFTable is Pointer + 4.

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
    rTTICompleteObjectLocator(Pointer, COLA, TDA, CHDA, _O1, _CDOffset),
    % CDOffset is usually zero, but we've found at least one case (mysqld) where it was 4.  It
    % appears that this rule is too strict if it limits the CDOffset to zero.
    VFTable is Pointer + 4,
    rTTIClassHierarchyDescriptor(CHDA, _HierarchyAttributes, Bases),
    member(BCDA, Bases),

    %logtraceln('Evaluating TDA=~Q COLA=~Q CHDA=~Q BCDA=~Q', [TDA, COLA, CHDA, BCDA]),

    % We're primarly checking that TDA points back to the original type descriptor.  But also,
    % if (and only if) BaseAttributes is has the bcd_has_CHD_pointer bit set, then the optional
    % BCHDA field should also point to the same class hierarchy descriptor.
    rTTIBaseClassDescriptor(BCDA, TDA, _NumBases, 0, 0xffffffff, 0, BaseAttributes, BCHDA),
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
    rTTIBaseClassDescriptor(_BCDA, TDA, 0, _M, _P, _V, _BaseAttributes, _ECHDA).

:- table rTTIAncestorOf/2 as opaque.
rTTIAncestorOf(DerivedTDA, AncestorTDA) :-
    rTTICompleteObjectLocator(_Pointer, _COLA, DerivedTDA, CHDA, _Offset, _O2),
    rTTIClassHierarchyDescriptor(CHDA, _HierarchyAttributes, Bases),
    member(BCDA, Bases),
    rTTIBaseClassDescriptor(BCDA, AncestorTDA, _NumBases, _M, _P, _V, _BaseAttributes, _ECHDA),
    AncestorTDA \= DerivedTDA.

:- table rTTIInheritsIndirectlyFrom/2 as opaque.
rTTIInheritsIndirectlyFrom(DerivedTDA, AncestorTDA) :-
    rTTIAncestorOf(DerivedTDA, BaseTDA),
    rTTIAncestorOf(BaseTDA, AncestorTDA).

:- table rTTIInheritsDirectlyFrom/6 as opaque.
rTTIInheritsDirectlyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V) :-
    rTTICompleteObjectLocator(_Pointer, _COLA, DerivedTDA, CHDA, M, _O2),
    rTTIClassHierarchyDescriptor(CHDA, Attributes, Bases),
    member(BCDA, Bases),
    rTTIBaseClassDescriptor(BCDA, AncestorTDA, _NumBases, M, P, V, AttrValue, _ECHDA),
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
    rTTICompleteObjectLocator(_Pointer, _COLA, DerivedTDA, CHDA, M, _O2),
    rTTIClassHierarchyDescriptor(CHDA, Attributes, Bases),
    member(BCDA, Bases),
    rTTIBaseClassDescriptor(BCDA, AncestorTDA, _NumBases, M, P, V, AttrValue, _ECHDA),
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


:- table rTTIInheritsFrom/6 as opaque.
rTTIInheritsFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V) :-
    (rTTIInheritsDirectlyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V);
     rTTIInheritsVirtuallyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V)).

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
    rTTICompleteObjectLocator(Pointer, _COLAddress, TDAddress, _CHDAddress, _O1, _O2),
    rTTITypeDescriptor(TDAddress, _VFTableCheck, RTTIName, _DName),
    VFTableAddress is Pointer + 4,
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
    rTTIBaseClassDescriptor(BCDA, _TDA, _NumBases, _M, _P, _V, Attributes, _CHDA),
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
    rTTIClassHierarchyDescriptor(CHDA, HierarchyAttributes, _Bases),

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
    rTTICompleteObjectLocator(_Pointer, _COLA, TDA, _CHDA, _O1, _O2).

:- table rTTIHasSelfRef/1 as opaque.
rTTIHasSelfRef(TDA) :-
    rTTISelfRef(TDA, _COLA, _CHDA, _BCDA, _VFTable, _Name) -> true;
    rttiwarninvalid('missing self-reference for TDA at address ~Q', [TDA]),
    false.

:- table rTTIAllTypeDescriptors/1 as opaque.
rTTIAllTypeDescriptors(TDA) :-
    rTTITypeDescriptor(TDA, _VFTableCheck, _RTTIName, _DName).

rTTIAllTypeDescriptors(TDA) :-
    rTTICompleteObjectLocator(_Pointer, _Address, TDA, _CHDAddress, _Offset, _CDOffset).

rTTIAllTypeDescriptors(TDA) :-
    rTTIBaseClassDescriptor(_Address, TDA, _NumBases, _M, _P, _V, _Attr, _CHDA).

:- table rTTIHasTypeDescriptor/1 as opaque.
rTTIHasTypeDescriptor(TDA) :-
    rTTITypeDescriptor(TDA, _VFTableCheck, _RTTIName, _DName) -> true;
    rttiwarninvalid('missing type descriptor for TDA at address ~Q', [TDA]),
    false.


findNone(Pred) :-
    findall(true, Pred, R), R = [].

% Is the RTTI information internally consistent?
:- table rTTIValid/0 as opaque.
rTTIValid :-
    rTTIEnabled ->
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
    aggregate_all(count, rTTICompleteObjectLocator(_, _, _, _, _, _), Count2),
    aggregate_all(count, rTTIBaseClassDescriptor(_, _, _, _, _, _, _, _), Count3),
    aggregate_all(count, rTTIClassHierarchyDescriptor(_, _, _), Count4),
    Count is Count1 + Count2 + Count3 + Count4.

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
