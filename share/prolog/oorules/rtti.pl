:- import member/2 from lists.

:- index(rTTICompleteObjectLocator/6, [1,2,3,4,5,6]).
:- dynamic rTTICompleteObjectLocator/6.
:- index(rTTITypeDescriptor/3, [1,2,3]).
:- dynamic rTTITypeDescriptor/3.
:- index(rTTIClassHierarchyDescriptor/3, [1,2,3]).
:- dynamic rTTIClassHierarchyDescriptor/3.
:- dynamic rTTIBaseClassDescriptor/8.

% Given a TypeDescriptor address, return Name.
:- table rTTIName/2 as opaque.
rTTIName(TDA, Name) :-
    rTTITypeDescriptor(TDA, _TIVTable, Name).

:- table rTTITDA2VFTable/2 as opaque.
rTTITDA2VFTable(TDA, VFTable) :-
    rTTITypeDescriptor(TDA, _TIVTable, _Name),
    rTTICompleteObjectLocator(Pointer, _COLA, TDA, _CHDA, _Offset, _O2),
    VFTable is Pointer + 4.

% This tule must be table incremental because of the find() clause.
:- table rTTITDA2Class/2 as incremental.
rTTITDA2Class(TDA, Class) :-
    % First turn the TypeDescriptor address into a VFTable address.
    rTTITypeDescriptor(TDA, _TIVTable, _Name),
    rTTICompleteObjectLocator(Pointer, _COLA, TDA, _CHDA, _Offset, _O2),
    VFTable is Pointer + 4,
    % Now to turn the VFTable address into a class ID.
    % Presumably there's at least one method that write the VFTable pointer.
    factVFTableWrite(_Insn, Method, _ObjectOffset, VFTable),
    % But if that method is confused about which VFTable is the primary, don't use that method
    % to determine the correct class.   Presumably there will be another non-conflicted method
    % that will just produce the correct answer.
    not(possibleVFTableOverwrite(_, _, Method, _Offset, _VFTable1, _VFTable2)),
    % Finally, get the current class representative for that method.

    % Because of inlining and optimization, destructors should not be used for correlating TDAs
    % and VFTables.   See the commentary in mergeClasses().
    not(factNOTConstructor(Method)),

    find(Method, Class).

% In each class definition, there's supposed to be one circular loop of pointers that describes
% casting a class into itself.  This rule finds that set of pointers, tying together a type
% descriptor, a complete object locator, a class heirarchy descriptor, a base class descriptor,
% a primary virtual function table address, and a class name.

:- table rTTISelfRef/6 as opaque.
rTTISelfRef(TDA, COLA, CHDA, BCDA, VFTable, Name) :-
    rTTITypeDescriptor(TDA, _TIVTable, Name),
    rTTICompleteObjectLocator(Pointer, COLA, TDA, CHDA, _O1, 0),
    VFTable is Pointer + 4,
    rTTIClassHierarchyDescriptor(CHDA, _HierarchyAttributes, Bases),
    member(BCDA, Bases),

    % Silly Prolog thinks unsigned numbers don't exist.  That's so 1978!
    Big is 0x7fffffff,
    NegativeOne is Big * 2 + 1,
    rTTIBaseClassDescriptor(BCDA, TDA, _NumBases, 0, NegativeOne, 0, _BaseAttibutes, CHDA),

    % Debugging.
    %debug('debug-rTTISelfRef('),
    %debug(TDA), debug(', '),
    %debug(COLA), debug(', '),
    %debug(CHDA), debug(', '),
    %debug(BCDA), debug(', '),
    %debug(VFTable), debug(', '),
    %debug('\''), debug(Name), debug('\''), debugln(').'),
    true.

:- table rTTINoBase/1 as opaque.
rTTINoBase(TDA) :-
    rTTITypeDescriptor(TDA, _TIVTable, _Name),
    rTTIBaseClassDescriptor(_BCDA, TDA, 0, _M, _P, _V, _BaseAttibutes, _ECHDA).

:- table rTTIAncestorOf/2 as opaque.
rTTIAncestorOf(DerivedTDA, AncestorTDA) :-
    rTTICompleteObjectLocator(_Pointer, _COLA, DerivedTDA, CHDA, _Offset, _O2),
    rTTIClassHierarchyDescriptor(CHDA, _HierarchyAttributes, Bases),
    member(BCDA, Bases),
    rTTIBaseClassDescriptor(BCDA, AncestorTDA, _NumBases, _M, _P, _V, _BaseAttibutes, _ECHDA),
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
    rTTIBaseClassDescriptor(BCDA, AncestorTDA, _NumBases, M, P, V, 0x40, _ECHDA),
    AncestorTDA \= DerivedTDA,

    % Cory has still not found a more obvious way to determine whether the inheritance is
    % direct using P, V, or other flags.  This approach raises questions about what happens in
    % cases where the base class is inherited both directly and indirectly.  Will this
    % algorithm miss the direct base if it's also a base of a base?
    not(rTTIInheritsIndirectlyFrom(DerivedTDA, AncestorTDA)),

    %debug('debug-rTTIInheritsDirectlyFrom('),
    %debug(DerivedTDA), debug(', '),
    %debug(AncestorTDA), debug(', '),
    %debug(Attributes), debug(', '),
    %debug(M), debug(', '),
    %debug(P), debug(', '),
    %debug(V), debug(', '),
    %debug(BCDA), debugln(').'),
    true.

:- table rTTIInheritsVirtuallyFrom/6 as opaque.
rTTIInheritsVirtuallyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V) :-
    rTTICompleteObjectLocator(_Pointer, _COLA, DerivedTDA, CHDA, M, _O2),
    rTTIClassHierarchyDescriptor(CHDA, Attributes, Bases),
    member(BCDA, Bases),
    rTTIBaseClassDescriptor(BCDA, AncestorTDA, _NumBases, M, P, V, 0x50, _ECHDA),
    AncestorTDA \= DerivedTDA,

    not(rTTIInheritsIndirectlyFrom(DerivedTDA, AncestorTDA)),

    % Is M always zero in virtual inheritance?

    % Debugging.
    %debug('debug-rTTIInheritsVirtuallyFrom('),
    %debug(DerivedTDA), debug(', '),
    %debug(AncestorTDA), debug(', '),
    %debug(Attributes), debug(', '),
    %debug(M), debug(', '),
    %debug(P), debug(', '),
    %debug(V), debug(', '),
    %debug(BCDA), debugln(').'),
    true.


:- table rTTIInheritsFrom/6 as opaque.
rTTIInheritsFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V) :-
    (rTTIInheritsDirectlyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V);
     rTTIInheritsVirtuallyFrom(DerivedTDA, AncestorTDA, Attributes, M, P, V)).

% --------------------------------------------------------------------------------------------
:- table reasonRTTIInformation/3 as incremental.

% This rule is only used in final.pl to obtain a class name now.  Perhaps it should be
% rewritten.
% PAPER: XXX
reasonRTTIInformation(VFTableAddress, Pointer, RTTIName) :-
    rTTICompleteObjectLocator(Pointer, _COLAddress, TDAddress, _CHDAddress, _O1, _O2),
    rTTITypeDescriptor(TDAddress, _VFTableCheck, RTTIName),
    VFTableAddress is Pointer + 4,
    factVFTable(VFTableAddress).

% ============================================================================================
% Validation
% ============================================================================================

% Is the use of RTTI information during reasoning enabled?
:- dynamic rTTIEnabled/0 as opaque.

rTTIInvalidBaseAttributes :-
    rTTIBaseClassDescriptor(_BCDA, _TDA, _NumBases, _M, _P, _V, Attributes, _CHDA),
    Attributes \= 0x50,
    Attributes \= 0x40,
    debug('RTTI Information is invalid because BaseClassDescriptor Attributes = '),
    debugln(Attributes).

rTTIInvalidCOLOffset2 :-
    rTTICompleteObjectLocator(_Pointer, _COLA, _TDA, _CHDA, _Offset, Offset2),
    Offset2 \= 0x0,
    Offset2 \= 0x4,
    debug('RTTI Information is invalid because CompleteObjectLocator Offset2 = '),
    debugln(Offset2).

rTTIInvalidDirectInheritanceP :-
    Big is 0x7fffffff,
    NegativeOne is Big * 2 + 1,
    rTTIInheritsDirectlyFrom(_DerivedTDA, _AncestorTDA, _Attributes, _M, P, _V),
    P \= NegativeOne,
    debug('RTTI Information is invalid because InheritsDirectlyFrom P = '),
    debugln(P).

rTTIInvalidDirectInheritanceV :-
    rTTIInheritsDirectlyFrom(_DerivedTDA, _AncestorTDA, _Attributes, _M, _P, V),
    V \= 0x0,
    debug('RTTI Information is invalid because InheritsDirectlyFrom V = '),
    debugln(V).

rTTIInvalidHierarchyAttributes :-
    rTTIClassHierarchyDescriptor(_CHDA, HierarchyAttributes, _Bases),

    % Attributes 0x0 means a normal inheritance (non multiple/virtual)
    HierarchyAttributes \= 0x0,

    % Attributes 0x1 means multiple inheritance
    HierarchyAttributes \= 0x1,

    % Attributes 0x2 is not believed to be possible since it would imply virtual inheritance
    % without multiple inheritance.

    % Attributes 0x3 means multiple virtual inheritance
    HierarchyAttributes \= 0x3,
    debug('RTTI Information is invalid because HierarchyAttributes = '),
    debugln(HierarchyAttributes).

:- table rTTIMissingSelfRef/1 as opaque.
rTTIMissingSelfRef(TDA) :-
    not(rTTISelfRef(TDA, _COLA, _CHDA, _BCDA, _VFTable, _Name)),
    rTTIName(TDA, Name),
    debug('RTTI Information is invalid because there is no self-ref for: '),
    debug(TDA), debug(' with class name '), debugln(Name).

:- table rTTIShouldHaveSelfRef/1 as opaque.
rTTIShouldHaveSelfRef(TDA) :-
    rTTITypeDescriptor(TDA, _VFTableCheck, _RTTIName),
    rTTICompleteObjectLocator(_Pointer, _COLA, TDA, _CHDA, _O1, _O2).

:- table rTTIHasSelfRef/1 as opaque.
rTTIHasSelfRef(TDA) :-
    not(rTTIMissingSelfRef(TDA)).

% Is the RTTI information internally consistent?
:- table rTTIValid/0 as opaque.
rTTIValid :-
    rTTIEnabled,
    not(rTTIInvalidBaseAttributes),
    not(rTTIInvalidCOLOffset2),
    not(rTTIInvalidDirectInheritanceP),
    not(rTTIInvalidDirectInheritanceV),
    setof(TDA, rTTIShouldHaveSelfRef(TDA), Set),
    maplist(rTTIHasSelfRef, Set).

% ============================================================================================
% Reporting
% ============================================================================================

:- import maplist/2 from swi.

reportNoBase((A)) :-
    write('rTTINoBaseName('),
    writeHex(A), write(', '),
    rTTIName(A, AName),
    write('\''), writeHex(AName), write('\''), writeln(').').
reportNoBase :-
    setof((A), rTTINoBase(A), Set),
    maplist(reportNoBase, Set).
reportNoBase :- true.

reportAncestorOf((D, A)) :-
    write('rTTIAncestorOfName('),
    writeHex(D), write(', '),
    writeHex(A), write(', '),
    rTTIName(D, DName),
    rTTIName(A, AName),
    write('\''), writeHex(DName), write('\''), write(', '),
    write('\''), writeHex(AName), write('\''), writeln(').').
reportAncestorOf :-
    setof((D, A), rTTIAncestorOf(D, A), Set),
    maplist(reportAncestorOf, Set).
reportAncestorOf :- true.

reportInheritsDirectlyFrom((D, A, H, M, P, V)) :-
    write('rTTIInheritsDirectlyFromName('),
    writeHex(D), write(', '),
    writeHex(A), write(', '),
    writeHex(H), write(', '),
    writeHex(M), write(', '),
    writeHex(P), write(', '),
    writeHex(V), write(', '),
    rTTIName(D, DName),
    rTTIName(A, AName),
    write('\''), writeHex(DName), write('\''), write(', '),
    write('\''), writeHex(AName), write('\''), writeln('). ').
reportInheritsDirectlyFrom :-
    setof((D, A, H, M, P, V), rTTIInheritsDirectlyFrom(D, A, H, M, P, V), Set),
    maplist(reportInheritsDirectlyFrom, Set).
reportInheritsDirectlyFrom :- true.

reportInheritsVirtuallyFrom((D, A, H, M, P, V)) :-
    write('rTTIInheritsVirtuallyFromName('),
    writeHex(D), write(', '),
    writeHex(A), write(', '),
    writeHex(H), write(', '),
    writeHex(M), write(', '),
    writeHex(P), write(', '),
    writeHex(V), write(', '),
    rTTIName(D, DName),
    rTTIName(A, AName),
    write('\''), writeHex(DName), write('\''), write(', '),
    write('\''), writeHex(AName), write('\''), writeln('). ').
reportInheritsVirtuallyFrom :-
    setof((D, A, H, M, P, V), rTTIInheritsVirtuallyFrom(D, A, H, M, P, V), Set),
    maplist(reportInheritsVirtuallyFrom, Set).
reportInheritsVirtuallyFrom :- true.


reportSelfRef((T, L, C, B, V, N)) :-
    write('rTTISelfRef('),
    writeHex(T), write(', '),
    writeHex(L), write(', '),
    writeHex(C), write(', '),
    writeHex(B), write(', '),
    writeHex(V), write(', '),
    write('\''), writeHex(N), write('\''), writeln('). ').
reportSelfRef :-
    setof((T, L, C, B, V, N), rTTISelfRef(T, L, C, B, V, N), Set),
    maplist(reportSelfRef, Set).
reportSelfRef :- true.

rTTISolve(X) :-
    load_dyn(X).

reportRTTIResults :-
    rTTIValid,
    reportNoBase,
    reportSelfRef,
    reportAncestorOf,
    reportInheritsDirectlyFrom,
    reportInheritsVirtuallyFrom,
    writeln('Report complete.').

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
