:- use_module(library(http/json), [json_write_dict/2]).
:- use_module(library(apply), [maplist/3]).
:- use_module(library(lists), [member/2, max_list/2]).

:- dynamic finalClass/6.
:- dynamic finalVFTable/5.
:- dynamic finalVFTableEntry/3.
:- dynamic finalVBTable/4.
:- dynamic finalVBTableEntry/3.
:- dynamic finalResolvedVirtualCall/3.
:- dynamic finalEmbeddedObject/4.
:- dynamic finalInheritance/5.
:- dynamic finalMember/4.
:- dynamic finalMemberAccess/4.
:- dynamic finalMethodProperty/3.
:- dynamic finalThunk/2.
:- dynamic finalDemangledName/4.

:- ensure_loaded(util).
:- ensure_loaded(results).

% ===================================================================
% Usages
% ===================================================================

makeClassName(ClassId, Out):-
    finalClass(ClassId, VFTable, _, _, _, _),
    % Only use the VFTable as the name if finalClass did.  This is necessary to ensure we don't
    % use the same name for multiple classes which causes an error
    ClassId=VFTable,
    % If there's a VFTable for the address, and the VFTable has a non-null name, then use that
    % name, otherwise make a class name from the address.
    finalVFTable(VFTable, _, _, _, RTTIName),
    iso_dif(RTTIName, ''),
    Out = RTTIName,
    !.

makeClassName(ClassId, Out):-
    % Does this always make sense?
    hexAddr(ClassId, HexAddr),
    string_concat('cls_', HexAddr, Out),
    !.

hexAddr(Addr, Out):-
    format(atom(Out), '0x~16r', Addr).

decAddr(Addr, Out):-
    format(atom(Out), '~10r', Addr).

% ===================================================================
% Members
% ===================================================================

% BUG?  Is it possible to have finalInheritance without a corresponding finalMember?

% When the member is a virtual function table point it gets named
% vftptr_offset
makeMemberPrefix(ClassId, 0, Out) :-
    finalClass(ClassId, VFTable, _, _, _, _),
    iso_dif(VFTable, 0),
    Out = "vftptr",
    !.

makeMemberPrefix(ClassId, Offset, Out) :-
    finalInheritance(ClassId, _OtherClassId, Offset, _, _),
    Out = "vftptr",
    !.

makeMemberPrefix(_, _, Out) :-
    Out = "mbr",
    !.

makeMemberName(_ClassId, Offset, Prefix, Out):-
    % The type isn't currently set to 'vftptr' or 'struc' anywhere right now.
    string_concat(Prefix, '_', TempStr),
    hexAddr(Offset, OffsetStr),
    string_concat(TempStr, OffsetStr, Out).


makeMemberType(_ClassId, _Size, "vftptr", "vftptr"):- !.
makeMemberType(_ClassId, Size, _Prefix, Out) :- makeMemberTypeFromSize(Size, Out), !.


% Type of standard members is blank
makeMemberTypeFromSize(_, "") :- !.

% For reasons that are not entirely clear, the C++ JSON exporter feels that every class
% with with a base class containing a virtual function table has it's own copy of the
% vftable pointer field.  I would have considered this part of the base class, being
% written into by the derived class, but maybe there's a reason that's inconvenient in the
% importer plusgins.  Rather than change the OOAnalyzer results, let's kludge it up by
% adding the missing results here as a special rule.  Unfortuntely, this means that the
% members are not longer coincidentally in the correct order, so we need to do some
% additional sorting (which perhaps we should be doing anyway).
:- table expandedFinalMember/2.
expandedFinalMember(ClassId, Offset):-
    finalInheritance(ClassId, _InnerClassId, Offset, _, _).

expandedFinalMember(ClassId, Offset):-
    finalEmbeddedObject(ClassId, Offset, _InnerClassId, _).

expandedFinalMember(ClassId, Offset):-
    finalMember(ClassId, Offset, _SizeList, _Confidence).

expandedFinalMember(ClassId, Offset):-
    finalMemberAccess(ClassId, Offset, _Size, _InsnList).


getBaseMember(ClassId, Offset, false):-
    finalInheritance(ClassId, _InnerClassId, Offset, _, _), !.

getBaseMember(ClassId, Offset, false):-
    finalEmbeddedObject(ClassId, Offset, _InnerClassId, _), !.

getBaseMember(ClassId, Offset, false):-
    finalMember(ClassId, Offset, _SizeList, _Confidence), !.

getBaseMember(_ClassId, _Offset, true):-
    true.

getMemberSizes(ClassId, Offset, Size):-
    finalMember(ClassId, Offset, SizeList, _Confidence), max_list(SizeList, Size).
getMemberSizes(ClassId, Offset, Size):-
    finalMemberAccess(ClassId, Offset, Size, _InsnList).

% BUG! This finds code USED TO find members usages that the Pharos JSON exporter does NOT.
% That's really a subtle bug in the way finalMemberAccess results are reported for accesses of
% base class members.  If the base class access is in a derived class method, there will be a
% finalMethodAccess result for a member that's not directly on the derived class.  The C++ JSON
% exporter currently only exports accesses for members "exactly" on the derived class.  For an
% example, see 0x411156c in 2008/Debug/ooex2.

% Normal member
makeNormalMemberJson(ClassId, Offset, OffsetStr, Out):-
    expandedFinalMember(ClassId, Offset),
    getBaseMember(ClassId, Offset, Base),
    ((finalEmbeddedObject(ClassId, Offset, InnerClassId, _);
      finalInheritance(ClassId, InnerClassId, Offset, _, _)) ->
         (
             (finalClass(InnerClassId, _VFTable, Size, _OtherSize, _RealDestruct, _Methods)
              -> true;
              (Size=unknown,
               logerrorln('Unable to find class ~Q. Please report this error to the OOAnalyzer developers.', InnerClassId))),
             makeClassName(InnerClassId, ClsType),
             makeMemberName(ClassId, Offset, ClsType, MemberName),
             Struct = ClsType, Type = 'struc'
         );
     (
         bagof(Size, getMemberSizes(ClassId, Offset, Size), SizeList),
         max_list(SizeList, Size),
         makeMemberPrefix(ClassId, Offset, Prefix),
         makeMemberType(ClassId, Size, Prefix, Type),
         makeMemberName(ClassId, Offset, Prefix, MemberName),
         Struct = ''
     )
    ),
    (finalInheritance(ClassId, _, Offset, _, _) -> Parent=true; Parent=false),
    (setof(InsnAddr, memberAccess(ClassId, Offset, InsnAddr), UsageList) ->
         true; UsageList=[]),
    maplist(hexAddr, UsageList, UsageJson),
    hexAddr(Offset, OffsetStr),
    Out = member{'name': MemberName, 'type': Type, 'size': Size, 'struc': Struct,
                 'parent': Parent, 'offset': OffsetStr, 'base': Base,
                 'usages': UsageJson}.

memberAccess(ClassId, Offset, InsnAddr):-
    finalMemberAccess(ClassId, Offset, _Size, Instructions),
    member(InsnAddr, Instructions).

% First process normal members, sorted by their offsets.
makeOneMemberJson(ClassId, OffsetStr, Json):-
    findall(Offset, expandedFinalMember(ClassId, Offset), OffsetList),
    sort(0, @=<, OffsetList, SortedOffsetList),
    member(SortedOffset, SortedOffsetList),
    makeNormalMemberJson(ClassId, SortedOffset, OffsetStr, Json).

% This was the right syntax when Out was a json()...
makeAllMembersJson(ClassID, Json) :-
    bagof(OffsetStr:Out, makeOneMemberJson(ClassID, OffsetStr, Out), KVPairs),
    dict_create(Json, jsontag, KVPairs).

% ===================================================================
% Methods
% ===================================================================

methodType(Address, 'ctor'):-
    finalMethodProperty(Address, constructor, _), !.
methodType(Address, 'dtor'):-
    finalMethodProperty(Address, realDestructor, _), !.
methodType(Address, 'deldtor'):-
    finalMethodProperty(Address, deletingDestructor, _), !.
methodType(_Address, 'meth'):- !.

methodPrependVirt(_ClassId, Address, InType, OutType):-
    finalThunk(Thunk, Address),
    finalVFTableEntry(_VFTable, _Offset, Thunk),
    string_concat('virt_', InType, OutType),
    !.

methodPrependVirt(_ClassId, Address, InType, OutType):-
    finalVFTableEntry(_VFTable, _Offset, Address),
    string_concat('virt_', InType, OutType),
    !.

methodPrependVirt(_ClassId, _Address, InType, OutType):-
    InType = OutType, !.

makeMethodName(Address, _Type, true, OutMangled, OutDemangled):-
    finalDemangledName(Address, OutMangled, _ClassName, OutDemangled),
    !.

makeMethodName(Address, Type, false, OutMangled, ''):-
    hexAddr(Address, AddressStr),
    string_concat(Type, '_', NamePrefix),
    string_concat(NamePrefix, AddressStr, OutMangled),
    !.

makeMethodJson(ClassId, Address, AddrStr, Out):-
    methodType(Address, Type1),
    methodPrependVirt(ClassId, Address, Type1, Type),

    hexAddr(Address, AddrStr),

    makeMethodName(Address, Type, Imported, MangledName, DemangledName),

    Out = method{'ea': AddrStr, 'name': MangledName, 'import': Imported,
                 'demangled_name': DemangledName, 'type': Type1 }.

makeOneMethodJson(ClassId, AddressKey, Json):-
    % Get the list of all methods on the class.
    finalClass(ClassId, _VFTable, _Size, _OtherSize, _RealDestructor, Methods),
    % We need to not only be in the method list...
    member(Address, Methods),

    % If the method is a virtual method on this class, don't list it here.  We'll list it in
    % the corresponding VFTable instead.
    %virtualMethodsOnClass(ClassId, VirtualMethods),
    %not(member(Address, VirtualMethods)),

    makeMethodJson(ClassId, Address, AddressKey, Json).

makeAllMethodsJson(ClassId, Json):-
    bagof(Address:Out, makeOneMethodJson(ClassId, Address, Out), KVPairs),
    dict_create(Json, methods, KVPairs).

% ===================================================================
% VFTables
% ===================================================================


%makeVFTableEntryJson(triple(ClassId, Offset, Address), Out):-
makeVFTableEntryJson(ClassId, VFTable, Key, Out):-
    % For each dethunked method in the VFTable...
    dethunkedVFTableMethod(VFTable, Offset, Address),

    % It also needs to be in the Methods list on the class, because if it's not it means that
    % the method is really associated with a base class, and we don't want to report it here.
    % Don't match the primary VFTable for the class, because we might be reporting on a second
    % base class vftable.
    finalClass(ClassId, _MaybeNotPrimaryVFTable, _Size, _OtherSize, _RealDestructor, Methods),
    member(Address, Methods),

    methodType(Address, Type1),
    methodPrependVirt(ClassId, Address, Type1, Type),
    makeMethodName(Address, Type, Imported, MangledName, DemangledName),
    hexAddr(Address, AddrStr),
    % Convert the memory offset (bytes) into a table entry offset by dividing by the size of
    % pointer.  Hard coding 4 here presumes 32-bit addresses.  If we support 64-bit OO programs
    % in the future, we'll need to know our architecture byte size here.
    OffsetCount is Offset // 4,
    decAddr(OffsetCount, OffsetDecStr),
    atom_string(Key, OffsetDecStr),
    Out = vftentry{'ea': AddrStr, 'offset': OffsetCount, 'name': MangledName,
                   'demangled_name': DemangledName, 'import': Imported, 'type': Type1}.

oneVFTableEntry(ClassId, VFTable, Offset, Method):-
    % For each dethunked method in the VFTable...
    dethunkedVFTableMethod(VFTable, Offset, Method),

    % It also needs to be in the Methods list on the class, because if it's not it means that
    % the method is really associated with a base class, and we don't want to report it here.
    finalClass(ClassId, _MaybeNotPrimaryVFTable, _Size, _OtherSize, _RealDestructor, Methods),
    member(Method, Methods).

findEntries(ClassId, VFTable, VFTableEntriesJson):-
    (bagof(Key:Out, makeVFTableEntryJson(ClassId, VFTable, Key, Out), KVPairs),
     dict_create(VFTableEntriesJson, entries, KVPairs)) -> true;
     VFTableEntriesJson = entries{}.

makeVFTableJson(ClassId, VFTable, Offset, AddrStr, Out):-
    hexAddr(VFTable, AddrStr),
    finalVFTable(VFTable, Size, _, _, _),
    Length is Size // 4,
    hexAddr(Offset, OffsetStr),
    findEntries(ClassId, VFTable, VFTableEntries),
    Out = vftable{'ea': AddrStr, 'vftptr': OffsetStr, 'entries': VFTableEntries, 'length': Length }.

% Return true if the method is a virtual method on the class.
:- table virtualMethodOnClass/2.
virtualMethodOnClass(ClassId, Method):-
    setof(VFT, Offset^vFTableForClass(ClassId, VFT, Offset), VFTableList),
    member(VFTable, VFTableList),
    dethunkedVFTableMethod(VFTable, _MethodOffset, Method).

% Construct a list of virtual methods on the class, return an empty list if there are none.
:- table virtualMethodsOnClass/2.
virtualMethodsOnClass(ClassId, MethodList):-
    setof(Method, virtualMethodOnClass(ClassId, Method), MethodList) -> true; MethodList=[].

% Return true if there's a VFTable at the given offset in the class.
:- table vFTableForClass/3.
vFTableForClass(ClassId, VFTable, Offset):-
    (finalClass(ClassId, VFTable, _Size, _OtherSize, _RealDestructor, _Methods), Offset=0);
    finalInheritance(ClassId, _BaseClassId, Offset, VFTable, _).

makeOneVFTableJson(ClassId, AddrStr, Json):-
    vFTableForClass(ClassId, VFTable, Offset),
    finalVFTable(VFTable, _Size1, _Size2, _RTTI, _MangledName),
    makeVFTableJson(ClassId, VFTable, Offset, AddrStr, Json).

makeAllVFTablesJson(ClassId, Json):-
    bagof(AddrStr:Out, makeOneVFTableJson(ClassId, AddrStr, Out), KVPairs),
    dict_create(Json, jsontag, KVPairs).

dethunkedVFTableMethod(VFTable, Offset, Method):-
    % There must be an entry in the VFTable for us to report it here.
    finalVFTableEntry(VFTable, Offset, Addr),

    % IF there is a thunk, use that.  Otherwise use the address.
    once((finalThunk(Addr, Method); Method = Addr)).

% ===================================================================
% Main
% ===================================================================

makeOneClassJson(ClassId, Json):-

    % BUG! We're missing classes composed entirely of imported methods right now.
    % Probably because one of the rules for building up the class JSON object is missing
    % one of the finalProperties that is currently expected to be present.  See
    % 2008/Debug/ooex7 basic_ostream for an example.

    finalClass(ClassId, VFTable, Size, _OtherSize, _RealDestructor, Methods),

    once(
            % This duplicates the code in makeClassName, but we do this to also get the
            % DemangledName, which makeClassName doesn't provide.
            (
                ClassId=VFTable,
                finalDemangledName(VFTable, ClassName, DemangledName, _UnusedMethodName1)
                ;
                (member(Method, Methods),
                 % The MangledClassName field is NOT in fact a mangled class name.  It's a mangled
                 % _method_ name, but the old JSON exports the wrong thing here, and right now, I'm
                 % just trying to match.
                 finalDemangledName(Method, _MangledMethodName, DemangledName, _UnusedMethodName2),
                 makeClassName(ClassId, ClassName))
            )
            ;
            (DemangledName = '', makeClassName(ClassId, ClassName))
        ),

    %format(atom(SizeStr), '~d', Size),

    (makeAllMembersJson(ClassId, MemberJson) -> true; MemberJson = members{}),
    (makeAllMethodsJson(ClassId, MethodJson) -> true; MethodJson = methods{}),
    (makeAllVFTablesJson(ClassId, VFTableJson) -> true; VFTableJson = vftables{}),

    Json = classes{'name': ClassName, 'demangled_name': DemangledName,
                   'size': Size, 'members': MemberJson,
                   'methods': MethodJson, 'vftables': VFTableJson}.

makeOneClassInOrder(List, SortedClassNames, NameKey, Json):-
    member(C, List),
    makeOneClassJson(C, Json),
    % The class name is not necessarily unique because there can be multiple vftables that
    % contain the same name.  If it is unique, we will use that.  If not, we'll use the class
    % ID instead.
    ((nth0(I1, SortedClassNames, Json.name), nth0(I2, SortedClassNames, Json.name), iso_dif(I1, I2))
     ->
         hexAddr(C, ClassIdStr)
     ;
     ClassIdStr = Json.name),
    atom_string(NameKey, ClassIdStr).

makeAllStructuresJson(Json):-
    % Get a list of Class IDs and sort them by the class ID.
    findall(ClsId, finalClass(ClsId, _, _, _, _, _), ClassIDList),
    sort(0, @=<, ClassIDList, SortedClassIDList),
    maplist(makeClassName, SortedClassIDList, SortedClassNameList),
    bagof(NameKey:ClsJson, makeOneClassInOrder(SortedClassIDList, SortedClassNameList, NameKey, ClsJson), KVPairs),
    dict_create(Json, structures, KVPairs).

makeOneVcallUsageJson(Insn, Key, Out):-
    setof(Target, VFTable^finalResolvedVirtualCall(Insn, VFTable, Target), Targets),
    maplist(hexAddr, Targets, TargetJsons),
    hexAddr(Insn, HexAddr),
    atom_string(Key, HexAddr),
    Out = vcall{'targets': TargetJsons}.


exportJSONTo(FileName) :-
    setup_call_cleanup(
        open(FileName, write, Stream),
        with_output_to(Stream, exportJSON),
        close(Stream)).

exportJSON :-
    makeAllStructuresJson(ClassJson),
    (bagof(Key:Out, Insn^makeOneVcallUsageJson(Insn, Key, Out), KVPairs) ->
         dict_create(VcallsJson, vcalls, KVPairs);
     VcallsJson = vcalls{}),
    finalFileInfo(FileMD5, FileName),
    json_write_dict(current_output,
                    root{'structures': ClassJson, 'vcalls':VcallsJson, 'version': '2.2.0',
                         'filemd5': FileMD5, 'filename': FileName}),
    writeln('').

exportJSON(ResultsFile) :-
    loadResults(ResultsFile),
    exportJSON.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
