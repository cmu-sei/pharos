%% Copyright 2017 Carnegie Mellon University.
%% --------------------------------------------------------------------------------------------

%% This prolog files contains rules to reason about type propogation in pharos. These rules are
%% used in libpharos/types.cpp

:- compiler_options([spec_off]).

:- import member/2 from basics.
:- import length/2 from basics.
:- import format/2 from basics.

:- dynamic opAdd/2.
:- dynamic opAsr/3.
:- dynamic opBvAnd/2.
:- dynamic opBvOr/2.
:- dynamic opBvXor/2.
:- dynamic opConcat/2.
%:- dynamic opEq/3. probably unused
:- dynamic opExtract/4.
:- dynamic opInvert/2.
:- dynamic opIte/4. % No other references!
:- dynamic opRead/2.
:- dynamic opRol/3.
:- dynamic opRor/3.
:- dynamic opSdiv/3.
:- dynamic opSextend/3.
:- dynamic opShl0/3.
:- dynamic opShl1/3.
:- dynamic opShr0/3.
:- dynamic opShr1/3.
:- dynamic opSmod/3. % No other references!
:- dynamic opSmul/3.
:- dynamic opUdiv/3.
:- dynamic opUextend/3.
:- dynamic opUmod/3. % No other references!
:- dynamic opUmul/3.
:- dynamic opZerop/2. % No other references!
:- dynamic archBits/1.

%% API-related facts
:- dynamic apiCallName/2.
:- dynamic sameType/2.
:- dynamic functionCallArg/3.
:- dynamic functionCallRetval/2.
:- dynamic apiParamPointerness/3.
:- dynamic apiParamType/4.
:- dynamic typePointerness/2.
:- dynamic typeSignedness/2.
:- dynamic expectedSigned/2.
:- dynamic expectedPointer/2.
:- dynamic memaddr/1.
:- dynamic bitwidth/2.
:- dynamic value/2.
:- dynamic pointsTo/2.
:- dynamic typeRef/2.

%%  Facts for knowned-ness :)
:- dynamic knownPointer/2.
:- dynamic knownSigned/2.
:- dynamic knownTypename/2.
:- dynamic knownObject/2.

:- table pointer/2.
:- table signed/2.
:- table typeName/2.
:- table object/2.

:- table finalPointer/2.
:- table finalSigned/2.
:- table finalObject/2.

%%  This is now duplicated in our system (see util.pl)
iso_dif(X, Y) :-
   X \== Y,
   (X \= Y -> true).

%%  debugging code
:- dynamic debuggingEnabled/0.
:- dynamic debuggingStoreEnabled/0.

%% Uncomment to debug
%% debuggingEnabled :- true.

debug(X) :-
    debuggingEnabled -> write(X) ; true.

debugln(X) :-
    debuggingEnabled -> writeln(X) ; true.


%% ==============================================================================

%% Handle symetry in type equality. Could probably write this in a more abbreviated way
typeEquals(Tnp1, Tnp2) :- (sameType(Tnp1, Tnp2); sameType(Tnp2, Tnp1)).

%% The typename rules place type names on the treenodes based on how they are used in
%% API calls.

%% generate type names for parameters based on API information
typeName(ParamTnp, TypeName) :-
    functionCallArg(Call, Ordinal, ParamTnp),
    apiParamType(Api, Ordinal, TypeName, _),
    apiCallName(Call, Api),
    debug('typeName API rules '), debug(ParamTnp), debug(' = '), debugln(TypeName).

%% The case where a tree node has a known type name
typeName(VarTnp, TypeName) :-
    knownTypename(VarTnp, TypeName),
    debug('typeName knownTypeName rule '), debug(VarTnp), debug(' = '), debugln(TypeName).

% Handle tree nodes that are the same type and one type name is known. In this case we can
% infer that the variable is the same type as the other.
typeName(Tnp, TypeName) :-
    typeEquals(Tnp, OtherTnp), % in PBV the variable and parameter are the same type
    iso_dif(Tnp, OtherTnp),
    typeName(OtherTnp, TypeName),
    debug('typeName sameType rule '), debug(Tnp), debug(' == '), debug(OtherTnp), debug(' : '), debugln(TypeName).

%% We do not believe that this rule is needed anymore. There are other rules, based on sameType
%% analysis that will properly assigne types. It isn't hurting anything to leave it be
%% (currently), but we should review and figure out if it is still necessary.
%%
%% Add the types that are passed by reference (PBR). In this relationship the value in the
%% parameter is the address of the stack variable, so we can deduce the type name of variable
%% from the parameter
%% typeName(VarTnp, VarTypeName) :-
%%     pointsTo(VarAddressTnp, VarTnp),
%%     typeEquals(VarAddressTnp, ParamTnp), % the address of the variable is the same type as the param
%%     iso_dif(VarAddressTnp, ParamTnp),

%%     %%  If this is the same type, then the type name is the same
%%     typeName(ParamTnp, ParamType),

%%     %%  The type must be a pointer for a valid PBR
%%     typePointerness(ParamType, pointer),
%%     typeRef(ParamType, VarTypeName),
%%     debug('typeName PBR rule '), debugln(VarTnp).

%% Handle the situation where the name of the value is known, but not the name of address type.
typeName(AddrTnp, AddrTypename) :-
    pointsTo(AddrTnp, ValTnp),
    % the typename is either a known type name or has been assigned
    (knownTypename(ValTnp, ValTypename); typeName(ValTnp, ValTypename)),
    iso_dif(AddrTnp, ValTnp),
    typeRef(AddrTypename, ValTypename),
    debug('typeName name of value known rule '), debug(AddrTnp), debug(' = '), debugln(AddrTypename).

%% Set the type of the variable based on the type of its address
typeName(VarTnp, VarTypeName) :-
    pointsTo(AddrTnp, VarTnp), % binds AddrTnp
    iso_dif(AddrTnp, VarTnp),
    (knownTypename(AddrTnp,AddrTypeName); typeName(AddrTnp, AddrTypeName)),
    typeRef(AddrTypeName, VarTypeName),
    debug('typeName type of address known rule '), debug(VarTnp), debug(' = '), debugln(VarTypeName).

%% In this case there is no knownPointer fact, so reason about the pointer type via how it is
%% passed to an API
typeName(AddrTnp, AddrTypename) :-
    pointsTo(AddrTnp, ValTnp), % binds ValTnp
    iso_dif(AddrTnp, ValTnp),

    functionCallArg(_, Ord, ValTnp),
    apiParamType(_, Ord, ValTypename, _), % binds typename

    typeRef(AddrTypename, ValTypename),
    debug('typeName pointer type known rule '), debug(AddrTnp), debug(' = '), debugln(AddrTypename).


%% handle return type names from APIs
typeName(Tnp, TypeName) :-
    functionCallRetval(FnCall, Tnp),
    apiCallName(FnCall, ApiName),
    apiReturnType(ApiName, TypeName),
    debug('typeName return type rule ' ), debug(Tnp), debug(' = '), debugln(TypeName).

%% ======================================================================
%%  Object analysis

%% if something is a known object, then it is obviously an object
object(Tnp, is) :-
    knownObject(Tnp, is).

%% Handle tree node eqivalence as it pertains to objectneNamess
object(Tnp, is) :-
    typeEquals(Tnp, OtherTnp),
    iso_dif(Tnp, OtherTnp),
    object(OtherTnp, is).

%% ======================================================================
%% Api-related pointer analysis

%%  Obviously if pointer type is known, mark it as such, right?
pointer(Tnp, is) :-
    knownPointer(Tnp, is),
    debug('knownPointer IS rule '), debugln(Tnp).

%% All __this pointers are ... well ... pointers
pointer(Tnp, is) :-
    object(Tnp, is).

pointer(Tnp, isnot) :-
    knownPointer(Tnp, isnot),
    debug('knownPointer ISNOT rule '), debugln(Tnp).

%%  Obviously any tree node that points to something is a pointer, right?
pointer(Tnp, is) :-
    pointsTo(Tnp, _),
    debug('pointsTo IS rule '), debugln(Tnp).

%%  Mark parameter a pointer based on type name
pointer(ParamTnp, is) :-
    typeName(ParamTnp, TypeName),
    typePointerness(TypeName, pointer),
    debug('param pointer IS based on typename rule '), debugln(ParamTnp).

pointer(ParamTnp, isnot) :-
    typeName(ParamTnp, TypeName),
    typePointerness(TypeName, notpointer),
    debug('param not pointer ISNOT based on typename rule '), debug(ParamTnp).

%% OUT parameters must be pointers. Otherwise they would not retain their values
pointer(ArgTnp, is) :-
    apiCallName(Call, Api),
    functionCallArg(Call, Ordinal, ArgTnp),
    apiParamType(Api, Ordinal, _, out),
    debug('out parameter pointer IS rule '), debugln(ArgTnp).

%% We are not sure that we really needs these two pointer rules. The PBR typename rule and the
%% typePointerness rule may be sufficient. Having these rules seems to dramatically increase
%% run time (almost double)

%% If the parameter type is a pointer, then we know something about what it points to
pointer(VarTnp, isnot) :-
    pointsTo(VarAddressTnp, VarTnp),
    typeName(ArgTnp, PointerType), % bind the type name
    typeEquals(VarAddressTnp, ArgTnp),

    %% Determine if pointee type is a pointer by checking refs
    typeRef(PointerType, PointeeType),
    typePointerness(PointeeType, notpointer),
    debug('PBR pointer ISNOT rule '), debugln(VarTnp).

pointer(VarTnp, is) :-
    pointsTo(VarAddressTnp, VarTnp),
    typeName(ArgTnp, PointerType),  % bind the type name
    typeEquals(VarAddressTnp, ArgTnp),

    %% Determine if pointee type is a pointer by checking refs
    typeRef(PointerType, PointeeType),
    typePointerness(PointeeType, pointer),
    debug('PBR pointer IS rule '), debugln(VarTnp).

%% Handle tree node eqivalence
pointer(Tnp, is) :-
    typeEquals(Tnp, OtherTnp),
    iso_dif(Tnp, OtherTnp),
    pointer(OtherTnp, is),
    debug('TN equals pointer IS rule '), debug(Tnp), debug(' == '), debugln(OtherTnp).

pointer(Tnp, isnot) :-
    typeEquals(Tnp, OtherTnp),
    iso_dif(Tnp, OtherTnp),
    pointer(OtherTnp, isnot),
    debug('TN equals pointer ISNOT rule '), debug(Tnp), debug(' == '), debugln(OtherTnp).

%% ==============================================================================
%% API-type related signedness analysis

%%  Obviously if signedness is known, mark it as such, right?
signed(Tnp, is) :- knownSigned(Tnp, is).
signed(Tnp, isnot) :- knownSigned(Tnp, isnot).

%% Determine if signed/unsigned based on type name
signed(Tnp, is) :-
    typeEquals(Tnp, OtherTnp),
    iso_dif(Tnp, OtherTnp),
    signed(OtherTnp, is).

signed(Tnp, isnot) :-
    typeEquals(Tnp, OtherTnp),
    iso_dif(Tnp, OtherTnp),
    signed(OtherTnp, isnot).

signed(ParamTnp, is) :-
    typeName(ParamTnp, TypeName),
    typeSignedness(TypeName, signed).

% does the type name imply signedness?
signed(ParamTnp, isnot) :-
    typeName(ParamTnp, TypeName),
    typeSignedness(TypeName, unsigned).

%% Reference types refer to other types. If we have knowledge of those types then we can infer
%% signedness
signed(VarTnp, is) :-
    pointsTo(VarAddressTnp, VarTnp),
    typeEquals(VarAddressTnp, ArgTnp),
    typeName(ArgTnp, PointerType), % bind the type name

    %% Bind the pointer type to the pointee type and determine if the pointee type is signed
    typeRef(PointerType, PointeeType),
    typeRef(PointerType, PointeeType),
    typeSignedness(PointeeType, signed).

signed(VarTnp, isnot) :-
    pointsTo(VarAddressTnp, VarTnp),
    typeEquals(VarAddressTnp, ArgTnp),
    typeName(ArgTnp, PointerType), % bind the type name

    %% Bind the pointer type to the pointee type and detemine if the pointee type is signed
    typeRef(PointerType, PointeeType),
    typeRef(PointerType, PointeeType),
    typeSignedness(PointeeType, unsigned).

%% ==============================================================================
%%  Operation-related type rules

% Handle OP_SEXTEND pointer facts
% Nothing in a sign extend is a pointer.

%%  We have reason to believe that the result of a SEXTEND can in fact be a pointer due to an
%%  interaction with ITEs and flags. Currently, what we know for sure is that the Width of the
%%  extension cannot be a pointer. Thus, the following two rules are commented out.
%%
%% pointer(Result, isnot) :-
%%     opSextend(Result, _, _),
%%     debug('pointer ISNOT SEXTEND rule '), debugln(Result).
%% pointer(Result, isnot) :-
%%     opSextend(_, _, Result),
%%     debug('pointer ISNOT SEXTEND rule '), debugln(Result).

%%  The Width of the extension is always the second argument.

pointer(Width, isnot) :-
    opSextend(_, Width, _),
    debug('pointer ISNOT SEXTEND rule '), debugln(Width).

% signed extension means the result is signed
signed(Result, is) :-
    opSextend(Result, _, _).

% ==============================================================================
% Handle OP_UEXTEND pointer facts
% Nothing in an unsigned sign extend is a pointer.

%%  Like the SEXTEND, the Width parameter is the only one that will never be a pointer.
pointer(Width, isnot) :-
    opUextend(_, Width, _),
    debug('pointer ISNOT UEXTEND rule /2 '), debugln(Width).

% unsigned extension means the result is not signed
signed(Result, isnot) :-
    opUextend(Result, _, _).

% ==============================================================================
% Handle OP_BV_AND
% The only case where something in an AND operation is a pointer is when it is AND-ed with the
% dword align value. Affirming this may be to strong for pointerness.
pointer(Result, is) :-
    opBvAnd(Result, List),
    containsPointerAlignVal(List),
    debug('pointer IS BVAND rule '), debugln(Result).

% if the dword-align value is not present this cannot be a pointer
pointer(Result, isnot) :-
    opBvAnd(Result, List),
    \+ containsPointerAlignVal(List), % If the AND operation does not contain the alignment exception, it cannot be a pointer
    debug('pointer ISNOT BVAND rule '), debugln(Result).

% This is the hack to handle large numbers. We cannot put the integer version of the alignment
% value, 0xfffffff0 in the rules file because the number is too large for the xwam file format;
% thus it cannot be in this rules file. The hack is to convert the string version of the
% alignment value to a number and then compare that the the AlignVal
containsPointerAlignVal(List) :-
    member(Val, List),
    value(Val, AlignVal),
    string:atom_to_term('4294967280', X), X =:= AlignVal. % 4294967280 == 0xfffffff0

% ==============================================================================
% Handle OP_BV_OR
% The result of a logical OR or XOR cannot be a pointer
pointer(Result, isnot) :-
    (opBvOr(Result, _); opBvXor(Result, _)),
    debug('pointer ISNOT BV OR/XOR rule '), debugln(Result).

% ==============================================================================
% Handle EXTRACT and CONCAT, which has signedness and pointerness implications

% If an extract operation is OP_EXTRACT(R, A, B, C) where bits A ... B of C are extracted to R,
% then neither A nor B nor R can be a pointer. Technically, A and B should have value facts therenby
% adding evidence to their non-pointerness
pointer(Result, isnot) :-
    opExtract(Result, _, _, _),
    debug('pointer ISNOT EXTRACT Result rule '), debugln(Result).

pointer(A, isnot) :-
    opExtract(_, A, _, _),
    value(A, _),
    debug('pointer ISNOT EXTRACT/valueA rule '), debugln(A).

pointer(B, isnot) :-
    opExtract(_, _, B, _),
    value(B, _),
    debug('pointer ISNOT EXTRACT/valueB rule '), debugln(B).

signed(A, isnot) :-
    opExtract(_, A, _, _),
    value(A, _).

signed(B, isnot) :-
    opExtract(_, _, B, _),
    value(B, _).

% if the left-most element of the list (the most significant part of the concat) is signed
% then the result is signed; otherwise, the result is unsigned
signed(R, is) :-
    opConcat(R, [H|_]),
    signed(H, is).

signed(R, isnot) :-
    opConcat(R, [H|_]),
    signed(H, isnot).

% ==============================================================================
% Handle various shifts and rotates
% Nothing in a shift is ever a pointer - it is a purely mathematical operation
pointer(X, isnot) :-
    (opAsr(X, _, _); opShl0(X, _, _); opShl1(X, _, _); opShr0(X, _, _); opShr1(X, _, _); opRor(X, _, _); opRol(X, _, _)),
    debug('pointer ISNOT Shifts rule '), debugln(X).

pointer(X, isnot) :-
    (opAsr(_, X, _); opShl0(_, X, _); opShl1(_, X, _); opShr0(_, X, _); opShr1(_, X, _); opRor(_, X, _); opRol(_, X, _)),
    debug('pointer ISNOT Shifts rule '), debugln(X).

pointer(X, isnot) :-
    (opAsr(_, _, X); opShl0(_, _, X); opShl1(_, _, X); opShr0(_, _, X); opShr1(_, _, X); opRor(_, _, X); opRol(_, _, X)),
    debug('pointer ISNOT Shifts rule '), debugln(X).

% the shift/rotate amount for must be between 1 ... 31, it cannot be negative; thus it is not signed
signed(X, isnot) :-
    (opAsr(_, _, X); opShl0(_, _, X);  opShl1(_, _, X);  opShr0(_, _, X);  opShr1(_, _, X); opRor(_, _, X); opRol(_, _, X)),
    value(X, _). % as an extra check, make sure there is a value for the shift amount

% the shift right 1 introduces 1s at the MSB, JSG thinks this means the result is signed.
signed(X, is) :-
    opShr1(X, _, _).

% the shift right 0 introduces 0s at the LSB, JSG thinks this means the result is unsigned.
signed(X, isnot) :-
    opShr0(X, _, _).

% ==============================================================================
% Handle OP_ADD
% Adding two pointers results in a NOT pointer. However, we can encounter a list of addition operands.
% To deal with this there are two simple rules:
%
% 1. if the number of pointer operands is even, then the sum is not a pointer. This is because pointers cannot
%    be added.
% 2. if the number of pointer operands is oddd, the the sum is a pointer. This is to handle things like adding
%    an offset to a pointer.

% this is the base case that says that an empty list contains no pointers
countPointers([], 0).

% increment the pointer count recursively.
countPointers([H|T], P) :-
    (pointer(H, is), countPointers(T, X), P is X + 1); % If the list head is a pointer then increment pointer count
    (pointer(H, isnot), countPointers(T, P)).          % If the list head is not pointer, don't increment

% check eveness based on modulo; oddness is not even
even(N) :- 0 is N mod 2.
odd(N) :- \+ even(N).

% if num of pointers is even
pointer(R, is) :-
    opAdd(R, X),
    countPointers(X, P),
    odd(P),
    debug('pointer IS ADD rule '), debugln(R).

pointer(R, isnot) :-
    opAdd(R, X),
    countPointers(X, P),
    even(P),
    debug('pointer ISNOT ADD rule '), debugln(R).

% ==============================================================================
% Handle OP_SMUL/OP_UMUL  facts
% The result of a multiplication, signed or unsigned is not a pointer. TODO: Figure out if either of the
% operands can be pointers?
pointer(Result, isnot) :-
    opSmul(Result, _, _); opUmul(Result, _, _).

% The result of a signed multiplication is signed
signed(Result, is) :-
    opSmul(Result, _, _).

% The result of unsigned multiplication is usigned
signed(Result, isnot) :-
    opUmul(Result, _, _).

% ==============================================================================
% Handle OP_SDIV/OP_UDIV facts
% The result of a division, signed or unsigned is not a pointer. TODO: Figure out if either of the
% operands be pointers?
pointer(Result, isnot) :-
    (opSdiv(Result, _, _); opUdiv(Result, _, _)),
    debug('pointer ISNOT SDIV rule '), debugln(Result).

% The result of a signed division is signed
signed(Result, is) :-
    opSdiv(Result, _, _).

% The result of unsigned division is usigned
signed(Result, isnot) :-
    opUdiv(Result, _, _).

%% ==============================================================================
%% Handle OP_READ (probably unused)
%% By definition, the second operand of a read operation is memory and thus a pointer.
pointer(X, is) :-
    opRead(_, X),
    debug('pointer IS READ rule '), debugln(X).

%% ==============================================================================
%% Non-operation rules to reason about pointer/signed properties

%% This rule captures that no pointers are ever signed.
signed(X, isnot) :-
     pointer(X, is).

% and that nothing signed is ever a pointer
pointer(X, isnot) :-
    signed(X, is),
    debug('pointer ISNOT signed rule '), debugln(X).

% Anything that is has a memaddr fact is a pointer
pointer(X, is) :-
    memaddr(X),
     debug('pointer IS memaddr rule '), debugln(X).

%% A value is signed if it is negative. Unfortunately, signedness depends on the architecture.
%% So, the test requires shifting the value right to test if the most significant bit is set
%% isSigned32b(X, V) :-
%%     bitwidth(X, 0x20),
%%     Z is V >> 0x1f,
%%     Z =:= 1.

%% isSigned64b(X, V) :-
%%     bitwidth(X, 0x40),
%%     Z is sign(V),
%%     Z =:= -1.

%% isSigned16b(X, V) :-
%%     bitwidth(X, 0x10),
%%     Z is V >> 0xf,
%%     Z =:= 1.

%% isSigned8b(X, V) :-
%%     bitwidth(X, 0x8),
%%     Z is V >> 0x7,
%%     Z =:= 1.

%% signed(X, is) :-
%%     value(X, V),
%%     (isSigned64b(X, V); isSigned32b(X, V); isSigned16b(X, V); isSigned8b(X, V)).

%% signed(X, isnot) :-
%%     value(X, V),
%%     \+ (isSigned64b(X, V); isSigned32b(X, V); isSigned16b(X, V); isSigned8b(X, V)).

%% ==============================================================================

%% Pointers must correspond to architecture bits. Anything that is not that width cannot be a
%% pointer.
%%
%% This rule continues to be problematic because all facts must re-asserted. JSG isn't sure
%% that it is worth the fuss
%%
%% pointer(X, isnot) :-
%%     archBits(Bits),
%%     not(bitwidth(X, Bits)) -> debug('no bitwidth fact! '),
%%     debug('pointer ISNOT archbits rule '), debugln(X).

% One bit wide treenodes, aka booleans, are never signed and never pointers.
signed(X, isnot) :- bitwidth(X, 0x1).

pointer(X, isnot) :-
    bitwidth(X, 0x1),
    debug('pointer ISNOT bitwidth=1 rule '), debugln(X).

% ==============================================================================
% Hanle OP_INVERT facts
% Anything that is inverted is not a pointer
pointer(X, isnot) :-
    opInvert(_, X),
    debug('pointer ISNOT INVERT rule '), debugln(X).

% ==============================================================================
% For reporting and final summary of results.
% ==============================================================================

% A list of all treenodes in data.
treeNodeExists(X) :-
    bitwidth(X, _).

% Make the not-so-useful boolean results into something that's easier to report.

% Our final answer is bottom is we got both pointer and not-pointer.
finalPointer(X, bottom) :-
    pointer(X, is),
    pointer(X, isnot).

% Promote "is" to our final answer, but not if there's contradictory evidence.
finalPointer(X, is) :-
    pointer(X, is),
    tnot(pointer(X, isnot)),
    tnot(finalPointer(X, bottom)).

% Promote "isnot" to our final answer, but not if there's contradictory evidence.
finalPointer(X, isnot) :-
    pointer(X, isnot),
    tnot(pointer(X, is)),
    tnot(finalPointer(X, bottom)).

%% No need to report top.  It's implied by the absence of information.  If we really wanted to
%% do we could do it like this...  First export facts: treenode(a), treenode(b), for each tree
%% node, then: treenode(z).
finalPointer(X, top) :-
    treeNodeExists(X),
    tnot(pointer(X, is)),
    tnot(pointer(X, isnot)),
    tnot(finalPointer(X, bottom)).

%% ==============================================================================
%% signedness analysis

finalSigned(X, isnot) :-
    signed(X, isnot),
    tnot(signed(X, is)),
    tnot(finalSigned(X, bottom)).

finalSigned(X, is) :-
    signed(X, is),
    tnot(signed(X, isnot)),
    tnot(finalSigned(X, bottom)).

finalSigned(X, bottom) :-
    signed(X, is),
    signed(X, isnot).

finalSigned(X, top) :-
    treeNodeExists(X),
    tnot(signed(X, is)),
    tnot(signed(X, isnot)),
    tnot(finalSigned(X, bottom)).

%% ==============================================================================
%% Object-ness analysis

%% Our final answer is bottom is we got both object and not-object.
finalObject(X, bottom) :-
    object(X, is),
    object(X, isnot).

% Promote "is" to our final answer, but not if there's contradictory evidence.
finalObject(X, is) :-
    object(X, is),
    tnot(object(X, isnot)),
    tnot(finalObject(X, bottom)).

% Promote "isnot" to our final answer, but not if there's contradictory evidence.
finalObject(X, isnot) :-
    object(X, isnot),
    tnot(object(X, is)),
    tnot(finalObject(X, bottom)).

finalObject(X, top) :-
    treeNodeExists(X),
    tnot(object(X, is)),
    tnot(object(X, isnot)),
    tnot(finalObject(X, bottom)).

%%  ===========================================================================

%%  If there is a type name, then use it.
candidateTypeName(Tnp, TypeName) :-
    (typeName(Tnp, TypeName); knownTypename(Tnp, TypeName)),

    %% When something is missing in the API database

    TypeName \= '', TypeName \= 'top',
    debug('Candidate existing typeName for '), debug(Tnp), debug(' is '), debugln(TypeName).

%% if there is not a type name, then check for default signed non-pointer types
candidateTypeName(Tnp, TypeName) :-
    finalPointer(Tnp, isnot),
    finalSigned(Tnp, is),
    tnot(typeName(Tnp, TypeName)),
    (bitwidth(Tnp, 8)  -> TypeName = 'int8_t';
     bitwidth(Tnp, 16) -> TypeName = 'int16_t';
     bitwidth(Tnp, 32) -> TypeName = 'int32_t';
     bitwidth(Tnp, 64) -> TypeName = 'int64_t'),
    debug('Candidate default signed int for '), debugln(Tnp).

%% if there is not a type name, then check for default unsigned non-pointer types
candidateTypeName(Tnp, TypeName) :-
    finalPointer(Tnp, isnot),
    finalSigned(Tnp, isnot),
    tnot(typeName(Tnp, TypeName)),
    (bitwidth(Tnp, 8)  -> TypeName = 'uint8_t';
     bitwidth(Tnp, 16) -> TypeName = 'uint16_t';
     bitwidth(Tnp, 32) -> TypeName = 'uint32_t';
     bitwidth(Tnp, 64) -> TypeName = 'uint64_t'),
    debug('Candidate default unsigned int for '), debugln(Tnp).

%% There is a problem reasoning about default pointer types in the presence of other pointer
%% types. This doesn't bother JSG too much because the void* assignment was always pretty
%% superficial - pointerness is handled independently

%% candidateTypeName(Tnp, TypeName) :-
%%     finalPointer(Tnp, is),
%%     (tnot(typeName(Tnp, TypeName)); not(knownTypename(Tnp, TypeName))) -> TypeName = 'void*',
%%     debug('Candidate default void* for '), debugln(Tnp).

finalTypeName(Tnp, NameSet) :-
    setof(TypeName, candidateTypeName(Tnp, TypeName), NameSet),
    debug('Type name candidates for '), debug(Tnp), debug(': '), debugln(NameSet).

%% Ed's finalTypeName solution ... requires some thinking to understand
%% reallyFinalTypeName(A, B) :- finalTypeName(A, _), once(finalTypeName(A,B)).

%% ==============================================================================
%% reporting methods, mostly needed for dubugging

reportPointer(X) :-
    finalPointer(X, Type),
    write('finalPointer('), write(X), write(', '), write(Type), writeln(').').

reportSigned(X) :-
    finalSigned(X, Type),
    write('finalSigned('), write(X), write(', '), write(Type), writeln(').').

reportTypeName(Tnp, Name) :-
    finalTypeName(Tnp, Name),
    write('finalTypeName('), write(Tnp), write(', '), write(Name), writeln(').').

reportObject(X) :-
    finalObject(X, Type),
    write('finalObject('), write(X), write(', '), write(Type), writeln(').').

report :-
    %% forall(finalPointer(X, _), reportPointer(X)),
    %% forall(finalSigned(Y, _), reportSigned(Y)),
    %% forall(finalObject(Z, _), reportObject(Z)),
    forall(finalTypeName(T, Name), reportTypeName(T, Name)).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
