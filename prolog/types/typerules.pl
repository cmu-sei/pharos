%% Copyright 2017 Carnegie Mellon University.
%% --------------------------------------------------------------------------------------------

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
:- dynamic opIte/4.
:- dynamic opRead/2.
:- dynamic opRol/3.
:- dynamic opRor/3.
:- dynamic opSdiv/3.
:- dynamic opSextend/3.
:- dynamic opShl0/3.
:- dynamic opShl1/3.
:- dynamic opShr0/3.
:- dynamic opShr1/3.
:- dynamic opSmod/3.
:- dynamic opSmul/3.
:- dynamic opSmul/3.
:- dynamic opUdiv/3.
:- dynamic opUextend/3.
:- dynamic opUmod/3.
:- dynamic opUmul/3.
:- dynamic opZerop/2.
:- dynamic archBits/1.

%% API-related facts
:- dynamic apiCallName/2.
:- dynamic sameType/2.
:- dynamic functionCallArg/3.
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

:- table pointer/2.
:- table signed/2.
:- table typeName/2.

:- table finalPointer/2.
:- table finalSigned/2.

%%  This is now duplicated in our system (see util.pl)
iso_dif(X, Y) :-
   X \== Y,
   (X \= Y -> true).

%%  debugging code
:- dynamic debuggingEnabled/0.
:- dynamic debuggingStoreEnabled/0.

debug(X) :-
    debuggingEnabled -> write(X) ; true.

debugln(X) :-
    debuggingEnabled -> writeln(X) ; true.


%% ==============================================================================

%% The typename rules place type names on the treenodes based on how they are used in
%% API calls.

%%  These are the rules to assign default type names for signed/unsigned non-pointers
typeName(Tnp, TypeName) :-
    pointer(Tnp, isnot),
    signed(Tnp, is),
    (bitwidth(Tnp, 8)  -> TypeName = 'int8_t';
     bitwidth(Tnp, 16) -> TypeName = 'int16_t';
     bitwidth(Tnp, 32) -> TypeName = 'int32_t';
     bitwidth(Tnp, 64) -> TypeName = 'int64_t').

typeName(Tnp, TypeName) :-
    pointer(Tnp, isnot),
    signed(Tnp, isnot),
    (bitwidth(Tnp, 8)  -> TypeName = 'uint8_t';
     bitwidth(Tnp, 16) -> TypeName = 'uint16_t';
     bitwidth(Tnp, 32) -> TypeName = 'uint32_t';
     bitwidth(Tnp, 64) -> TypeName = 'uint64_t').

%% generate type names for parameters based on API informtion
typeName(ParamTnp, TypeName) :-
    apiCallName(Call, Api),
    functionCallArg(Call, Ordinal, ParamTnp),
    apiParamType(Api, Ordinal, TypeName, _).

%% The case where a variable is used as an argument to a call and the type of the argument is
%% known
typeName(VarTnp, TypeName) :-
    functionCallArg(_, _, VarTnp),
    knownTypename(VarTnp, TypeName).

% Handle variables that are passed by value (PBV). In this case we can infer that the variable
% is the same type as the parameter
typeName(VarTnp, TypeName) :-
    sameType(VarTnp, ParamTnp), % in PBV the variable and parameter are the same type
    iso_dif(VarTnp, ParamTnp),
    typeName(ParamTnp, TypeName).

%% Add the types that are passed by reference (PBR). In this relationship the value in the
%% parameter is the address of the stack variable, so we can deduce the type name of variable
%% from the parameter
typeName(VarTnp, TypeName) :-
    pointsTo(VarAddressTnp, VarTnp),
    sameType(VarAddressTnp, ParamTnp), % the address of the variable is the same type as the parameter
    iso_dif(VarAddressTnp, ParamTnp),

    %%  If this is the same type, then the type name is the same
    typeName(ParamTnp, ParamType),

    %%  The type must be a pointer for a valid PBR
    typePointerness(ParamType, pointer),
    typeRef(ParamType, TypeName).

%% Handle the situation where the value is known, but not the address type
typeName(AddrTnp, AddrTypename) :-
    pointsTo(AddrTnp, ValTnp),
    knownTypename(ValTnp, ValTypename),
    iso_dif(AddrTnp, ValTnp),
    typeRef(AddrTypename, ValTypename).

%% In this case there is no knownPointer fact, so reason about the pointer type via how it is
%% passed to an API
typeName(AddrTnp, AddrTypename) :-
    pointsTo(AddrTnp, ValTnp), % binds ValTnp
    iso_dif(AddrTnp, ValTnp),

    functionCallArg(_, Ord, ValTnp),
    apiParamType(_, Ord, ValTypename, _), % binds typename

    typeRef(AddrTypename, ValTypename).

%% ======================================================================
%% Api-related pointer analysis

%%  Obviously if pointer type is known, mark it as such, right?
pointer(Tnp, is) :- knownPointer(Tnp, is).
pointer(Tnp, isnot) :- knownPointer(Tnp, isnot).

%%  Obviously any tree node that points to something is a pointer, right?
pointer(Tnp, is) :- pointsTo(Tnp, _).

%%  Mark parameter a pointer based on type name
pointer(ParamTnp, is) :-
    typeName(ParamTnp, TypeName),
    typePointerness(TypeName, pointer).

pointer(ParamTnp, isnot) :-
    typeName(ParamTnp, TypeName),
    typePointerness(TypeName, notpointer).

%% OUT parameters must be pointers. Otherwise they would not retain their values
pointer(ArgTnp, is) :-
    apiCallName(Call, Api),
    functionCallArg(Call, Ordinal, ArgTnp),
    apiParamType(Api, Ordinal, _, out).

%% JSG is not sure that he really needs these two pointer rules. The PBR typename rule and the
%% typePointerness rule may be sufficient. Having these rules seems to dramatically increase
%% run time (almost double)

%% If the parameter type is a pointer, then we know something about what it points to
pointer(VarTnp, isnot) :-
    pointsTo(VarAddressTnp, VarTnp),
    typeName(ArgTnp, PointerType), % bind the type name
    sameType(VarAddressTnp, ArgTnp),

    %% Determine if pointee type is a pointer by checking refs
    typeRef(PointerType, PointeeType),
    typePointerness(PointeeType, notpointer).

pointer(VarTnp, is) :-
    pointsTo(VarAddressTnp, VarTnp),
    typeName(ArgTnp, PointerType),  % bind the type name
    sameType(VarAddressTnp, ArgTnp),

    %% Determine if pointee type is a pointer by checking refs
    typeRef(PointerType, PointeeType),
    typePointerness(PointeeType, pointer).

%% Handle tree node eqivalence
pointer(Tnp, is) :-
    sameType(Tnp, OtherTnp),
    iso_dif(Tnp, OtherTnp),
    pointer(OtherTnp, is).

pointer(Tnp, isnot) :-
    sameType(Tnp, OtherTnp),
    iso_dif(Tnp, OtherTnp),
    pointer(OtherTnp, isnot).

%% ==============================================================================
%% API-type related signedness analysis

%%  Obviously if signedness is known, mark it as such, right?
signed(Tnp, is) :- knownSigned(Tnp, is).
signed(Tnp, isnot) :- knownSigned(Tnp, isnot).

%% Determine if signed/unsigned based on type name
signed(Tnp, is) :-
    sameType(Tnp, OtherTnp),
    iso_dif(Tnp, OtherTnp),
    signed(OtherTnp, is).

signed(Tnp, isnot) :-
    sameType(Tnp, OtherTnp),
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
    sameType(VarAddressTnp, ArgTnp),
    typeName(ArgTnp, PointerType), % bind the type name

    %% Bind the pointer type to the pointee type and determine if the pointee type is signed
    typeRef(PointerType, PointeeType),
    typeRef(PointerType, PointeeType),
    typeSignedness(PointeeType, signed).

signed(VarTnp, isnot) :-
    pointsTo(VarAddressTnp, VarTnp),
    sameType(VarAddressTnp, ArgTnp),
    typeName(ArgTnp, PointerType), % bind the type name
    %% Bind the pointer type to the pointee type and detemine if the pointee type is signed
    typeRef(PointerType, PointeeType),
    typeRef(PointerType, PointeeType),
    typeSignedness(PointeeType, unsigned).

%% ==============================================================================
%%  Operation-related type rules

% Handle OP_SEXTEND pointer facts
% Nothing in a sign extend is a pointer.
pointer(Result, isnot) :-
    opSextend(Result, _, _).
pointer(Result, isnot) :-
    opSextend(_, Result, _).
pointer(Result, isnot) :-
    opSextend(_, _, Result).

% signed extension means the result is signed
signed(Result, is) :-
    opSextend(Result, _, _).

% ==============================================================================
% Handle OP_UEXTEND pointer facts
% Nothing in an unsigned sign extend is a pointer.
pointer(Result, isnot) :-
    opUextend(Result, _, _).
pointer(Result, isnot) :-
    opUextend(_, Result, _).
pointer(Result, isnot) :-
    opUextend(_, X, Result),
    % Pointers are sometimes legitimately extended by one bit.
    not(pointerUextendException(X)).

pointerUextendException(X) :-
        value(X, 0x21).
pointerUextendException(X) :-
        value(X, 0x41).

% unsigned extension means the result is not signed
signed(Result, isnot) :-
    opUextend(Result, _, _).

% ==============================================================================
% Handle OP_BV_AND
% The only case where something in an AND operation is a pointer is when it is AND-ed with the
% dword align value. Affirming this may be to strong for pointerness.
pointer(Result, is) :-
    opBvAnd(Result, List),
    containsPointerAlignVal(List).

% if the dword-align value is not present this cannot be a pointer
pointer(Result, isnot) :-
    opBvAnd(Result, List),
    \+ containsPointerAlignVal(List). % If the AND operation does not contain the alignment exception, it cannot be a pointer

% This is the hack to handle large numbers. We cannot put the integer version of the alignment value,
% 0xfffffff0 in the rules file because the number is too large for the xwam file format; thus it
% cannot be in this rules file. The hack is to convert the string version of the alignment value
% to a number and then compare that the the AlignVal
containsPointerAlignVal(List) :-
    member(Val, List),
    value(Val, AlignVal),
    string:atom_to_term('4294967280', X), X =:= AlignVal. % 4294967280 == 0xfffffff0

% ==============================================================================
% Handle OP_BV_OR
% The result of a logical OR or XOR cannot be a pointer
pointer(Result, isnot) :-
    opBvOr(Result, _); opBvXor(Result, _).

% ==============================================================================
% Handle EXTRACT and CONCAT, which has signedness and pointerness implications

% If an extract operation is OP_EXTRACT(R, A, B, C) where bits A ... B of C are extracted to R,
% then neither A nor B nor R can be a pointer. Technically, A and B should have value facts therenby
% adding evidence to their non-pointerness
pointer(Result, isnot) :-
    opExtract(Result, _, _, _).

pointer(A, isnot) :-
    opExtract(_, A, _, _),
    value(A, _).

pointer(B, isnot) :-
    opExtract(_, _, B, _),
    value(B, _).

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
pointer(X,isnot) :-
    opAsr(X, _, _); opShl0(X, _, _); opShl1(X, _, _); opShr0(X, _, _); opShr1(X, _, _); opRor(X, _, _); opRol(X, _, _).

pointer(X,isnot) :-
    opAsr(_, X, _); opShl0(_, X, _); opShl1(_, X, _); opShr0(_, X, _); opShr1(_, X, _); opRor(_, X, _); opRol(_, X, _).

pointer(X,isnot) :-
    opAsr(_, _, X); opShl0(_, _, X); opShl1(_, _, X); opShr0(_, _, X); opShr1(_, _, X); opRor(_, _, X); opRol(_, _, X).

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
    odd(P).

pointer(R, isnot) :-
    opAdd(R, X),
    countPointers(X, P),
    even(P).

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
    opSdiv(Result, _, _); opUdiv(Result, _, _).

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
    opRead(_, X).

%% ==============================================================================
%% Non-operation rules to reason about pointer/signed properties

%% This rule captures that no pointers are ever signed.
signed(X, isnot) :-
     pointer(X, is).

% and that nothing signed is ever a pointer
pointer(X, isnot) :-
    signed(X, is).

% Anything that is has a memaddr fact is a pointer
pointer(X, is) :-
    memaddr(X).

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
pointer(X, isnot) :-
    archBits(Bits),
    \+ bitwidth(X, Bits).

% One bit wide treenodes, aka booleans, are never signed and never pointers.
signed(X, isnot) :- bitwidth(X, 0x1).

pointer(X, isnot) :- bitwidth(X, 0x1).

% ==============================================================================
% Hanle OP_INVERT facts
% Anything that is inverted is not a pointer
pointer(X, isnot) :-
    opInvert(_, X).

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
%% reporting methods, mostly needed for dubugging

reportPointer(X) :-
    finalPointer(X, Type),
    write('finalPointer('), write(X), write(', '), write(Type), writeln(').').

reportSigned(X) :-
    finalSigned(X, Type),
    write('finalSigned('), write(X), write(', '), write(Type), writeln(').').

reportTypeName(Tnp, Name) :-
    typeName(Tnp, Name),
    write('typeName('), write(Tnp), write(', '), write(Name), writeln(').').

report :-
    forall(finalPointer(X, _), reportPointer(X)),
    forall(finalSigned(Y, _), reportSigned(Y)),
    forall(typeName(Tnp, Name), reportTypeName(Tnp, Name)).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
