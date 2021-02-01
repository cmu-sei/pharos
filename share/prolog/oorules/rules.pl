% Copyright 2017-2020 Carnegie Mellon University.

:- use_module(library(lists), [member/2, max_list/2]).

% --------------------------------------------------------------------------------------------
% The method is certain to be an object-oriented method.
:- table reasonMethod/1 as incremental.

:- table reasonMethod_A/1 as incremental.
:- table reasonMethod_B/1 as incremental.
:- table reasonMethod_C/1 as incremental.
:- table reasonMethod_D/1 as incremental.
:- table reasonMethod_E/1 as incremental.
:- table reasonMethod_F/1 as incremental.
:- table reasonMethod_G/1 as incremental.
:- table reasonMethod_H/1 as incremental.
:- table reasonMethod_I/1 as incremental.
:- table reasonMethod_J/1 as incremental.
:- table reasonMethod_K/1 as incremental.
:- table reasonMethod_L/1 as incremental.
:- table reasonMethod_M/1 as incremental.
:- table reasonMethod_N/1 as incremental.
:- table reasonMethod_O/1 as incremental.
:- table reasonMethod_P/1 as incremental.

reasonMethod(Method) :-
    %logwarnln('Recomputing reasonMethod...'),
    or([reasonMethod_A(Method),
        reasonMethod_B(Method),
        reasonMethod_C(Method),
        reasonMethod_D(Method),
        reasonMethod_E(Method),
        reasonMethod_F(Method),
        reasonMethod_G(Method),
        reasonMethod_H(Method),
        reasonMethod_I(Method),
        reasonMethod_J(Method),
        reasonMethod_K(Method),
        reasonMethod_L(Method),
        reasonMethod_M(Method),
        reasonMethod_N(Method)
      %        reasonMethod_O(Method),
      %        reasonMethod_P(Method)
      ]).

% Because we already know.
% PAPER: ??? This entire rule is new and still pretty experimental.
reasonMethod_A(Method) :-
    factMethod(Method).

% Because contructors are definitely methods.
reasonMethod_B(Method) :-
    factConstructor(Method).

% Because real destructors are definitely methods.
reasonMethod_C(Method) :-
    factRealDestructor(Method).

% Because deleting destructors are methods as far as Cory knows.
reasonMethod_D(Method) :-
    factDeletingDestructor(Method).

% Because a symbol told us so.
reasonMethod_E(Method) :-
    symbolClass(Method, _MangledName, _ClassName, _MethodName).

% Because a symbol property told us so.
reasonMethod_F(Method) :-
    symbolProperty(Method, _Property).

% Because proven entries in proven virtual function tables are methods.
% ED_PAPER_INTERESTING
reasonMethod_G(Method) :-
    factVFTableEntry(_VFTable, _Offset, Entry),
    dethunk(Entry, Method).

% Because we've already proven that the VFTable write was legitimate.
% Technically this is not sound, but it should have very low false positives.
reasonMethod_H(Method) :-
    factVFTableWrite(_Insn, Method, _Offset, _VFTable).

reasonMethod_I(Method) :-
    factVBTableWrite(_Insn, Method, _Offset, _VBTable).

% Because the calling convention proves it's on OO method.
% This is currently weak enough that we're guessing it instead.
% But it might be fixed now, so we should try it again...
%reasonMethod_I(Method) :-
%    The method is marked __thiscall, and nothing else?
%    callingConvention(Address, '__thiscall'),
%    not((callingConvention(Address, Convention), iso_dif(Convention, '__thiscall'))).

% Because it's called on a class that's known to be a class.
reasonMethod_J(Method) :-
    factClassCallsMethod(_Class, Method).

% Because the thisptr is known to be an object pointer.
reasonMethod_K(Method) :-
    thisPtrUsage(_Insn1, Func, ThisPtr, Method1),
    factMethod(Method1),
    thisPtrUsage(_Insn2, Func, ThisPtr, Method).

% Because the thisptr is known to be an object pointer.
reasonMethod_L(Method) :-
    factMethod(Caller),
    % Intentionally NOT a validFuncOffset!
    funcOffset(_Insn1, Caller, Method, 0),
    % Require that the Method also read/use the value.
    funcParameter(Method, ecx, _SymbolicValue),
    logtraceln('~@~Q.', [not(factMethod(Method)), reasonMethod_L(Method)]).

% Because direct data flow from new() makes the function a method.
reasonMethod_M(Method) :-
    thisPtrAllocation(_Insn1, Func, ThisPtr, _Type, _Size),
    thisPtrUsage(_Insn2, Func, ThisPtr, Method),
    % Require that the Method also read/use the value.
    funcParameter(Method, ecx, _SymbolicValue),
    logtraceln('~@~Q.', [not(factMethod(Method)), reasonMethod_M(Method)]).

% Because the thisptr is known to be an object pointer.
reasonMethod_N(Func) :-
    thisPtrUsage(_Insn1, Func, ThisPtr, Method),
    factMethod(Method),
    % This rule needs to permit invalid calling conventions for many correct results in Lite
    % oo, poly, and ooex7 test cases.
    (callingConvention(Func, '__thiscall'); callingConvention(Func, 'invalid')),
    funcParameter(Func, 'ecx', ThisPtr),
    logtraceln('~@~Q.', [not(factMethod(Method)), reasonMethod_N(Func)]).

% Because a known OO __thiscall method passes the this-pointer as parameter zero to a cdecl
% method, making the method in question a __cdecl OO method.  This happens sometimes when the
% method uses the varargs calling convention for example.
reasonMethod_O(Method) :-
    % There's a method that we know is an OO method.
    factMethod(Proven),
    % We already know that Proven is a this call method...
    callingConvention(Proven, '__thiscall'),
    funcParameter(Proven, ecx, ThisPtr),
    % The ThisPtr is passed to another method in a call
    callParameter(Insn, Proven, 0, ThisPtr),
    % That Method is us.
    callTarget(Insn, Proven, Target),
    dethunk(Target, Method),
    % And we're __cdecl.
    callingConvention(Method, '__cdecl'),
    logtraceln('~@~Q.', [not(factMethod(Method)), reasonMethod_O(Method)]).

% Because the same this-pointer is passed from a known __cdecl OO method to another __cdecl
% method (as the first parameter) in the same function.
reasonMethod_P(Method) :-
    % A ThisPtr is passed to a known method.
    callParameter(Insn1, Func, 0, ThisPtr),
    callTarget(Insn1, Func, Target1),
    dethunk(Target1, Proven),
    factMethod(Proven),
    % Then the same this-pointer is passed to another method.
    callParameter(Insn2, Func, 0, ThisPtr),
    callTarget(Insn2, Func, Target2),
    dethunk(Target2, Method),
    callingConvention(Method, '__cdecl'),
    logtraceln('~@~Q.', [not(factMethod(Method)), reasonMethod_P(Method)]).

%reasonMethod_Q(Method) :-
% Does this rule remove the need for dethunk in other reasonMethod.
%    thunk(Method, Called),
%    factMethod(Called).

reasonMethodSet(Set) :-
    setof(Method, reasonMethod(Method), Set).

% --------------------------------------------------------------------------------------------
% The method is certain to be a constructor.
:- table reasonConstructor/1 as incremental.

% Because it is already known to be a constructor.
% PAPER: Not relevant
reasonConstructor(Method) :-
    factConstructor(Method).

% Because it is known to be a constructor or destructor and we've eliminited the other
% possibilities.
% PAPER: Logic
reasonConstructor(Method) :-
    certainConstructorOrDestructor(Method),
    factNOTRealDestructor(Method),
    factNOTDeletingDestructor(Method),
    logtraceln('~@~Q.', [not(factConstructor(Method)), reasonConstructor_A(Method)]).

% Because there are virtual base table writes, and that only happens in constructors (as far as
% we know currently).  Strictly speaking, this rule should really be based on factVBTableWrite,
% and we should guess that as we do virtual function calls (with very high confidence and very
% early), but this code is still so experimental that seems too heavy weight for right now.
% PAPER: VFTableWrite-ConstructorDestructor  (Cory notes that this PAPER name is poor!)
% ED_PAPER_INTERESTING
reasonConstructor(Method) :-
    factVBTableWrite(_Insn, Method, _Offset, _VBTable),
    logtraceln('~@~Q.', [not(factConstructor(Method)), reasonConstructor_B(Method)]).

% Because a symbol says so!
reasonConstructor(Method) :-
    symbolProperty(Method, constructor),
    logtraceln('~@~Q.', [not(factConstructor(Method)), reasonConstructor_C(Method)]).

% Because if we're certain about a derived constructor relationship then obviously both methods
% are constructors.  Duplicative?
%reasonConstructor(Method) :-
%    factDerivedClass(_DerivedConstructor, Method, _Offset).
%reasonConstructor(Method) :-
%    factDerivedClass(Method, _BaseConstructor, _Offset).

% Because we already know the direction of the Base/Derived class relationship.  This rule is
% complicated.  The idea is that knowing which class is the Base and which is the Derived tells
% us whether the Method is a Constructor or Destructor.  Ahh...  That's probably where this
% rule belongs.

% Because there's a VFTable overwrite and a known inheritance relationship.
%reasonConstructor(Method) :-
%    % VFTable1 is overwritten by VFTable2.
%    possibleVFTableOverwrite(_Insn1, _Insn2, Method, Offset, VFTable1, VFTable2),
%    factVFTable(VFTable1),
%    factVFTable(VFTable2),
%    %
%    find(Method, Class1),
%    possibleVFTableWrite(_Insn3, OtherMethod, Offset, VFTable2),
%    find(OtherMethod, Class2),
%    factDerivedClass(DerivedClass, BaseClass, Offset).

reasonConstructorSet(Set) :-
    setof(Method, reasonConstructor(Method), Set).

% --------------------------------------------------------------------------------------------
% The method is certain to NOT be a constructor.
:- table reasonNOTConstructor/1 as incremental.

:- table reasonNOTConstructor_A/1 as incremental.
:- table reasonNOTConstructor_B/1 as incremental.
:- table reasonNOTConstructor_C/1 as incremental.
:- table reasonNOTConstructor_D/1 as incremental.
:- table reasonNOTConstructor_E/1 as incremental.
:- table reasonNOTConstructor_F/1 as incremental.
:- table reasonNOTConstructor_G/1 as incremental.
:- table reasonNOTConstructor_H/1 as incremental.

reasonNOTConstructor(Method) :-
    %logwarnln('Recomputing reasonNOTConstructor...'),
    or([reasonNOTConstructor_A(Method),
        reasonNOTConstructor_B(Method),
        reasonNOTConstructor_C(Method),
        reasonNOTConstructor_D(Method),
        reasonNOTConstructor_E(Method),
        reasonNOTConstructor_F(Method),
        reasonNOTConstructor_G(Method),
        reasonNOTConstructor_H(Method)
      ]).

% Because it is already known to NOT be a constructor.
% PAPER: NA
reasonNOTConstructor_A(Method) :-
    factNOTConstructor(Method).

% Because it is a real destructor.
% PAPER: Logic
reasonNOTConstructor_B(Method) :-
    factRealDestructor(Method),
    % Debugging
    logtraceln('~@~Q.', [not(factNOTConstructor(Method)), reasonNOTConstructor_B(Method)]).

% Because it is a deleting destructor.
% PAPER: Logic
reasonNOTConstructor_C(Method) :-
    factDeletingDestructor(Method),
    % Debugging
    logtraceln('~@~Q.', [not(factNOTConstructor(Method)), reasonNOTConstructor_C(Method)]).


% Because it is in a virtual function table and constructors can't be virtual.
% PAPER: VFTableEntry-NotConstructor
% ED_PAPER_INTERESTING
reasonNOTConstructor_D(Method) :-
    factVFTableEntry(_VFTable, _Offset, Entry),
    dethunk(Entry, Method),
    % Debugging
    logtraceln('~@~Q.', [not(factNOTConstructor(Method)), reasonNOTConstructor_D(Method)]).

% Because it is called after another method on an object instance pointer.
% PAPER: Order-NotConstructor
% ED_PAPER_INTERESTING
reasonNOTConstructor_E(Method) :-
    factMethod(Method),
    not(possibleConstructor(Method)),
    % Debugging
    logtraceln('~@~Q.', [not(factNOTConstructor(Method)), reasonNOTConstructor_E(Method)]).

% Because it is called by a non-constructor on the same object instance.
% PAPER: Call-NotConstructor
% ED_PAPER_INTERESTING
reasonNOTConstructor_F(Method) :-
    factNOTConstructor(OtherMethod),
    validFuncOffset(_Insn, OtherMethod, Method, _Offset),
    % Debugging
    logtraceln('~@~Q.', [not(factNOTConstructor(Method)), reasonNOTConstructor_F(Method, OtherMethod)]).


% Because you can't be a constructor on a class that's already known to have a VFTable if you
% you don't have a VFTable.  This rule was added largely to reach the correct conclusions on
% methods like operator=.
% ED_PAPER_INTERESTING
reasonNOTConstructor_G(Method) :-
    % There's another method that calls this method on the same object pointer.
    validFuncOffset(_, Caller, Method, 0),
    % The caller is known to be a constructor or destructor.
    (factConstructor(Caller); factRealDestructor(Caller)),
    % The caller is already known to have a VFTable write.
    factVFTableWrite(_Insn1, Caller, 0, _VFTable1),
    % But this method doesn't have the required write.
    not(possibleVFTableWrite(_Insn2, Method, 0, _VFTable2)),
    %
    % Debugging
    logtraceln('~@~Q.', [not(factNOTConstructor(Method)),
                         reasonNOTConstructor_G(Caller, Method)]).

% If we know which VFTable is associated with this class, and the method does not install it,
% it's NOT a constructor.
reasonNOTConstructor_H(Method) :-
    % There is a VFTable on a class
    findVFTable(VFTable, Class),
    % There is a method on the class
    findMethod(Method, Class),
    % The method does not install the vftable
    not(possibleVFTableWrite(_Insn, Method, _, VFTable)),

    logtraceln('~@~Q.', [not(factNOTConstructor(Method)),
                         reasonNOTConstructor_H(VFTable, Method)]).


reasonNOTConstructorSet(Set) :-
    setof(Method, reasonNOTConstructor(Method), Set).

% --------------------------------------------------------------------------------------------
% The method is certain to be a real destructor.
:- table reasonRealDestructor/1 as incremental.

% Because it is already known to be a real destructor.
% PAPER: NA
reasonRealDestructor(Method) :-
    factRealDestructor(Method).

% Because it is known to be a constructor or destructor and we've eliminited the other
% possibilities.
% PAPER: Logic
reasonRealDestructor(Method) :-
    certainConstructorOrDestructor(Method),
    factNOTConstructor(Method),
    factNOTDeletingDestructor(Method).

% Because a symbol says so!
reasonRealDestructor(Method) :-
    symbolProperty(Method, realDestructor).

% Because a symbol says so! (Bit of a hacky corner case).
% PAPER: ??? NEW!
% This should probably be a separate type of desstructor really.
% Disabled for now as a work-around for #61.
%% reasonRealDestructor(Method) :-
%%     symbolClass(Method, _MangledName, _ClassName, '`vbase destructor''').

reasonRealDestructorSet(Set) :-
    setof(Method, reasonRealDestructor(Method), Set).

% --------------------------------------------------------------------------------------------
% The method is certain to NOT be a real destructor.
:- table reasonNOTRealDestructor/1 as incremental.

:- table reasonNOTRealDestructor_A/1 as incremental.
:- table reasonNOTRealDestructor_B/1 as incremental.
:- table reasonNOTRealDestructor_C/1 as incremental.
:- table reasonNOTRealDestructor_D/1 as incremental.
:- table reasonNOTRealDestructor_E/1 as incremental.
:- table reasonNOTRealDestructor_F/1 as incremental.
:- table reasonNOTRealDestructor_G/1 as incremental.
:- table reasonNOTRealDestructor_H/1 as incremental.
:- table reasonNOTRealDestructor_I/2 as opaque.

reasonNOTRealDestructor(Method) :-
    %logwarnln('Recomputing reasonNOTRealDestructor...'),
    or([reasonNOTRealDestructor_A(Method),
        reasonNOTRealDestructor_B(Method),
        reasonNOTRealDestructor_C(Method),
        reasonNOTRealDestructor_D(Method),
        reasonNOTRealDestructor_E(Method),
        reasonNOTRealDestructor_F(Method),
        reasonNOTRealDestructor_G(Method),
        reasonNOTRealDestructor_H(Method),
        reasonNOTRealDestructor_I(Method)
      ]).

% Because it is already known to NOT be a real destructor.
% PAPER: NA
reasonNOTRealDestructor_A(Method) :-
    factNOTRealDestructor(Method).

% Because it is a constructor.
% PAPER: Logic
reasonNOTRealDestructor_B(Method) :-
    factConstructor(Method).

% Because it is a deleting destructor.
% PAPER: Logic
reasonNOTRealDestructor_C(Method) :-
    factDeletingDestructor(Method).

% Because it was called before another method on a this-pointer.
% PAPER: Order-NotDestructor
reasonNOTRealDestructor_D(Method) :-
    factMethod(Method),
    not(possibleDestructor(Method)).

% Because a class can have only one real destructor and we've already one for this class.
% PAPER: Sanity constraints for each class.  Currently: "Each class has one real destructor"
reasonNOTRealDestructor_E(Method) :-
    % There is a real destructor
    factRealDestructor(RealDestructor),
    % And it is on Class
    find(RealDestructor, Class),
    % Therefore every other method on the class is NOT a real destructor
    findMethod(Method, Class),
    % Exclude RealDestructor
    iso_dif(Method, RealDestructor).

% Because a method on a class cannot destruct itself (unless it's a deleting destructor).
reasonNOTRealDestructor_F(Method) :-
    validFuncOffset(_Insn, Caller, Method, 0),
    factMethod(Method),
    find(Method, Class),
    find(Caller, Class),
    iso_dif(Method, Caller),
    factNOTDeletingDestructor(Caller),
    % Debugging
    logtraceln('~Q.', reasonNOTRealDestructor_F(Caller, Method)).

% A correlary to reasonNOTConstructor_G (requiring VFTable writes if others have them).
% PAPER: ??? NEW!
reasonNOTRealDestructor_G(Method) :-
    % There's another method that calls this method on the same object pointer.
    validFuncOffset(_, Caller, Method, 0),
    % The caller is known to be a constructor or destructor.
    (factConstructor(Caller); factRealDestructor(Caller)),
    % The caller is already known to have a VFTable write.
    factVFTableWrite(_Insn1, Caller, 0, _VFTable1),
    % But this method doesn't have the required write.
    not(possibleVFTableWrite(_Insn2, Method, 0, _VFTable2)),
    % Debugging
    logtraceln('~@~Q.', [not(factNOTRealDestructor(Method)),
                         reasonNOTRealDestructor_G(Caller, Method)]).

% Real destructors cannot delete themselves.  This rule should help distinguish between real
% destructors and deleting destructors.
reasonNOTRealDestructor_H(Method) :-
    % We should already know that Method is an OO method in general.
    factMethod(Method),
    % The method calls delete on ThisPtr.
    insnCallsDelete(_Insn, Method, ThisPtr),
    % And ThisPtr was literally "this" for the method.
    funcParameter(Method, ecx, ThisPtr),
    % The presumption about ECX also necessitates this restriction?
    callingConvention(Method, '__thiscall').

% Destructors normally have one argument.  According to
% https://fossies.org/linux/cfe/lib/CodeGen/MicrosoftCXXABI.cpp, deleting destructors have a
% second argument.  Therefore, any method that has more than two parameters is not a
% destructor. Any method with more than one parameter is not a real destructor.
:- table reasonDestructorParams/2 as opaque.
reasonDestructorParams(Method, MaxParams) :-
    % There is a method
    findMethod(Method, _Class),
    % Get params
    setof(Param, Hash^funcParameter(Method, Param, Hash), Params),
    % ejs: It looks like arguments are not reliable
    %setof(Arg, Ins^Hash^callParameter(Ins, Method, Arg, Hash), Args),
    % Check length
    length(Params, ParamLen),
    %length(Args, ArgLen),

    ParamLen > MaxParams.
    %(ParamLen > MaxParams; ArgLen > MaxParams).

reasonNOTRealDestructor_I(Method) :-
    Params = 1,
    reasonDestructorParams(Method, Params),

    logtraceln('~@~Q.', [not(factNOTRealDestructor(Method)),
                         reasonNOTRealDestructor_I(Params, Method)]).

reasonNOTRealDestructorSet(Set) :-
    setof(Method, reasonNOTRealDestructor(Method), Set).

% --------------------------------------------------------------------------------------------
% The method is certain to be a deleting destructor.
:- table reasonDeletingDestructor/1 as incremental.

% Because it is already known to be a deleting destructor.
% PAPER: NA
reasonDeletingDestructor(Method) :-
    factDeletingDestructor(Method).

% Because it is known to be a constructor or destructor and we've eliminited the other
% possibilities.  It appears that deleting destructors participate in the vftable write rule.
% PAPER: Logic
reasonDeletingDestructor(Method) :-
    certainConstructorOrDestructor(Method),
    factNOTConstructor(Method),
    factNOTRealDestructor(Method).

% If a method deletes itself, it's almost certainly a deleting destructor.  There's a very
% _rare_ situation in which ordinary methods can delete(this), but it's not clear that it's
% worth worrying about.  We could block it here with certainConstructorOrDestructor(Method), or
% we could make this rule a guess. This rule should help distinguish between real destructors
% and deleting destructors.
reasonDeletingDestructor(Method) :-
    % If we're certain that we're a either a constructor or destructor.
    % certainConstructorOrDestructor(Method),
    factMethod(Method),
    % The method calls delete on ThisPtr.
    insnCallsDelete(_Insn, Method, ThisPtr),
    % And ThisPtr was literally "this" for the method.
    funcParameter(Method, ecx, ThisPtr),
    % The presumption about ECX also necessitates this restriction?
    callingConvention(Method, '__thiscall').

% Because a symbol says so!
reasonDeletingDestructor(Method) :-
    symbolProperty(Method, deletingDestructor).

% --------------------------------------------------------------------------------------------
% The method is certain to NOT be a deleting destructor.
:- table reasonNOTDeletingDestructor/1 as incremental.

:- table reasonNOTDeletingDestructor_A/1 as incremental.
:- table reasonNOTDeletingDestructor_B/1 as incremental.
:- table reasonNOTDeletingDestructor_C/1 as incremental.
:- table reasonNOTDeletingDestructor_D/1 as incremental.
:- table reasonNOTDeletingDestructor_E/1 as incremental.
:- table reasonNOTDeletingDestructor_F/1 as incremental.
:- table reasonNOTDeletingDestructor_G/1 as incremental.
:- table reasonNOTDeletingDestructor_H/1 as opaque.

reasonNOTDeletingDestructor(Method) :-
    %logwarnln('Recomputing reasonNOTDeletingDestructor...'),
    or([reasonNOTDeletingDestructor_A(Method),
        reasonNOTDeletingDestructor_B(Method),
        reasonNOTDeletingDestructor_C(Method),
        reasonNOTDeletingDestructor_D(Method),
        reasonNOTDeletingDestructor_E(Method),
        reasonNOTDeletingDestructor_F(Method),
        reasonNOTDeletingDestructor_G(Method),
        reasonNOTDeletingDestructor_H(Method)
      ]).

% Because it is already known to NOT be a deleting destructor.
% PAPER: NA
reasonNOTDeletingDestructor_A(Method) :-
    factNOTDeletingDestructor(Method).

% Because it is a constructor.
% PAPER: Logic
reasonNOTDeletingDestructor_B(Method) :-
    factConstructor(Method).

% Because it is a real destructor.
% PAPER: Logic
reasonNOTDeletingDestructor_C(Method) :-
    factRealDestructor(Method).

% Because it was called before another method on a this-pointer.
% PAPER: Order-NotDestructor
reasonNOTDeletingDestructor_D(Method) :-
    factMethod(Method),
    not(possibleDestructor(Method)).

% Because a method on a class cannot _deallocate_ itself.
% PAPER: ??? NEW!
reasonNOTDeletingDestructor_E(Method) :-
    % This rule can be pretty broad, because I'm not aware of any circumstances where passing
    % your own this pointer to a deleting destructor is valid.
    factMethod(Method),
    factMethod(Caller),
    iso_dif(Method, Caller),
    validFuncOffset(_Insn, Caller, Method, 0),
    % Debugging
    logtraceln('~Q.', reasonNOTDeletingDestructor_E(Method, Caller)).

% Because we identified at least one call to delete, and this method does not call delete.
% Unfortunately, there could be multiple delete implementations, in which case we could falsely
% conclude that a destructor is not a destructor.  We likely have several other rules that will
% perform badly in this case, so we are leaving it for now.  But perhaps it should be relegated
% to a guessing rule.
reasonNOTDeletingDestructor_F(Method) :-
    factMethod(Method),
    % Someone calls delete
    insnCallsDelete(_Insn, _Method, _Ptr),
    % We use thiscall
    callingConvention(Method, '__thiscall'),
    funcParameter(Method, ecx, ThisPtr),
    % But we don't call delete on ourself
    not(insnCallsDelete(_Insn2, Method, ThisPtr)).

% Deleting destructors are always virtual, so if we can't possibly be a virtual, then we can't
% possibly be a deleting destructor.  The primary benefit of this rule compared to some others
% is that is does not rely on the correct detection of delete() which is sometimes a problem.
reasonNOTDeletingDestructor_G(Method) :-
    not(possiblyVirtual(Method)).

% Destructors normally have one argument.  According to
% https://fossies.org/linux/cfe/lib/CodeGen/MicrosoftCXXABI.cpp, deleting destructors have a
% second argument.  Therefore, any method that has more than two parameters is not a
% destructor. Any method with more than one parameter is not a real destructor.
reasonNOTDeletingDestructor_H(Method) :-
    Params = 2,
    reasonDestructorParams(Method, Params),

    logtraceln('~@~Q.', [not(factNOTDeletingDestructor(Method)),
                         reasonNOTDeletingDestructor_H(Params, Method)]).

reasonNOTDeletingDestructorSet(Set) :-
    setof(Method, reasonNOTDeletingDestructor(Method), Set).

% --------------------------------------------------------------------------------------------
% Method is certain to be either a constructor or a destructor.  The reasoning here is that any
% method that is writing VFTable values into an object must be either a constructor or
% destructor, since as mentioned in the reasonVFTableWrite rule, no user code has access to the
% virtual function table address.  There was some confusion about inlined constructors for
% other objects (e.g. local stack objects or heap allocated objects), but they won't be writing
% into the current method's object, so there wouldn't have been a possibleVFTableWrite() fact
% in the first place.  Jeff Gennari and Cory Cohen are both fairly confident of this rule, but
% it's hard to prove the negative (that the compiler doesn't use the VFTable under any other
% condition).  Cory subsequently established (via the badalloc deleting destructor in
% Lite/ooex0) that deleting destructors can install the VFTable for the current object
% (possibly due to inlining?) so this conclusion does NOT say which type of destructor it might
% be.  This rule is here and named in the old style mostly so that this gigantic comment can be
% here rather than in the middle of a bunch of other rules.
% PAPER: VFTableWrite-ConstructorDestructor
% ED_PAPER_INTERESTING
certainConstructorOrDestructor(Method) :-
    factVFTableWrite(_Insn, Method, _Offset, _VFTable).

certainConstructorOrDestructor(Method) :-
    factVBTableWrite(_Insn, Method, _Offset, _VBTable).

certainConstructorOrDestructorSet(Set) :-
    setof(Method, certainConstructorOrDestructor(Method), Set).

% factVFTableOverwrite is directional, which requires us to know whether the methods involved
% are constructors or destructors.  But sometimes we know that there is an overwrite, but not
% which direction.  The following facts attempt to express this so that it can be used to delay
% decisions that rely on whether there is an overwrite.
certainConstructorOrDestructorButUndecided(Method) :-
    % We know it's one or the other
    certainConstructorOrDestructor(Method),
    % But haven't decided yet
    not((factConstructor(Method); factNOTConstructor(Method))).

mayHavePendingOverwrites(Method) :-
    certainConstructorOrDestructorButUndecided(Method).

% ============================================================================================
% Rules for virtual function tables, virtual function calls, etc.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% The address VFTable is certain to be a virtual function table.
% This rule does not say which class the VFTable is associated with.
:- table reasonVFTable/1 as incremental.

% Because it is already known to be a VFTable.
% PAPER: NA
reasonVFTable(VFTable) :-
    factVFTable(VFTable).

% Because the RTTI information says so.
% PAPER: ??? NEW?
reasonVFTable(VFTable) :-
    rTTIEnabled,
    rTTIValid,
    rTTITDA2VFTable(_TDA, VFTable),
    logtraceln('~Q.', reasonVFTable1(VFTable)).

% Because the VFTable was used in a virtual function call.
% PAPER: VirtualCall-VFTable
reasonVFTable(VFTable) :-
    factVirtualFunctionCall(_Insn, _Method, _ObjectOffset, VFTable, _VFTableOffset).

% Implement: Derived/Base class relationships validate the virtual function tables at the same
% offsets in oteher class?  Is it possible to conclude the derived class relationship without
% the being certain of the VFTables (if there are VFTables)?

% --------------------------------------------------------------------------------------------
% The Insn in Method writing to Offset in the current object is known to be writing a certain
% virtual function table pointer.
:- table reasonVFTableWrite/4 as incremental.

% Because it is already known to be a valid VFTable write.
% PAPER: NA
reasonVFTableWrite(Insn, Method, Offset, VFTable) :-
    factVFTableWrite(Insn, Method, Offset, VFTable).

% Because if we know that the address is a VFTable, and it's apparently being written into an
% object, there's almost no chance that it's not a legitimate VFTable write.  The source code
% doesn't legitimately have access to the VFTables addresses, so no instruction other than a
% constructor/destructor vftable write should mention the address.
% PAPER: VFTable-VFTableWrite
reasonVFTableWrite(Insn, Method, Offset, VFTable) :-
    % The VFTtable itself must already be certain.
    factVFTable(VFTable),
    % And there's a VFTable write that references that VFTable.
    possibleVFTableWrite(Insn, Method, Offset, VFTable).

% It should be possible to use the base table entry at offset zero (the one that the virtual
% base class uses to find it's virtual funtion table) to prove the existence of the virtual
% function table write.  I haven't actually implemented this rule yet, because it's a little
% unclear under exactly what circumstances it would be beneficial.  Perhaps it would be better
% implemented as a validation rule.

% --------------------------------------------------------------------------------------------
% Rules for overwritten VFTables when more than one VFTable is written to the same object
% offset.  Unlike possibleVFTableOverwrite, which is based on the literal overwriting of
% VFTable pointers based on instruction ordering, this rule is conceptual ordered from the
% perspective of the constructor (which is reversed in the destructors).

:- table reasonVFTableOverwrite/4 as incremental.

% Because VFTable1 is overwritten by VFTable2, and the method is a constructor, so we're
% overwriting tables in the "normal" direction, meaning that the order of the instructions
% matches the semantic meaning of the overwrite.
reasonVFTableOverwrite(Method, VFTable1, VFTable2, Offset) :-
    possibleVFTableOverwrite(_Insn1, _Insn2, Method, Offset, VFTable1, VFTable2),
    factVFTable(VFTable1),
    factVFTable(VFTable2),
    factConstructor(Method),

    % Debugging
    logtraceln('~@~Q.', [not(factVFTableOverwrite(Method, VFTable1, VFTable2, Offset)),
                         reasonVFTableOverwrite_A(Method, VFTable1, VFTable2, Offset)]).

% Because VFTable1 is overwritten by VFTable2, and the method is a NOT a constructor, so we're
% overwriting tables in the "opposite" direction, meaning that the order of the instructions is
% opposite of the semantics meaning of the overwrite.  Note that the order of VFTable2 and
% VFTable1 has been reversed from the previous rule.
reasonVFTableOverwrite(Method, VFTable2, VFTable1, Offset) :-
    possibleVFTableOverwrite(_Insn1, _Insn2, Method, Offset, VFTable1, VFTable2),
    factVFTable(VFTable1),
    factVFTable(VFTable2),

    % You'd think we could say (factDeletingDestructor or factRealDestructor) but it turns out
    % that excludes cases where we're still unclear on which type of destructor it is.  I've
    % included certainConstructorOrDestructor(Method) but that rule is currently just test for
    % a VFTable write, so it's a bit duplicative here.  In the end, factNOTConstructor() may be
    % sufficient even if it's a little confusing.
    certainConstructorOrDestructor(Method),
    factNOTConstructor(Method),

    % Debugging
    logtraceln('~@~Q.', [not(factVFTableOverwrite(Method, VFTable2, VFTable1, Offset)),
                         reasonVFTableOverwrite_B(Method, VFTable2, VFTable1, Offset)]).


% --------------------------------------------------------------------------------------------

% The following two predicates both relate vftables to classes.

% reasonVFTableBelongsToClass(VFTable, Offset, Class) means that a method on Class installs a
% pointer at Offset _in its own object_ (NOT an embedded object) to VFTable.  Roughly, this
% means a pimary VFTable at offset 0 for the class, and any extra vftables that are used in the
% case of multiple inheritance.  The "Primary" VFTable is simply defined to be the one at
% offset 0.

:- table reasonVFTableBelongsToClass/5 as incremental.

% Free, _, Bound
reasonVFTableBelongsToClass(VFTable, Offset, Class, Rule, VFTableWrite) :-
    var(VFTable),
    nonvar(Class),
    !,
    find(Method, Class),
    factVFTableWrite(Insn, Method, Offset, VFTable),
    VFTableWrite=factVFTableWrite(Insn, Method, Offset, VFTable),

    % ejs 10/9/20: We found the destructor rule was applying to a method which we had not
    % decided was a constructor or destructor.  The problem is that factVFTableOverwrite facts
    % are not produced when that happens.  So the following clause forces us to wait for that
    % decision to be made.
    not(mayHavePendingOverwrites(Method)),

    % ejs 9/13/20: If a factVFTableOverwrite exists, then the VFTable doesn't belong to this
    % class.  This is different than the first case below, which says that the absence of
    % factVFTableOverwrite indicates that the installed vftable belongs to the class (but only
    % for constructors).  This clause is especially important for base classes that may not be
    % directly instantiated, because the "no other class trying to install this vftable" will
    % be trivially true, and without this clause, the vftable will simply belong to an
    % arbitrary method that installs it.
    not(factVFTableOverwrite(Method, VFTable, _OverwriteVFTable, Offset)),

    % Constructors may inline embedded constructors.  If non-offset
    % zero, we must make sure that there is an inherited class at this
    % offset.
    (Offset = 0 -> true; factDerivedClass(Class, _BaseClass, Offset)),

    % VFTables from a base class can be reused in a derived class.  If this happens, we know
    % that the VFTable does not belong to the derived class.
    (Offset = 0 -> true; forall(factVFTableWrite(_Insn2, _OtherMethod, OtherOffset, VFTable), OtherOffset > 0)),

    % Additional checks.  One of the following must be true...
    (
        % If Method is a constructor, we can use factVFTableOverwrite to make sure that we are
        % actually installing this vftable for this class.  This only applies to constructors
        % because we have found destructors get optimized more. See the more detailed
        % commentary in reasonMergeClasses_D regarding the bad_cast case in Lite/oo.

        % ejs 8/27/20: We saw cases where we would falsely use this rule because
        % factVFTableOverwrite had not yet been proved, which requires factConstructor,
        % factVFTable, and other rules.  So we use possibleVFTableOverwrite here instead to be
        % more conservative.
        % ejs 9/13/20: We now use factConstructor anyway, so perhaps we could relax this.
        % ejs 10/9/20: Since we call not(mayHavePendingOverwrites(Method)) above, should we change this to factVFTableOverwrite?
        (not(possibleVFTableOverwrite(_Insn3, _Insn4, Method, Offset, VFTable, _OtherVFTable)),
         % ejs 9/13/20: In mysqld.exe, we were using this rule to incorrectly associate
         % vftables with destructors before any determination about constructors or destructors
         % was made.  So we must actually wait for a definitive constructor conclusion rather
         % than the absence of contradictory evidence.
         factConstructor(Method),
         Rule=constructor);

        % Alternatively, if we are a destructor, make sure there is no other class trying to
        % install this vftable
        % XXX: Should Offset = Offset2?
        (forall(factVFTableWrite(_Insn5, Method2, Offset2, VFTable),
               % It is ok to ignore overwritten vftables
               (factVFTableOverwrite(Method2, VFTable, _OtherVFTable, Offset2);
                % Otherwise it better be the same class
                find(Method2, Class))),
         Rule=destructor);

        % If Class has no base, then the VFTable installation we see must be the right one.
        (factClassHasNoBase(Class),
         Rule=hasnobase)

    ).

% Bound, _, Bound: OK
% Bound, _, Free: OK
% Free, _, Bound: Not OK
% Free, _, Free: OK
reasonVFTableBelongsToClass(VFTable, Offset, Class, Rule, VFTableWrite) :-
    factVFTableWrite(Insn, Method, Offset, VFTable),
    VFTableWrite=factVFTableWrite(Insn, Method, Offset, VFTable),
    find(Method, Class),


    % ejs 10/9/20: We found the destructor rule was applying to a method which we had not
    % decided was a constructor or destructor.  The problem is that factVFTableOverwrite facts
    % are not produced when that happens.  So the following clause forces us to wait for that
    % decision to be made.
    not(mayHavePendingOverwrites(Method)),

    % ejs 9/13/20: If a factVFTableOverwrite exists, then the VFTable doesn't belong to this
    % class.  This is different than the first case below, which says that the absence of
    % factVFTableOverwrite indicates that the installed vftable belongs to the class (but only
    % for constructors).  This clause is especially important for base classes that may not be
    % directly instantiated, because the "no other class trying to install this vftable" will
    % be trivially true, and without this clause, the vftable will simply belong to an
    % arbitrary method that installs it.
    not(factVFTableOverwrite(Method, VFTable, _OverwriteVFTable, Offset)),

    % Constructors may inline embedded constructors.  If non-offset
    % zero, we must make sure that there is an inherited class at this
    % offset.
    (Offset = 0 -> true; factDerivedClass(Class, _BaseClass, Offset)),

    % VFTables from a base class can be reused in a derived class.  If this happens, we know
    % that the VFTable does not belong to the derived class.
    (Offset = 0 -> true; forall(factVFTableWrite(_Insn2, _OtherMethod, OtherOffset, VFTable), OtherOffset > 0)),

    % Additional checks.  One of the following must be true...
    (
        % If Method is a constructor, we can use factVFTableOverwrite to make sure that we are
        % actually installing this vftable for this class.  This only applies to constructors
        % because we have found destructors get optimized more. See the more detailed
        % commentary in reasonMergeClasses_D regarding the bad_cast case in Lite/oo.

        % ejs 8/27/20: We saw cases where we would falsely use this rule because
        % factVFTableOverwrite had not yet been proved, which requires factConstructor,
        % factVFTable, and other rules.  So we use possibleVFTableOverwrite here instead to be
        % more conservative.
        % ejs 9/13/20: We now use factConstructor anyway, so perhaps we could relax this.
        % ejs 10/9/20: Since we call not(mayHavePendingOverwrites(Method)) above, should we change this to factVFTableOverwrite?
        (not(possibleVFTableOverwrite(_Insn3, _Insn4, Method, Offset, VFTable, _OtherVFTable)),
         % ejs 9/13/20: In mysqld.exe, we were using this rule to incorrectly associate
         % vftables with destructors before any determination about constructors or destructors
         % was made.  So we must actually wait for a definitive constructor conclusion rather
         % than the absence of contradictory evidence.
         factConstructor(Method),
         Rule=constructor);

        % Alternatively, if we are a destructor, make sure there is no other class trying to
        % install this vftable
        % XXX: Should Offset = Offset2?
        (forall(factVFTableWrite(_Insn5, Method2, Offset2, VFTable),
               % It is ok to ignore overwritten vftables
               (factVFTableOverwrite(Method2, VFTable, _OtherVFTable, Offset2);
                % Otherwise it better be the same class
                find(Method2, Class))),
         Rule=destructor);

        % If Class has no base, then the VFTable installation we see must be the right one.
        (factClassHasNoBase(Class),
         Rule=hasnobase)

    ).

% --------------------------------------------------------------------------------------------
% The offset in the VFTable is a valid VFTable entry.
:- table reasonVFTableEntry/3 as incremental.

% Because it is already known to be a valid VFTable entry.
% PAPER: NA
reasonVFTableEntry(VFTable, Offset, Entry) :-
    factVFTableEntry(VFTable, Offset, Entry).

% Because the first entry in the VFTable is always valid (they are no zero size VFTables).
% PAPER: VFTable-VFTableEntry
reasonVFTableEntry(VFTable, 0, Entry) :-
    factVFTable(VFTable),
    possibleVFTableEntry(VFTable, 0, Entry).

% Because there is a larger valid VFTable entry in the same VFTable.
% PAPER: Larger-VFTableEntry
reasonVFTableEntry(VFTable, Offset, Entry) :-
    (factVFTableEntry(VFTable, ExistingOffset, _OtherEntry);
     (factVFTableSizeGTE(VFTable, ExistingSize), ExistingOffset is ExistingSize - 4)),
    possibleVFTableEntry(VFTable, Offset, Entry),
    Offset =< ExistingOffset.

% Because the entry was used in a virtual function call.
% PAPER: VirtualCall-VFTableEntry
reasonVFTableEntry(VFTable, Offset, Entry) :-
    factVirtualFunctionCall(_Insn, _Method, _ObjectOffset, VFTable, Offset),
    possibleVFTableEntry(VFTable, Offset, Entry).

% Implement: Because our parent class already has a larger VFTable?

% Implement: The second real DTOR in a table ends the table?

% --------------------------------------------------------------------------------------------
% It is certain that the possible VFTableEntry is NOT in fact a valid entry in that table.
:- table reasonNOTVFTableEntry/3 as incremental.

:- table reasonNOTVFTableEntry_A/3 as incremental.
:- table reasonNOTVFTableEntry_B/3 as incremental.
:- table reasonNOTVFTableEntry_C/3 as incremental.
:- table reasonNOTVFTableEntry_D/3 as incremental.
:- table reasonNOTVFTableEntry_E/3 as incremental.

reasonNOTVFTableEntry(VFTable, Offset, Entry) :-
    %logwarnln('Recomputing reasonNOTVFTableEntry...'),
    or([reasonNOTVFTableEntry_A(VFTable, Offset, Entry),
        reasonNOTVFTableEntry_B(VFTable, Offset, Entry),
        reasonNOTVFTableEntry_C(VFTable, Offset, Entry),
        reasonNOTVFTableEntry_D(VFTable, Offset, Entry),
        reasonNOTVFTableEntry_E(VFTable, Offset, Entry)
      ]).

% Because it has already been proved not to be.
% PAPER: NA
reasonNOTVFTableEntry_A(VFTable, Offset, Entry) :-
    factNOTVFTableEntry(VFTable, Offset, Entry).

% Because the same address is known to already be the start of a different table, and
% virtual function tables can not overlap.
% PAPER: Overlap-NotVFTableEntry
reasonNOTVFTableEntry_B(VFTableAddress, Offset, Entry) :-
    factVFTable(VFTableAddress),
    possibleVFTableEntry(VFTableAddress, Offset, Entry),
    Offset \= 0,
    ComputedAddress is VFTableAddress + Offset,
    factVFTable(ComputedAddress).

% Because the first invalid entry in a table invalidates all subsequent possible entries
% (virtual function tables are contiguous).
% PAPER: Larger-NotVFTableEntry
reasonNOTVFTableEntry_C(VFTable, Offset, Entry) :-
    factVFTable(VFTable),
    possibleVFTableEntry(VFTable, Offset, Entry),
    Offset \= 0,
    ComputedOffset is Offset - 4,
    possibleVFTableEntry(VFTable, ComputedOffset, OtherEntry),
    factNOTVFTableEntry(VFTable, ComputedOffset, OtherEntry).

% Because the address is already used for the RTTI data structure of a confirmed VFTable.
% PAPER: rTTI-NotVFTableEntry
reasonNOTVFTableEntry_D(VFTable, Offset, Entry) :-
    factVFTable(VFTable),
    possibleVFTableEntry(VFTable, Offset, Entry),
    ComputedAddress is VFTable + Offset,
    rTTICompleteObjectLocator(ComputedAddress, _Address, _TDAddress, _CHDAddress, _O1, _O2).

% Because the method it points to is certain to be a constructor.  This rule is suspicious.
% Are we really sure that the method is a constructor?  Why does it appear to be in the virtual
% function table?  I suppose this rule is required to maintain consistency in the solution.
% PAPER: TBD: Add to the consistency rules
reasonNOTVFTableEntry_E(VFTable, Offset, Entry) :-
    possibleVFTableEntry(VFTable, Offset, Entry),
    dethunk(Entry, Method),
    factConstructor(Method),
    % Debugging
    logtraceln('~Q.', reasonNOTVFTableEntry_E(VFTable, Offset, Entry)).

% Implement: Because our derived VFTable already has a smaller table?

reasonNOTVFTableEntrySet(VFTable, Set) :-
    factVFTable(VFTable),
    setof(Offset, Entry^reasonNOTVFTableEntry(VFTable, Offset, Entry), Set).

% --------------------------------------------------------------------------------------------
:- table reasonVFTableSizeGTE/2 as incremental.

% The size includes the length of the last pointer, and pointers are incorrectly assumed to by
% 4 byte (32-bit) function pointers.  So a table with one entry will have size 4, with two
% entries size 8, and so on.

reasonVFTableSizeGTE(VFTable, Size) :-
    factVFTableSizeGTE(VFTable, Size).

% PAPER: VSize-1
reasonVFTableSizeGTE(VFTable, Size) :-
    % Ed says: By prefixing E^ we tell setof NOT to case on E.
    % If we leave E as _, it will case on different values of E!
    setof(S, E^factVFTableEntry(VFTable, S, E), Set),
    max_list(Set, LastEntry),
    Size is LastEntry + 4,
    % Debugging
    logtraceln('~@~Q.', [not((factVFTableSizeGTE(VFTable, ExistingSize),
                              ExistingSize >= Size)),
                         reasonVFTableSizeGTE_A(VFTable, Size)]).

% VFTable size for inherited vftables
reasonVFTableSizeGTE(VFTable, Size) :-
    % In this rule we're only considering base classes that are NOT at offset zero.
    factDerivedClass(DerivedClass, BaseClass, Offset),
    % Pair the derived table at that offset with the base table at offset zero, and constrain
    % the base table to >= the derived table.
    findVFTable(DerivedVFTable, Offset, DerivedClass),
    findVFTable(BaseVFTable, 0, BaseClass),

    % This rule only holds for the primary inheritance relationship, and does not work for base
    % cases where there's multiple inheritance.
    ((Offset = 0, factVFTableSizeGTE(BaseVFTable, Size), VFTable = DerivedVFTable);

     % For multiple inheritance, we think the additional vftables must be the same size as the
     % base classes that they inherit from.
     (iso_dif(Offset, 0),
      % This clause will enforce the GTE constraint in both directions (between Derived and
      % Base) once it has backtracked through all solutions.
      (factVFTableSizeGTE(DerivedVFTable, Size), VFTable=BaseVFTable;
       factVFTableSizeGTE(BaseVFTable, Size), VFTable=DerivedVFTable))),

    % Debugging
    logtraceln('~@~Q.', [not((factVFTableSizeGTE(VFTable, ExistingSize),
                              ExistingSize >= Size)),
                         reasonVFTableSizeGTE_B(DerivedClass, DerivedVFTable, Offset, BaseClass, BaseVFTable, VFTable, Size)]).

% --------------------------------------------------------------------------------------------
:- table reasonVFTableSizeLTE/2 as incremental.

% The size includes the length of the last pointer, and pointers are incorrectly assumed to by
% 4 byte (32-bit) function pointers.  So a table with one entry will have size 4, with two
% entries size 8, and so on.

reasonVFTableSizeLTE(VFTable, Size) :-
    factVFTableSizeLTE(VFTable, Size).

% PAPER: VSize-0
reasonVFTableSizeLTE(VFTable, Size) :-
    % Ed says: By prefixing M^ we tell setof NOT to case on M.
    % If we leave M as _, it will case on different values of M!
    setof(S, M^factNOTVFTableEntry(VFTable, S, M), Set),
    max_list(Set, LastEntry),
    Size is LastEntry + 4,
    % Debugging
    logtraceln('~@~Q.', [not((factVFTableSizeLTE(VFTable, ExistingSize),
                              ExistingSize >= Size)),
                         reasonVFTableSizeLTE_A(VFTable, Size)]).


% VFTable size for inherited vftables
reasonVFTableSizeLTE(VFTable, Size) :-
    % In this rule we're only considering base classes that are NOT at offset zero.
    factDerivedClass(DerivedClass, BaseClass, Offset),
    % Pair the derived table at that offset with the base table at offset zero, and constrain
    % the base table to >= the derived table.
    findVFTable(DerivedVFTable, Offset, DerivedClass),
    findVFTable(BaseVFTable, 0, BaseClass),

    % This rule only holds for the primary inheritance relationship, and does not work for base
    % cases where there's multiple inheritance.
    ((Offset = 0, factVFTableSizeLTE(DerivedVFTable, Size), VFTable = BaseVFTable);

     % For multiple inheritance, we think the additional vftables must be the same size as the
     % base classes that they inherit from.
     (iso_dif(Offset, 0),
      % This clause will enforce the GTE constraint in both directions (between Derived and
      % Base) once it has backtracked through all solutions.
      (factVFTableSizeLTE(DerivedVFTable, Size), VFTable=BaseVFTable;
       factVFTableSizeLTE(BaseVFTable, Size), VFTable=DerivedVFTable))),

    % Debugging
    logtraceln('~@~Q.', [not((factVFTableSizeLTE(VFTable, ExistingSize),
                              ExistingSize >= Size)),
                         reasonVFTableSizeLTE_B(DerivedClass, DerivedVFTable, Offset, BaseClass, BaseVFTable, VFTable, Size)]).

% --------------------------------------------------------------------------------------------
:- table reasonVirtualFunctionCall/5 as incremental.

reasonVirtualFunctionCall(Insn, Method, ObjectOffset, VFTable, VFTableOffset) :-
    factVirtualFunctionCall(Insn, Method, ObjectOffset, VFTable, VFTableOffset).

% Because we're able to reolve the call.
% PAPER: XXX
% The call proves the entry in this rule.  It relies on the VFTableWrite which can be proven
% from the VFTable, which can come from RTTI for example.
reasonVirtualFunctionCall(Insn, Method, ObjectOffset, VFTable, VFTableOffset) :-
    % There's a possible virtual function call.
    possibleVirtualFunctionCall(Insn, Function, ThisPtr, ObjectOffset, VFTableOffset),
    % There's a this-pointer usage that calls a method.
    thisPtrUsage(_CallInsn, Function, ThisPtr, Method),
    % We know what VFTable was written into that object offset.
    factVFTableWrite(_WriteInsn, Method, ObjectOffset, VFTable),
    % Debugging
    logtraceln('~Q.', reasonVirtualFunctionCall(Insn, Method, ObjectOffset,
                                                VFTable, VFTableOffset)).

% ============================================================================================
% Rules for virtual BASE tables.
% ============================================================================================

% --------------------------------------------------------------------------------------------
:- table reasonVBTable/1 as incremental.

% Because it is already known to be a VFTable.
% PAPER: NA
reasonVBTable(VBTable) :-
    factVBTable(VBTable).

% Because an entry was validated first, for example from RTTI.
% PAPER: ??? NEW!
reasonVBTable(VBTable) :-
    factVBTableEntry(VBTable, Offset, _Value),
    Offset >= 4,
    logtraceln('~Q.', reasonVBTable_A(VBTable)).

% --------------------------------------------------------------------------------------------
:- table reasonVBTableWrite/4 as incremental.

% Because it is already known to be a valid VBTable write.
% PAPER: NA
reasonVBTableWrite(Insn, Method, Offset, VBTable) :-
    factVBTableWrite(Insn, Method, Offset, VBTable).

% PAPER: ??? NEW!
reasonVBTableWrite(Insn, Method, Offset, VBTable) :-
    % The VBTtable itself must already be certain.
    factVBTable(VBTable),
    % And there's a VBTable write that references that VBTable.
    possibleVBTableWrite(Insn, Method, Offset, VBTable),
    % Debugging
    logtraceln('~Q.', reasonVBTableWrite_A(Insn, Method, Offset, VBTable)).

% --------------------------------------------------------------------------------------------
:- table reasonVBTableEntry/3 as incremental.

% Because it is already known to be a valid VBTable entry.
% PAPER: NA
reasonVBTableEntry(VBTable, Offset, Value) :-
    factVBTableEntry(VBTable, Offset, Value).

% Because the first two(?) entries in the VBTable are always valid.
% PAPER: ??? NEW!
reasonVBTableEntry(VBTable, 4, Value) :-
    factVBTable(VBTable),
    possibleVBTableEntry(VBTable, 4, Value).

% Because there is a larger valid VBTable entry in the same VBTable.
% PAPER: ??? NEW!
reasonVBTableEntry(VBTable, Offset, Value) :-
    factVBTableEntry(VBTable, ExistingOffset, _ExistingValue),
    possibleVBTableEntry(VBTable, Offset, Value),
    Offset < ExistingOffset.

% Because the RTTI information says so.
% PAPER: ??? NEW!
reasonVBTableEntry(VBTable, Offset, Value) :-
    rTTIEnabled,
    rTTIValid,
    rTTIInheritsFrom(DerivedTDA, _BaseTDA, _Attributes, 0, P, Offset),
    iso_dif(P, 0xffffffff),
    rTTITDA2Class(DerivedTDA, DerivedClass),
    find(Method, DerivedClass),
    possibleVBTableWrite(_Insn, Method, P, VBTable),
    possibleVBTableEntry(VBTable, Offset, Value),
    % Debugging
    logtraceln('~Q.', reasonVBTableEntry_A(VBTable, Offset, Value)).

% ============================================================================================
% Embedded object rules.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% The member at Offset in OuterConstructor is certain to be an object instance of class
% InnerConstructor.  The InnerConstructor might be a base class or an embedded object.  This
% rule makes no distinction.
:- table reasonObjectInObject/3 as incremental.

:- table reasonObjectInObject_A/3 as incremental.
:- table reasonObjectInObject_B/3 as incremental.
:- table reasonObjectInObject_C/3 as incremental.
:- table reasonObjectInObject_D/3 as incremental.
:- table reasonObjectInObject_E/3 as incremental.

reasonObjectInObject(OuterClass, InnerClass, Offset) :-
    %logwarnln('Recomputing reasonObjectInObject...'),
    or([reasonObjectInObject_A(OuterClass, InnerClass, Offset),
        reasonObjectInObject_B(OuterClass, InnerClass, Offset),
        reasonObjectInObject_C(OuterClass, InnerClass, Offset),
        reasonObjectInObject_D(OuterClass, InnerClass, Offset),
        reasonObjectInObject_E(OuterClass, InnerClass, Offset)
      ]).

% Because it is already known to be true.
% PAPER: NA
reasonObjectInObject_A(OuterClass, InnerClass, Offset) :-
    factObjectInObject(OuterClass, InnerClass, Offset).

% Because an existing inhertance relationship exists.
reasonObjectInObject_B(OuterClass, InnerClass, Offset) :-
    % While it's unusual to gain the derived class knowledge first, we should keep the fact
    % database consistent in cases where we do (e.g. from RTTI information).
    factDerivedClass(OuterClass, InnerClass, Offset),
    % Debugging
    logtraceln('~@~Q.', [not(factObjectInObject(OuterClass, InnerClass, Offset)),
                         reasonObjectInObject_B(OuterClass, InnerClass, Offset)]).

% Because an existing embedded object relationship exists.
reasonObjectInObject_C(OuterClass, InnerClass, Offset) :-
    % This case probably is used at all yet, but it might be someday.
    factEmbeddedObject(OuterClass, InnerClass, Offset),
    % Debugging
    logtraceln('~@~Q.', [not(factObjectInObject(OuterClass, InnerClass, Offset)),
                         reasonObjectInObject_C(OuterClass, InnerClass, Offset)]).

% This rule is a special case of the reasonObjectInObject_E, that relies on the fact that it
% does not matter whether the InnerClass and OuterClass are provably different or whether
% they're just currently not assigned to the same class.  The key observation is that the
% distinction only matters when offset is non-zero, because that fact alone rules out the
% possibility that the two classes are in fact the same class.
reasonObjectInObject_D(OuterClass, InnerClass, Offset) :-
    % We are certain that this member offset is passed to InnerConstructor.
    validFuncOffset(_CallInsn, OuterConstructor, InnerConstructor, Offset),
    factConstructor(OuterConstructor),
    factConstructor(InnerConstructor),
    iso_dif(InnerConstructor, OuterConstructor),
    find(InnerConstructor, InnerClass),
    find(OuterConstructor, OuterClass),

    % This constraint is the one that makes this rule different from ObjectInObject_E.
    iso_dif(Offset, 0),
    iso_dif(InnerClass, OuterClass),

    % Prevent grand ancestors from being decalred object in object.  See commentary below.
    % It's unclear of this constraint is really required in cases where Offset is non-zero.
    not(reasonClassRelationship(OuterClass, InnerClass)),

    % Debugging
    logtraceln('~@~Q.', [not(factObjectInObject(OuterClass, InnerClass, Offset)),
                         reasonObjectInObject_D(OuterClass, InnerClass, Offset)]).

% Because the outer constructor explicitly calls the inner constructor on that offset.
% PAPER: Relate-1
% ED_PAPER_INTERESTING
reasonObjectInObject_E(OuterClass, InnerClass, Offset) :-
    % We are certain that this member offset is passed to InnerConstructor.
    validFuncOffset(_CallInsn, OuterConstructor, InnerConstructor, Offset),
    factConstructor(OuterConstructor),
    factConstructor(InnerConstructor),
    iso_dif(InnerConstructor, OuterConstructor),
    find(InnerConstructor, InnerClass),
    find(OuterConstructor, OuterClass),

    % It's not good enough for the methods to currently be assigned to different classes
    % because they could actually be on the same class, and we just haven't merged them yet.
    % What's really correct is that we know that they're on different classes (or more
    % literally that we know that we're never going to merge the two classes).

    % The weaker version of this rule without this additional constraint was moved to a guess,
    % because there's a good chance that there's an ObjectInObject relationship even if we
    % can't prove that the two methods are on different classes yet.  This additional strength
    % is actually only required when the offset is zero, because it's always true that an
    % object can't embed or inherit itself at a non-zero offset.
    dynFactNOTMergeClasses(InnerClass, OuterClass),

    % There's a poorly understood case demonstrated by constructors in Lite/oo:
    %   0x40365c = std::length_error
    %   0x40360f = std::logic_error
    %   0x403f39 = std::exception

    % The hierarchy is length_error is a logic_error, which is an exception, but this rule
    % concludes that there's an exception in length_error, which is probably not what we
    % wanted.  This blocks that condition, but it's not clear that it does so optimally.
    not(reasonClassRelationship(OuterClass, InnerClass)),

    % Debugging
    logtraceln('~@~Q.', [not(factObjectInObject(OuterClass, InnerClass, Offset)),
                         reasonObjectInObject_E(OuterClass, InnerClass, Offset)]).

% The member at Offset in OuterConstructor is certain to be an object instance of class
% InnerConstructor.  The reasoning was intended to be based on two different constructors
% writing the same VFTable.  The intended scenario was that the outer constructor inlined a
% constructor for the inner class (which we detected via the VFTable write) but there was
% another implementation of the inner constructor that was associated with the inner class that
% identifed inner class for us.  But this rule proved to be too fragile.  Specifically, it's
% very important that we properly exclude the case where Offset is zero, and the two
% constructors are really two constructors on the same class.  This was supposed to happen
% because we called methodsNOTOnSameClass(), but that's not a true asserted fact -- it's
% reasoned based on our current find results, which can change with class mergers.  If we want
% this rule, we'll need stronger negative assertions of class non-equivalence.
%reasonObjectInObject(OuterClass, InnerClass, Offset) :-
%    factConstructor(OuterConstructor),
%    factVFTableWrite(_Insn1, OuterConstructor, Offset, VFTable),
%    factConstructor(InnerConstructor),
%    factVFTableWrite(_Insn2, InnerConstructor, 0, VFTable),
%    iso_dif(InnerConstructor, OuterConstructor,
%    find(InnerConstructor, InnerClass),
%    find(OuterConstructor, OuterClass),
%    iso_dif(InnerClass, OuterClass),
%    logtraceln('~Q.', reasonObjectInObject2(OuterClass, InnerClass, Offset)).

% --------------------------------------------------------------------------------------------
% The member at Offset in Class is certain to be an object instance of the type associated with
% the class EmbeddedClass.
:- table reasonEmbeddedObject/3 as incremental.

:- table reasonEmbeddedObject_A/3 as incremental.
:- table reasonEmbeddedObject_B/3 as incremental.
:- table reasonEmbeddedObject_C/3 as incremental.
:- table reasonEmbeddedObject_D/3 as incremental.

reasonEmbeddedObject(Class, EmbeddedClass, Offset) :-
    %logwarnln('Recomputing reasonEmbeddedObject...'),
    or([reasonEmbeddedObject_A(Class, EmbeddedClass, Offset),
        reasonEmbeddedObject_B(Class, EmbeddedClass, Offset),
        reasonEmbeddedObject_C(Class, EmbeddedClass, Offset),
        reasonEmbeddedObject_D(Class, EmbeddedClass, Offset)
      ]).

% Because it is already known to be true.
% PAPER: NA
reasonEmbeddedObject_A(Class, EmbeddedClass, Offset) :-
    factEmbeddedObject(Class, EmbeddedClass, Offset).

% Because the object is there and we know it's not a case of inheritance.
% PAPER: Logic
reasonEmbeddedObject_B(Class, EmbeddedClass, Offset) :-
    factObjectInObject(Class, EmbeddedClass, Offset),
    % If this were true, we'd be inhertance instead.
    factNOTDerivedClass(Class, EmbeddedClass, Offset).

% Because if a constructor has no base, but there is an object inside an object, then that
% object must be an embedded object (and not a base class).
% PAPER: Relate-2 / logic
reasonEmbeddedObject_C(Class, EmbeddedClass, Offset) :-
    factObjectInObject(Class, EmbeddedClass, Offset),
    factClassHasNoBase(Class).

% Because there's an embedded object before this object in the enclosing class.  Base clases
% are always located before the embedded objects, and so the first embedded object marks the
% end of inheritance.  This rule is a specialization of the next rule, but should perform
% better due to testing explicitly true facts rather than using "not()".
reasonEmbeddedObject_D(Class, EmbeddedClass, Offset) :-
    factObjectInObject(Class, EmbeddedClass, Offset),
    not(factDerivedClass(Class, EmbeddedClass, Offset)),
    iso_dif(Offset, 0),
    factEmbeddedObject(Class, _, LowerOffset),
    LowerOffset < Offset.

% Because there's a member before this one that's not an object.  In other words, there's an
% ordinary member before this object, which means that it can't be inheritance, because base
% classes are always listed before all other members.  This turns out to be not strictly true
% for cases of virtual inheritance, which can place ordinary members before the virtual base
% class.  See the corresponding sanity rule which has also been disabled.
%
% Expressing this rule in terms of not(ObjectInObject(...)) requires those facts to be present,
% and unfortunately they may not always been concluded in the correct order.  This also turned
% out to be a non-trivial problem with this rule, and no completely satisfactory solution was
% found (the problem was eventually worked around by making guesses in a better order).  There
% might be a solution involving ValidFuncOffset, and proving that there can never be an object
% at a given offset but that's stil proof based on the absence of evidence, which might not be
% the best plan.  I decided in the end to remove the draft rule entirely, because it was a
% mess, but to keep the comment because this line of thinking still has merit.

% Add rule for: We must be an embedded object if the table we write was the certain normal
% (unmodified) table of the embedded constructor.  Duplicate of inheritance NOT rule?

% --------------------------------------------------------------------------------------------
:- table reasonNOTEmbeddedObject/3 as incremental.

% Because it is already known to be true.
% PAPER: NA
reasonNOTEmbeddedObject(Class, EmbeddedClass, Offset) :-
    factNOTEmbeddedObject(Class, EmbeddedClass, Offset).

% Because we can't be an embedded object if we're already an inheritance relationship.
% PAPER: Logic
reasonNOTEmbeddedObject(Class, EmbeddedClass, Offset) :-
    factObjectInObject(Class, EmbeddedClass, Offset),
    factDerivedClass(Class, EmbeddedClass, Offset).

% Add rule for: We cannot be an embedded object if we've extended the vftable in question.

% ============================================================================================
% Rules for inheritance relationships.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% Derived class is certain to derived from the base class at the specified offset.
:- table reasonDerivedClass/3 as incremental.

:- table reasonDerivedClass_A/3 as incremental.
:- table reasonDerivedClass_B/3 as incremental.
:- table reasonDerivedClass_C/3 as incremental.
:- table reasonDerivedClass_D/3 as incremental.
:- table reasonDerivedClass_E/3 as incremental.
:- table reasonDerivedClass_F/3 as incremental.

reasonDerivedClass(DerivedClass, BaseClass, ObjectOffset) :-
    %logwarnln('Recomputing reasonDerivedClass...'),
    or([reasonDerivedClass_A(DerivedClass, BaseClass, ObjectOffset),
        reasonDerivedClass_B(DerivedClass, BaseClass, ObjectOffset),
        reasonDerivedClass_C(DerivedClass, BaseClass, ObjectOffset),
        reasonDerivedClass_D(DerivedClass, BaseClass, ObjectOffset),
        reasonDerivedClass_E(DerivedClass, BaseClass, ObjectOffset),
        reasonDerivedClass_F(DerivedClass, BaseClass, ObjectOffset)
      ]).

% Because it is already known to be true.
% PAPER: NA
reasonDerivedClass_A(DerivedClass, BaseClass, ObjectOffset) :-
    factDerivedClass(DerivedClass, BaseClass, ObjectOffset).

% Because the derived class constructor calls the base class constructor, and both constructors
% install VFTables into the same location.  The VFTable overwrite contraint is required because
% otherwise the rule will match embedded object releationships as well.  Proof that the two
% VFTable writes are to the same location is provided by the pointer math in validFuncOffset,
% paried with the appropriatte offsets in the VFTable writes.

% PAPER: Relate-3
% ED_PAPER_INTERESTING
reasonDerivedClass_B(DerivedClass, BaseClass, ObjectOffset) :-

    % ejs 10/9/20 In ooex_2010/Lite/ooex7.exe and possibly others, we are seeing RTTI tell us
    % that std::length_error inherits from std::logic_error.  But we see that std::length_error
    % installs the vftable for std::exception with this rule, and conclude that
    % std::length_error also inherits from std::exception.  This rule doesn't have much value
    % if RTTI is available though, so in that case we just turn it off.
    not((rTTIEnabled, rTTIValid)),

    % Some instruction in the derived class constructor called the base class constructor.
    % This is the part of the rule that determines which is the base class and which is the
    % derived class.  There might be other ways of doing this as well, like determining which
    % of the two classes is smaller.  Without this clause we'd just be saying that the two
    % constructors had an inheritance relationship without identifying which was the base.
    validFuncOffset(_, DerivedConstructor, BaseConstructor, ObjectOffset),
    factConstructor(DerivedConstructor),
    factConstructor(BaseConstructor),
    % A constructor can't be it's own parent.
    iso_dif(DerivedConstructor, BaseConstructor),

    % Both methods wrote confirmed vtables into offsets in the object.  In the derived class,
    % the offset is the location of the object, but in the base class it will always be the
    % table written to offset zero.
    factVFTableWrite(_Insn1, DerivedConstructor, ObjectOffset, DerivedVFTable),

    % No one overwrites the vftable
    not(factVFTableOverwrite(DerivedConstructor, DerivedVFTable, _OverwrittenDerivedVFTable, ObjectOffset)),

    ((factVFTableWrite(_Insn2, BaseConstructor, 0, BaseVFTable),
      % No one overwrites the vftable
      not(factVFTableOverwrite(BaseConstructor, BaseVFTable, _OverwrittenBaseVFTable, 0)),
      % And the vtables values written were different
      iso_dif(DerivedVFTable, BaseVFTable));
     % Right now we assume that if a class inherits from an imported class, the base class is
     % probably virtual.  In this case, we won't see base class vftable being installed.  We
     % could possibly verify this using RTTI to make this rule a little stronger.
     % Unfortunately, MFC apparently does not use RTTI, and this is probably one of the most
     % frequent cases of inheriting from an imported class
     % https://docs.microsoft.com/en-us/cpp/mfc/accessing-run-time-class-information?view=vs-2019.
     symbolClass(BaseConstructor, _MangledName, _ClassName, _MethodName)),

    find(DerivedConstructor, DerivedClass),
    find(BaseConstructor, BaseClass),

    % There's not already a relationship.  (Prevent grand ancestors)
    not(reasonClassRelationship(DerivedClass, BaseClass)),

    % Debugging
    logtraceln('~@DEBUG Derived VFTable: ~Q~n Base VFTable: ~Q~n Derived Constructor: ~Q~n Base Constructor: ~Q',
               [not(factDerivedClass(DerivedClass, BaseClass, ObjectOffset)),
                DerivedVFTable, BaseVFTable, DerivedConstructor, BaseConstructor]),

    logtraceln('~Q.', reasonDerivedClass_B(DerivedClass, BaseClass, ObjectOffset)).

% Ed: So this situation is complicated as well.  This rule is flawed because the last statement
% is incorrect (we are incorrectly permitting cases where the Method is on the base's base
% class).  This rule appears to be related to a failure in muparser where we reach a wrong
% conclusion because of it.  Even with it removed, we can still pass our tests, so it's not
% required.  But I think it was added to correct a problem in Firefox or something like that.
% Unfortunately, because our test suite management is poor, it's difficult to know why we
% needed it.  How do you think we should proceed?

% Because there's a method ocurring in two different VFTables, and those VFTables are written
% into the same location in an object.
% PAPER: Relate-4
%reasonDerivedClass(DerivedClass, BaseClass, ObjectOffset) :-
%    % And there's a method that appears in two different VFTables...
%    factVFTableEntry(BaseVFTable, _BaseVFTableOffset, Entry),
%    factVFTableEntry(DerivedVFTable, _DerivedVFTableOffset, Entry),
%    iso_dif(DerivedVFTable, BaseVFTable),
%    dethunk(Entry, Method),
%
%    % The method must be assigned to the base class because base classes can't call methods on
%    % the derived class.
%    find(Method, BaseClass),
%    not(purecall(Method)),
%
%    % Find a constructor in the base class.
%    factConstructor(BaseConstructor),
%    factVFTableWrite(_Insn1, BaseConstructor, 0, BaseVFTable),
%    find(BaseConstructor, BaseClass),
%
%    % And other constructor that's different from the base constructor.
%    factConstructor(DerivedConstructor),
%    factVFTableWrite(_Insn2, DerivedConstructor, ObjectOffset, DerivedVFTable),
%    iso_dif(DerivedConstructor, BaseConstructor),
%
%    % The derived class must be different from the base class.
%    find(DerivedConstructor, DerivedClass),
%    iso_dif(DerivedClass, BaseClass),
%
%    % We must eliminate cases where the method is really on the base classes' base class.  See
%    % ClassHasUnknownBase for more details.
%    factClassHasNoBase(BaseClass).
%    % Previous (incorrect) versions of this term/line included:
%not(factDerivedClass(DerivedClass, _ExistingBase, _OtherObjectOffset)),
%not(factDerivedClass(DerivedClass, BaseClass, _OtherObjectOffset)),

% Short format debugging.
%%     logtraceln('~Q.', reasonDerivedClass2(DerivedClass, BaseClass, ObjectOffset)),

%%     % Long format debugging.
%%     logtraceln('reasonDerivedClass2()...'),
%%     logtraceln('  Method: ~Q', Method),
%%     logtraceln('  Base VFTable: ~Q', BaseVFTable),
%%     logtraceln('    Constructor: ~Q', BaseConstructor),
%%     logtraceln('    Class: ~Q', BaseClass),
%%     logtraceln('  Derived VFTable: ~Q', DerivedVFTable),
%%     logtraceln('    Constructor: ~Q', DerivedConstructor),
%%     logtraceln('    Class: ~Q', DerivedClass).


% This rule might be slightly off, because another possibility is that there's a nearly
% invisible derived class relationship in between the derived class and the base class.  This
% was observed by David in ooex10 and ooex11 test cases.
% PAPER: Logic
reasonDerivedClass_C(DerivedClass, BaseClass, Offset) :-
    factObjectInObject(DerivedClass, BaseClass, Offset),
    factNOTEmbeddedObject(DerivedClass, BaseClass, Offset),
    % Debugging
    logtraceln('~@~Q.', [not(factDerivedClass(DerivedClass, BaseClass, Offset)),
                         reasonDerivedClass_C(DerivedClass, BaseClass, Offset)]).

% Because RTTI tells us so for a non-virtual base class.
reasonDerivedClass_D(DerivedClass, BaseClass, Offset) :-
    rTTIEnabled,
    rTTIValid,
    rTTIInheritsFrom(DerivedTDA, BaseTDA, _Attributes, Offset, 0xffffffff, 0),
    rTTITDA2Class(DerivedTDA, DerivedClass),
    rTTITDA2Class(BaseTDA, BaseClass),
    iso_dif(BaseClass, DerivedClass),
    % Debugging
    logtraceln('~@~Q.', [not(factDerivedClass(DerivedClass, BaseClass, Offset)),
                         reasonDerivedClass_D(DerivedTDA, BaseTDA, DerivedClass,
                                              BaseClass, Offset)]).

% Because RTTI tells us so for a virtual base class.
reasonDerivedClass_E(DerivedClass, BaseClass, Offset) :-
    rTTIEnabled,
    rTTIValid,
    rTTIInheritsFrom(DerivedTDA, BaseTDA, _Attributes, M, P, V),
    iso_dif(P, 0xffffffff),
    possibleVBTableWrite(_Insn, Method, P, VBTableAddr),
    rTTITDA2Class(DerivedTDA, DerivedClass),
    rTTITDA2Class(BaseTDA, BaseClass),
    iso_dif(BaseClass, DerivedClass),
    find(Method, DerivedClass),
    possibleVBTableEntry(VBTableAddr, V, Entry),
    Offset is P + Entry,
    % Debugging
    logtraceln('~@~Q.', [not(factDerivedClass(DerivedClass, BaseClass, Offset)),
                         reasonDerivedClass_E(M, P, V, Method, VBTableAddr,
                                              DerivedClass, BaseClass, Offset)]).

% An easier to understand version of E that builds on concluded VBTable facts instead of RTTI.
reasonDerivedClass_F(DerivedClass, BaseClass, Offset) :-
    factObjectInObject(DerivedClass, BaseClass, Offset),
    % There's an entry in some VBTable somehere (only unified by Offset so far).
    factVBTableEntry(VBTableAddress, _TableObjectOffset, Offset),
    % And that VBTable is installed into an object in some Method.
    factVBTableWrite(_Insn, Method, _VBTableOffset, VBTableAddress),
    % Finally, check that the method is assigned to the Derived class.
    % This is the unification that makes the VBTableEntry relevant.
    find(Method, DerivedClass),
    % Debugging
    logtraceln('~@~Q.', [not(factDerivedClass(DerivedClass, BaseClass, Offset)),
                         reasonDerivedClass_F(DerivedClass, BaseClass, Offset,
                                              VBTableAddress)]).

% --------------------------------------------------------------------------------------------
:- table reasonNOTDerivedClass/3 as incremental.

% Because it is already known to be true.
% PAPER: NA
reasonNOTDerivedClass(DerivedClass, BaseClass, ObjectOffset) :-
    factNOTDerivedClass(DerivedClass, BaseClass, ObjectOffset).

% Because it can't be an inheritance relationship if it is already an embedded object.
% PAPER: Logic
reasonNOTDerivedClass(DerivedClass, BaseClass, ObjectOffset) :-
    factEmbeddedObject(DerivedClass, BaseClass, ObjectOffset),
    find(DerivedConstructor, DerivedClass),
    find(BaseConstructor, BaseClass),
    % ejs: Why do these need to be constructors?
    factConstructor(DerivedConstructor),
    factConstructor(BaseConstructor).

% There can't be multiple inhertitance without single inheritance.  VFTable writes at non-zero
% offsets can not represent base classes unless there's also a VFTable write at offset zero.
% In other words, all VFTables installed into non-zero offsets of an object must be
% inlined-constructors of embedded objects rather than base classes.  The only possible
% exception to this could be a first base class that had no virtual functions and a second base
% class that did have virtual functions. However, I would expect that the compiler would choose
% the class with the virtual functions as the first base class in that case as a clear
% performance optimization.
reasonNOTDerivedClass(DerivedClass, BaseClass, ObjectOffset) :-

    % There is embedding or inheritance at non-offset 0
    factObjectInObject(DerivedClass, BaseClass, ObjectOffset),
    iso_dif(ObjectOffset, 0),
    find(DerivedConstructor, DerivedClass),
    factConstructor(DerivedConstructor),

    % The derived constructor does not write a vftable at offset 0
    not(factVFTableWrite(_Insn, DerivedConstructor, 0, _DVFTable)),

    % The base class has a primary vftable
    find(BaseConstructor, BaseClass),
    % ejs: Why do these need to be constructors?
    factConstructor(BaseConstructor),
    findVFTable(_BVFTable, 0, BaseClass).

% Add rule for: We cannot be a derived constructor if the table we write was the certain normal
% (unmodified) table of the base constructor.

% --------------------------------------------------------------------------------------------
% It is certain that there is a derived class relationship between the the two classes,
% although there might be multiple classes in between them in the inheritance hierarchy.
:- table reasonDerivedClassRelationship/2 as incremental.

% Because there's an immediate relationship.
% PAPER: NA
reasonDerivedClassRelationship(DerivedClass, BaseClass) :-
    factDerivedClass(DerivedClass, BaseClass, _Offset).

% Because there's a relationship with one or more intermediate classes.
% PAPER: Do we need this in the paper?
reasonDerivedClassRelationship(DerivedClass, BaseClass) :-
    factDerivedClass(DerivedClass, MiddleClass, _Offset),
    iso_dif(DerivedClass, MiddleClass),
    reasonDerivedClassRelationship(MiddleClass, BaseClass),
    iso_dif(MiddleClass, BaseClass).

% --------------------------------------------------------------------------------------------
% It is certain that there is a class relationship between the two classes (either through
% inheritance or embedding).

% This causes a huge amount of tabling space in FireFall.
:- table reasonClassRelationship/2 as incremental.

% Because there's an immediate relationship.
% PAPER: NA
reasonClassRelationship(DerivedClass, BaseClass) :-
    factObjectInObject(DerivedClass, BaseClass, _Offset).

% Because there's a relationship with one or more intermediate classes.
% PAPER: Do we need this in the paper?
reasonClassRelationship(DerivedClass, BaseClass) :-
    factObjectInObject(DerivedClass, MiddleClass, _Offset),
    iso_dif(DerivedClass, MiddleClass),
    reasonClassRelationship(MiddleClass, BaseClass),
    iso_dif(MiddleClass, BaseClass).

% --------------------------------------------------------------------------------------------
% It is certain that the class has no base class.
:- table reasonClassHasNoBase/1 as incremental.

% Because it is already known to be true.
% PAPER: NA
reasonClassHasNoBase(Class) :-
    factClassHasNoBase(Class).

% Because RTTI told us so.
% ED_PAPER_INTERESTING
reasonClassHasNoBase(Class) :-
    % RTTI analysis is enabled, and the data structures were internally consistent.
    rTTIEnabled,
    rTTIValid,
    rTTINoBase(TDA),
    rTTITDA2Class(TDA, Class),
    logtraceln('~Q.', reasonClassHasNoBase(TDA, Class)).

reasonClassHasNoBaseSet(Set) :-
    setof(Class, reasonClassHasNoBase(Class), Set).

% --------------------------------------------------------------------------------------------
% It is certain that the class has a base class (but we don't know which class it is).
:- table reasonClassHasUnknownBase/1 as incremental.
:- table reasonClassHasUnknownBase_A/1 as incremental.
:- table reasonClassHasUnknownBase_B/1 as incremental.
% This was broken up into several triggered rules
%:- table reasonClassHasUnknownBase_C/8 as incremental.
:- table reasonClassHasUnknownBase_D/1 as incremental.

% trigger
%:- table reasonClassHasUnknownBase_E/3 as incremental.

reasonClassHasUnknownBase(Class) :-
    %logwarnln('Recomputing reasonClassHasUnknownBase...'),
    or([reasonClassHasUnknownBase_A(Class),
        reasonClassHasUnknownBase_B(Class),
        % in trigger.pl
        %reasonClassHasUnknownBase_C(Class),
        reasonClassHasUnknownBase_D(Class)
      % in trigger.pl
      %reasonClassHasUnknownBase_E(Class)
      ]).

% Because it is already known to be true.
% PAPER: NA
reasonClassHasUnknownBase_A(Class) :-
    factClassHasUnknownBase(Class).

% Because there's what looks like a valid virtual base table.
% PAPER: Relate-5
% ED_PAPER_INTERESTING
reasonClassHasUnknownBase_B(Class) :-
    factVBTableWrite(_Insn, Constructor, _Offset, _VBTable),
    factConstructor(Constructor),
    find(Constructor, Class).

% Because there's a method ocurring in two different VFTables, and those VFTables are written
% into the same location in an object.  This rule does not prove which class is the base class,
% only that there's an ancestor class (because the rule might match a method on the true base's
% base class as well.
% PAPER: Relate-6
% ED_PAPER_INTERESTING

% factVFTableEntry: VFTable could be AncestorVFTable or DerivedVFTable
reasonClassHasUnknownBase_C1(DerivedClass, AncestorVFTable, DerivedVFTable, Entry) :-
    % And there's a method that appears in two different VFTables...  During the thunk
    % conversion Cory chose to make the VFTable entries match exactly, but it's possible that
    % we really mean any two entries that dethunk to the same actual method.
    factVFTableEntry(AncestorVFTable, _AncestorVFTableOffset, Entry),
    factVFTableEntry(DerivedVFTable, _DerivedVFTableOffset, Entry),
    iso_dif(DerivedVFTable, AncestorVFTable),

    % The method must be assigned to the ancestor class because ancestor classes can't call
    % methods on the derived class.
    dethunk(Entry, Method),
    find(Method, AncestorClass),

    % Ensure the ancestor constructor is in the base class.
    find(AncestorConstructor, AncestorClass),
    factConstructor(AncestorConstructor),

    % Both constructors wrote confirmed vtables into offsets in the object.  In the derived
    % class, the offset is the location of the object, but in the base class it will always be
    % the table written to offset zero.
    factVFTableWrite(_Insn2, AncestorConstructor, 0, AncestorVFTable),

    % And the other constructor is different from the base constructor.
    factVFTableWrite(_Insn1, DerivedConstructor, _ObjectOffset, DerivedVFTable),
    factConstructor(DerivedConstructor),
    % We don't need to check this because we check that both are on different classes below.
    %iso_dif(DerivedConstructor, AncestorConstructor),

    % And is on a different class.
    find(DerivedConstructor, DerivedClass),
    iso_dif(DerivedClass, AncestorClass).

% find: (FindMethod, FindClass) could be (Method, AncestorClass) or (AncestorConstructor, AncestorClass)
% How do we get to Entry?
% AncestorClass -> AncestorConstructor -> AncestorVFTable -> Entry
reasonClassHasUnknownBase_C2(DerivedClass, Method, AncestorConstructor, AncestorClass, AncestorVFTable) :-

    % Ensure the ancestor constructor is in the base class.
    find(AncestorConstructor, AncestorClass),
    factConstructor(AncestorConstructor),

    % Both constructors wrote confirmed vtables into offsets in the object.  In the derived
    % class, the offset is the location of the object, but in the base class it will always be
    % the table written to offset zero.
    factVFTableWrite(_Insn2, AncestorConstructor, 0, AncestorVFTable),

    % And there's a method that appears in two different VFTables...  During the thunk
    % conversion Cory chose to make the VFTable entries match exactly, but it's possible that
    % we really mean any two entries that dethunk to the same actual method.
    factVFTableEntry(AncestorVFTable, _AncestorVFTableOffset, Entry),

    % The method must be assigned to the ancestor class because ancestor classes can't call
    % methods on the derived class.
    dethunk(Entry, Method),

    find(Method, AncestorClass),

    % And there's a method that appears in two different VFTables...  During the thunk
    % conversion Cory chose to make the VFTable entries match exactly, but it's possible that
    % we really mean any two entries that dethunk to the same actual method.
    factVFTableEntry(DerivedVFTable, _DerivedVFTableOffset, Entry),
    iso_dif(DerivedVFTable, AncestorVFTable),

    % And the other constructor is different from the base constructor.
    factVFTableWrite(_Insn1, DerivedConstructor, _ObjectOffset, DerivedVFTable),
    factConstructor(DerivedConstructor),
    % We don't need to check this because we check that both are on different classes below.
    %iso_dif(DerivedConstructor, AncestorConstructor),

    % And is on a different class.
    find(DerivedConstructor, DerivedClass),
    iso_dif(DerivedClass, AncestorClass).

% find Method, Class could be DerivedConstructor, DerivedClass
% DerivedConstructor -> DerivedVFTable -> Entry
reasonClassHasUnknownBase_C3(DerivedClass, DerivedConstructor, DerivedVFTable) :-
    find(DerivedConstructor, DerivedClass),

    % And the other constructor is different from the base constructor.
    factVFTableWrite(_Insn1, DerivedConstructor, _ObjectOffset, DerivedVFTable),
    factConstructor(DerivedConstructor),

    % And there's a method that appears in two different VFTables...  During the thunk
    % conversion Cory chose to make the VFTable entries match exactly, but it's possible that
    % we really mean any two entries that dethunk to the same actual method.
    factVFTableEntry(DerivedVFTable, _DerivedVFTableOffset, Entry),
    factVFTableEntry(AncestorVFTable, _AncestorVFTableOffset, Entry),
    iso_dif(DerivedVFTable, AncestorVFTable),

    % The method must be assigned to the ancestor class because ancestor classes can't call
    % methods on the derived class.
    dethunk(Entry, Method),
    find(Method, AncestorClass),

    % Both constructors wrote confirmed vtables into offsets in the object.  In the derived
    % class, the offset is the location of the object, but in the base class it will always be
    % the table written to offset zero.
    factVFTableWrite(_Insn2, AncestorConstructor, 0, AncestorVFTable),

    % Ensure the ancestor constructor is in the base class.
    find(AncestorConstructor, AncestorClass),
    factConstructor(AncestorConstructor),

    % We don't need to check this because we check that both are on different classes below.
    %iso_dif(DerivedConstructor, AncestorConstructor),

    % And is on a different class.
    iso_dif(DerivedClass, AncestorClass).


% Because RTTI tells us so.
reasonClassHasUnknownBase_D(Class) :-
    % Normally we'd conclude that there was a specific derived relationship, but because of
    % problems reliably associating VFTables with methods, in some cases the best that we can
    % manage is to know that there's a base class...
    rTTIEnabled,
    rTTIValid,
    rTTIInheritsFrom(DerivedTDA, _BaseTDA, _Attributes, _Offset1, _P, _V),
    rTTITDA2Class(DerivedTDA, Class),
    % Debugging
    logtraceln('~@~Q.', [not(factClassHasUnknownBase(Class)),
                         reasonClassHasUnknownBase_D(Class)]).

% Because the class shares a method that we know is not assigned to the class.
reasonClassHasUnknownBase_E(Class, Method, MethodClass) :-
    factClassCallsMethod(Class, Method),
    find(Method, MethodClass),
    dynFactNOTMergeClasses(Class, MethodClass),
    % Debugging
    logtraceln('~@~Q.', [not(factClassHasUnknownBase(Class)),
                         reasonClassHasUnknownBase_E(Class)]).

reasonClassHasUnknownBaseSet(Set) :-
    setof(Class, reasonClassHasUnknownBase(Class), Set).

% ============================================================================================
% Rules for method assignment.
% ============================================================================================

:- table reasonClassCallsMethod/2 as incremental.
:- table reasonClassCallsMethod_A/2 as incremental.
:- table reasonClassCallsMethod_B/2 as incremental.
:- table reasonClassCallsMethod_C/2 as incremental.
:- table reasonClassCallsMethod_D/2 as incremental.
:- table reasonClassCallsMethod_E/2 as incremental.
:- table reasonClassCallsMethod_F/2 as incremental.

reasonClassCallsMethod(Class, Method) :-
    %logwarnln('Recomputing reasonClassCallsMethod...'),
    or([reasonClassCallsMethod_A(Class, Method),
        reasonClassCallsMethod_B(Class, Method),
        reasonClassCallsMethod_C(Class, Method),
        reasonClassCallsMethod_D(Class, Method)
      %        reasonClassCallsMethod_E(Class, Method),
      %        reasonClassCallsMethod_F(Class, Method)
      ]).

% Because two methods are called on the same this-pointer in the same function.
% This rule is NOT direction safe, because it simply observes two methods being called on the
% same object pointer, and does not account for inheritance relationships.  Cory and Ed
% discussed changing it into a guessing rule that guesses the direction of the relationship.
% PAPER: Call-1
reasonClassCallsMethod_A(Class1, Method2) :-
    thisPtrUsage(_, Function, ThisPtr, Method1),
    thisPtrUsage(_, Function, ThisPtr, Method2),
    iso_dif(Method1, Method2),
    find(Method1, Class1),
    % Don't propose assignments we already know.
    find(Method2, Class2),
    iso_dif(Class1, Class2),

    % Function could be a derived constructor calling Method1 (a base constructor) and Method2
    % (a method on Function's class).  This incorrectly concludes that Method2 is called from
    % Method1 unless it is blocked by a clause like this...  but what is really correct here?
    not((find(Function, FunctionClass), factObjectInObject(FunctionClass, Class1, 0))),

    % Functions that are methods can call base methods

    % Debugging
    logtraceln('~@~Q.', [not(factClassCallsMethod(Class1, Method2)),
                         reasonClassCallsMethod_A(Function, Method1, Class1, Method2)]).

% Because the method appears in a vftable assigned in another method.  This rule is direction
% safe because we know the class that "owns" the VFTable through findVFTable.
% PAPER: Call-2
reasonClassCallsMethod_B(Class1, Method2) :-
    findVFTable(VFTable, Class1),
    % And the method is in that virtual function table.
    factVFTableEntry(VFTable, _TableOffset, Entry2),
    dethunk(Entry2, Method2),
    not(purecall(Entry2)), % Never merge purecall methods into classes.
    not(purecall(Method2)), % Never merge purecall methods into classes.
    % Don't propose assignments we already know.
    find(Method2, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    logtraceln('~@~Q.', [not(factClassCallsMethod(Class1, Method2)),
                         reasonClassCallsMethod_B(VFTable, Class1, Method2)]).

% Because one method calls another method on the same this-pointer.  This rule is direction
% safe because we know what class Method1 is associated with, and if that conclusion was
% correct, this rule will be correct as well.  Does require the FuncOffset offset to be zero.
% PAPER: Call-3
reasonClassCallsMethod_C(Class1, Method2) :-
    validFuncOffset(_Insn, Method1, Method2, 0),
    iso_dif(Method1, Method2),
    find(Method1, Class1),
    % Don't propose assignments we already know.
    find(Method2, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    logtraceln('~@~Q.', [not(factClassCallsMethod(Class1, Method2)),
                         reasonClassCallsMethod_C(Method1, Class1, Method2)]).

% Because a method on an outer class calls a method on a known inner object.  This rule is
% direction safe because it incorporates ObjectInObject, which has sorted out the inheritance
% and/or embedding relationships with sufficient confidence that we have confidence in
% InnerClass.
reasonClassCallsMethod_D(InnerClass, InnerMethod) :-
    % An outer method calls and inner method on a this pointer.
    thisPtrUsage(_Insn, OuterMethod, InnerThisPtr, InnerMethod),
    % There's an offset from the outer this pointer to the inner this pointer.
    thisPtrOffset(_OuterThisPtr, Offset, InnerThisPtr),
    % BUG!!! We should really tie the OuterThisPtr to the OuterMethod, but we don't presently
    % export the facts required to do that, so we'll just assume they're related for right now.
    find(OuterMethod, OuterClass),
    % We must know that there's an object within an object at that offset.
    factObjectInObject(OuterClass, InnerClass, Offset),
    iso_dif(OuterClass, InnerClass),
    iso_dif(InnerClass, InnerMethod),
    % Debugging
    logtraceln('~@~Q.', [not(factClassCallsMethod(InnerClass, InnerMethod)),
                         reasonClassCallsMethod_D(OuterClass, OuterMethod,
                                                  InnerClass, InnerMethod)]).

% Because the __thiscall OO method calls the __cdecl OO method with the same-this pointer.
% This rule is basically a duplicate of the logic in reasonMethod_O that made the cdecl
% function a method in the first place.  Here we're just repeating the logic to also associate
% the __cdecl OO method with the correct class.  This rule is direction safe because we know
% the class associated with the __thiscall OO method.
reasonClassCallsMethod_E(Class, Method) :-
    factMethod(Proven),
    find(Proven, Class),
    callingConvention(Proven, '__thiscall'),
    funcParameter(Proven, ecx, ThisPtr),
    callParameter(Insn, Proven, 0, ThisPtr),
    callTarget(Insn, Proven, Method),
    callingConvention(Method, '__cdecl'),
    % Debugging
    logtraceln('~@~Q.', [not(factClassCallsMethod(Class, Method)),
                         reasonClassCallsMethod_E(Insn, Class, Method)]).

% Because the same this-pointer is passed from a known __cdecl OO method to another __cdecl
% method (as the first parameter) in the same function.  This method is not direction safe
% because the two cdecl methods could be on different classes involved in an inheritance
% relationship, and we haven't sorted that out correctly.
reasonClassCallsMethod_F(Class, Method) :-
    % A ThisPtr is passed to a known method.
    callParameter(Insn1, Func, 0, ThisPtr),
    callTarget(Insn1, Func, Target1),
    dethunk(Target1, Proven),
    factMethod(Proven),
    find(Proven, Class),
    % Then the same this-pointer is passed to another method.
    callParameter(Insn2, Func, 0, ThisPtr),
    iso_dif(Insn1, Insn2),
    callTarget(Insn2, Func, Target2),
    dethunk(Target2, Method),
    callingConvention(Method, '__cdecl'),
    % Debugging
    logtraceln('~@~Q.', [not(factClassCallsMethod(Class, Method)),
                         reasonClassCallsMethod_F(Insn1, Insn2, Class, Method)]).

% --------------------------------------------------------------------------------------------
% So the reasonInstanceIndirectlyCallMethod rule turned out to be wrong.  I've kept the notes
% to think about it some more.  Something like this is needed to drive arbitrary method
% assignment.  Because otherwise we don't know that loosely connected methods are more
% associated with a class than any other.  This is basically transitivity of call relationships
% (e.g if A calls B and B calls C, then A calls C as well.)  But where I seem to have gone
% wrong was by including this rule in InstanceCallsMethod which appears to include some
% reasoning that doesn't account for this indirection.  Perhaps the other rule would be more
% clearly named InstanceImmediatelyCallsMethod.  The flaw in this rule is somehow related to
% embedded objects at offset zero transferring method instances to the embedded object in a way
% that makes other rules incorrect.

% --------------------------------------------------------------------------------------------

% This rule is a much more tightly constrained version of possiblyReused in initial.pl.  This
% version may in fact be too tightly constrained to always detect the reuse in time to prevent
% the inappropriate class merges that it is designed to block, but it seems to work right now.
:- table reasonReusedImplementation/1 as incremental.

% Because there's a trivial function that occurs in two tables where we know that the classes
% are not associated by an inheritance relationship.
reasonReusedImplementation(Method) :-
    %possiblyReused(Method),
    factMethodInVFTable(VFTable1, _Offset1, Method),
    factMethodInVFTable(VFTable2, _Offset2, Method),
    iso_dif(VFTable1, VFTable2),
    find(VFTable1, Class1),
    find(VFTable2, Class2),
    iso_dif(Class1, Class2),
    not((
               reasonClassRelationship(Class1, Class2);
               reasonClassRelationship(Class2, Class1)
       )),
    logtraceln('~@~Q.', [
                   not(factReusedImplementation(Method)),
                   reasonReusedImplementation_A(Class1, VFTable1, Class2, VFTable2, Method)]).

% Because there are two instances of the same method pointer in the same VFTable.  This rule
% must use factVFTableEntry because the point of the thunks may be to differeniate between two
% addresses that share an implementation but the thunks are in fact the actual functions.
reasonReusedImplementation(Method) :-
    factVFTableEntry(VFTable, Offset1, Method),
    factVFTableEntry(VFTable, Offset2, Method),
    iso_dif(Offset1, Offset2),
    find(VFTable, Class),
    logtraceln('~@~Q.', [
                   not(factReusedImplementation(Method)),
                   reasonReusedImplementation_B(VFTable, Offset1, Offset2, Class, Method)]).


% --------------------------------------------------------------------------------------------
:- table reasonMergeVFTables/2 as incremental.
% ejs 10/16/20 This used to be a merge rule, but it's very important to make these conclusions
% early on, so we moved it to an entirely new class of facts that occurs earlier than class
% merging in general.

% Because a vftable is connected by a vftable write.  See reasonVFTableBelongsToClass for more
% information.
reasonMergeVFTables(VFTableClass, Class) :-
    reasonVFTableBelongsToClass(VFTable, Offset, Class, Rule, VFTableWrite),
    find(VFTable, VFTableClass),

    iso_dif(VFTableClass, Class),

    logtraceln('~@~Q.', [
                   not(find(VFTableClass, Class)),
                   reasonMergeVFTables_A(Rule, VFTableClass, Class, VFTable, Offset, VFTableWrite)]).

% --------------------------------------------------------------------------------------------
:- table reasonMergeClasses/2 as incremental.

% This is an attempt by Ed to avoid recomputing all of reasonMergeClasses when we invalidate
% the tables because of new facts.
%:- table reasonMergeClasses_A/2 as incremental.
:- table reasonMergeClasses_B/2 as incremental.
:- table reasonMergeClasses_C/2 as incremental.
:- table reasonMergeClasses_D/2 as incremental.
:- table reasonMergeClasses_E/2 as incremental.
%:- table reasonMergeClasses_F/2 as incremental.
:- table reasonMergeClasses_G/2 as incremental.
:- table reasonMergeClasses_H/2 as incremental.
:- table reasonMergeClasses_J/2 as incremental.
%:- table reasonMergeClasses_K/2 as incremental.

reasonMergeClasses(C,M) :-
    or([reasonMergeClasses_B(C,M),
        reasonMergeClasses_C(C,M),
        reasonMergeClasses_D(C,M),
        reasonMergeClasses_E(C,M),
        %reasonMergeClasses_F(C,M),
        reasonMergeClasses_G(C,M),
        reasonMergeClasses_H(C,M),
        reasonMergeClasses_J(C,M)
        %reasonMergeClasses_K(C,M)
      ]).

% Because the classes have already been merged.
%% reasonMergeClasses_A(Method1, Method2) :-
%%     factMergeClasses(Method1, Method2).

% If a constructor and a real destructor share the same vtable, they must be the same class.
% We decided that reasonMergeClassesA was a special case of reasonMergeClassesD.
%% reasonMergeClassesA(Constructor, RealDestructor) :-
%%     factConstructor(Constructor),
%%     factRealDestructor(RealDestructor),
%%     factVFTableWrite(_CInsn, Constructor, ObjectOffset, VFTable),
%%     factVFTableWrite(_DInsn, RealDestructor, ObjectOffset, VFTable),
%%     methodsNOTOnSameClass(Constructor, RealDestructor).

% Because the method occurs in a VFTable of a class that has no base.
%reasonMergeClasses(Constructor, Method) :-
%    % Technically, this might match a destructor which is also correct.
%    factVFTableWrite(_Insn, Constructor, _ObjectOffset, VFTable),
%    find(Constructor, Class),
%    factClassHasNoBase(Class),
%    factVFTableEntry(VFTable, _VFTableOffset, Entry), dethunk(Entry, Method),
%    logtraceln('************** ~Q.', reasonMergeClasses(Constructor, Method)).


% A large portion of this next rule used to be called "certainConflictedVirtualMethod".  Cory
% is very confused about whether that logic is useful on it's own or not, but until there's an
% actual example of where it's independently useful, I'm rolling it into this rule.  Part of
% the problem is that this rule is still dependent on constructors just because we haven't put
% VFTables in the class method list yet...  Wow!  This entire rule was a hot mess, and I'm not
% sure it's even needed.  After more analysis it appears to be a needlessly complicated version
% of reasonMergeClasses_F.

% Because the method occurs in a VFTable of a class that has no base.
reasonMergeClasses_B(BaseClass, MethodClass) :-
    % There's a base class that has no base of it's own.
    factClassHasNoBase(BaseClass),

    % The base class has a vftable
    findVFTable(BaseVFTable, BaseClass),

    % Which has a Method
    factMethodInVFTable(BaseVFTable, _Offset, Method),
    not(purecall(Method)),
    not(factReusedImplementation(Method)),

    % We don't have to check purecall because factMethodInVFTable does already

    % Finally check that the base class and method class are not already the same.
    find(Method, MethodClass),
    iso_dif(BaseClass, MethodClass),

    % Debugging.
    logtraceln('~@~Q.', [not(find(BaseClass, MethodClass)),
                         reasonMergeClasses_B(BaseVFTable, BaseClass, MethodClass, Method)]).

% If an object instance associated with the constructor calls the method, and it has no base
% class, the method must be on exactly the class associated with the constructor.  Wrong!  What
% we really mean is that it cannot be on the classes derived from this constructor, because
% base classes can't call derived methods, and if the constructor itself has no base class
% then...  It's either on exactly that class or the class embedded at offset zero.  For this
% rule to be correct we also need to exclude embedded objects at offset zero.  There's still
% confusion about whether we already know whether it's embedded or
% PAPER: Merging-2
reasonMergeClasses_C(Class, ExistingClass) :-
    factClassCallsMethod(Class, Method),
    not(purecall(Method)), % Never merge purecall methods into classes.
    % If we have no bases, it can't be on a base class.
    factClassHasNoBase(Class),
    % And if there's no object (embedded or base?) at offset zero...
    not(factObjectInObject(Class, _0InnerClass, 0)),

    find(Method, ExistingClass),
    iso_dif(Class, ExistingClass),
    % Confusingly, the method's class must also have no base and no object at offset zero,
    % because the method being called could actually be the base class method...
    factClassHasNoBase(ExistingClass),
    not(factObjectInObject(ExistingClass, _0InnerClass, 0)),

    % Debugging
    logtraceln('~@~Q.', [not(find(Class, ExistingClass)),
                         reasonMergeClasses_C(Class, ExistingClass, Method)]).

% If there are two implementations of the constructor on the same class, they should be merged
% into a single class.  For example Cls1(int x) and Cls1(char y).  When the class has virtual
% methods, this case can be easily detected by observing that the same VFTable is written into
% offset zero of the object.  Unfortunately, the inlining of base class constructors can
% confuse this simple rule, because there is more than one VFTableWrite in the constructor (one
% for this class and one for the inlined base class).  The solution is to block this rule from
% applying in the cases where the VFTable is overwritten (the VFTable from the inlined base
% class constructor).
% PAPER: Merging-1
% ED_PAPER_INTERESTING
reasonMergeClasses_D(Class1, Class2) :-
    % We've been back and forth several times about whether the object offset that the VFTable
    % address is written into should bound to zero or not.  Cory currently believes that while
    % the rule _might_ apply in cases where the offset is non-zero, the obvious case occurs
    % when the offset is zero.  Instances of object embedding at non-zero offsets might
    % coincidentally be unrelated classes that happen to embed something at the same offset.
    % Instances of multiple inheritance should always be accompanied by a VFTable at offset
    % zero that will trigger the rule.  The interesting case is when our knowledge is
    % imperfect because the VFTableWrite at offset zero has not been proven yet.  In those
    % cases it's unclear if a weaker restriction on ObjectOffset would be helpful.
    ObjectOffset = 0,

    % Find two different methods that both install the same VFTable at the same offset.
    factVFTableWrite(Insn1, Method1, ObjectOffset, VFTable),

    % Finally there's what we now think is an optimization and inlining problem where the only
    % VFTable mentioned in the deleting destructor is a base class' VFTable.  This presumably
    % occurs because the base class destructor was inlined, and the compiler detected the
    % overwrite of the current class' VFTable with the base class' VFTable and optimized away
    % the currrent class' VFTable write.  If this same situation occurred in the constructor,
    % it would not affect this rule, because the VFTable write that was kept was the correct
    % one.  Therefore this logic only applies to destructors.  This problem is demonstrated by
    % 2010/Lite/oo bad_cast at 0x404046 and by codecvt at 0x402249.  Cory has tried several
    % variations of this clause, and sadly many produce different results.
    factConstructor(Method1),

    % Neither VFTable write may be overwritten by any other VFTable.  Use the unproven
    % possibleVFTableOverwrite facts here, because this is an exception to the rule, and we may
    % not have yet proven the pre-requisites to know that the overwrites are proven.  But we
    % should not merge classes until we're sure that this exception does NOT apply!
    % Unfortunately, because there's no way to "disprove" the possible facts, we'll never apply
    % this rule if the possibilty of an exception exists.  That's ok because we can always
    % merge for other proven reasons, or guess that this is a legitimate class merge.
    not(possibleVFTableOverwrite(Insn1, _OtherInsn2, Method1, ObjectOffset, VFTable, _OtherVFTable1)),

    factVFTableWrite(Insn2, Method2, ObjectOffset, VFTable),
    % Just to block the silliness of picking the same method as early as possible.
    iso_dif(Method1, Method2),
    % Method1 and Method2 cannot be purecall already (due to factVFTableWrite)

    factConstructor(Method2),

    not(possibleVFTableOverwrite(Insn2, _OtherInsn3, Method2, ObjectOffset, VFTable, _OtherVFTable2)),

    % And the existing classes are not the same already, which is obviously wrong...
    % ejs notes that nothing before this point depends on class membership...
    find(Method1, Class1),
    find(Method2, Class2),
    iso_dif(Class1, Class2),

    % Also ensure that the two methods not in a class relationship already.  Merging them would
    % ultimately result in merging a class with it's own ancestor.
    not((
               reasonClassRelationship(Class1, Class2);
               reasonClassRelationship(Class2, Class1)
       )),

    % Debugging
    logtraceln('~@~Q.', [not(find(Class1, Class2)),
                         reasonMergeClasses_D(Method1, Method2, Class1, Class2)]).

% The constructors are certain to be on the exact same class.  The reasoning is that if there's
% two known classes, and they're both a base class of a single derived class (at the same
% offset) then the two base classes must be same class.  I think this is another way of saying
% a class can't inherit from the same base class twice, which I think is true. Also see the
% inverse rule under reasonNOTMergeClasses.
% PAPER: Merging-4
reasonMergeClasses_E(Class1, Class2) :-
    factDerivedClass(DerivedClass, Class1, ObjectOffset),
    factDerivedClass(DerivedClass, Class2, ObjectOffset),
    iso_dif(Class1, Class2),

    % Debugging
    logtraceln('~@~Q.', [not(find(Class1, Class2)),
                         reasonMergeClasses_E(DerivedClass, ObjectOffset, Class1, Class2)]).

% ejs 9/22/20 Disabled because it's a redundant version of _B
% Because the Method2 appears in VFTable assocated with a class, and that class has no base, so
% all methods in the VFTable must be on the class.
% PAPER: Merging-16
% Ed comment: This rule seems too specialized. Another way of thinking about this rule is that any method in a virtual function table is on the class or its ancestor.  If there is no base, then obviously the method is on the class itself.
% ED_PAPER_INTERESTING
%% reasonMergeClasses_F(Class1, Class2) :-
%%     % Start with a method associated with a primary VFTable (offset zero).
%%     findVFTable(VFTable, 0, Class1),
%%     % There's a second method in that VFTable.
%%     factVFTableEntry(VFTable, _VFTableOffset, Entry),
%%     dethunk(Entry, Method2),
%%     % Method1 cannot be purecall already because of factVFTableWrite().
%%     not(purecall(Entry)), % Never merge purecall methods into classes.
%%     not(purecall(Method2)), % Never merge purecall methods into classes.
%%     % If the VFTable class has no base, the method must be on the class.
%%     factClassHasNoBase(Class1),
%%     find(Method2, Class2),
%%     iso_dif(Class1, Class2),
%%     % Debugging
%%     logtraceln('~@~Q.', [not(find(Class1, Class2)),
%%                          reasonMergeClasses_F(Method2, VFTable, Class1, Class2)]).

% Because the symbols tell us they're the same class.
% PAPER: XXX Symbols
reasonMergeClasses_G(Class1, Class2) :-
    symbolClass(Method1, _MangledName1, ClassName, _MethodName1),
    symbolClass(Method2, _MangledName2, ClassName, _MethodName2),
    iso_dif(Method1, Method2),
    find(Method1, Class1),
    find(Method2, Class2),
    iso_dif(Class1, Class2),
    % Debugging
    logtraceln('~@~Q.', [not(find(Class1, Class2)),
                         reasonMergeClasses_G(Method1, Method2, ClassName, Class1, Class2)]).

% Because additional methods in our VFTable must be ours.
% PAPER: Merging-17
% ED_PAPER_INTERESTING
reasonMergeClasses_H(DerivedClass, MethodClass) :-
    % There's a derived and base class, each with vftables.
    factDerivedClass(DerivedClass, BaseClass, _ObjectOffset),

    % This rule doesn't work when there's multiple inheritance because there are multiple base
    % VFTables in the Derived class, and using the size of one of them is incorrect.  We really
    % need to sum the sizes of the base class vftables, be confident in their layout order, and
    % no that there aren't any other complexities involving multiple inheritance.  In the mean
    % time, just disable this rule where there's more than one base class.
    not((factDerivedClass(DerivedClass, OtherBase, _OtherOffset), iso_dif(OtherBase, BaseClass))),

    findVFTable(DerivedVFTable, 0, DerivedClass),
    findVFTable(BaseVFTable, 0, BaseClass),
    % We know the maximum size of the base vftable.
    factVFTableSizeLTE(BaseVFTable, BaseSize),
    % There's an entry in the derived vftable that's to big to be in the base vftable.
    factVFTableEntry(DerivedVFTable, VOffset, Method),
    not(purecall(Method)),
    not(factReusedImplementation(Method)),
    VOffset > BaseSize,
    find(Method, MethodClass),
    iso_dif(DerivedClass, MethodClass),
    % Debugging
    logtraceln('~@~Q.', [not(find(DerivedClass, MethodClass)),
                         reasonMergeClasses_H(BaseVFTable, DerivedVFTable, BaseSize, VOffset,
                                              Method, BaseClass, DerivedClass, MethodClass)]).

% Sometimes a class may have multiple vftables that we know are on the same class through RTTI.
% But we may not be able to connect them to any methods through reasonVFTableBelongsToClass.
% This rule lets them be merged.
reasonMergeClasses_J(VFTable1Class, VFTable2Class) :-
    rTTITDA2VFTable(TDA, VFTable1),
    find(VFTable1, VFTable1Class),

    rTTITDA2VFTable(TDA, VFTable2),
    find(VFTable2, VFTable2Class),

    iso_dif(VFTable1Class, VFTable2Class),

    logtraceln('~@~Q.', [not(find(VFTable1Class, VFTable2Class)),
                         reasonMergeClasses_J(TDA, VFTable1, VFTable2, VFTable1Class, VFTable2Class)]).

% This rule says that if a constructor installs a single VFTable, then any method in that VFTable
% must belong to that VFTable's class.

%% ejs 8/29/20
%% I think this may only be true for constructors.
%% The method is 0x40228c in ooex_vs2010/Lite/oo.exe.  According to ground truth it is on std::basic_ios:

%% groundTruth(0x40228c, 'std::basic_ios<char, struct std::char_traits<char> >', '~basic_ios', method, realDestructor, linked, public, virtual, '__thiscall').

%% But look at the implementation of the function:

%%                              LAB_0040228c                                    XREF[1]:     004113c3(j)
%%         0040228c 8b ff           MOV        EDI,EDI
%%         0040228e 51              PUSH       ECX
%%         0040228f c7 01 84        MOV        dword ptr [ECX],std::ios_base::vftable           =
%%                  23 41 00
%%         00402295 e8 6f 1a        CALL       std::ios_base::_Ios_base_dtor                    void _Ios_base_dtor(ios_base * p
%%                  00 00
%%         0040229a 59              POP        ECX
%%         0040229b c3              RET

%% ejs 10/18/20: I don't think this rule is correct at all.

%% Looking back at my vftable installation table for inheritance 
%% https://docs.google.com/spreadsheets/d/1Sglpf0HT363kH09jmpx0tYHvuTvJgRTEsu7x0sj-QAA/edit#gid=1459733299
%%  and looking at which cases there can be a single vftable installed by
%% a constructor...

%% - When optimization is off, the derived vftable will always be the only
%% vftable installed.
%% - When optimization is on, if one vftable is installed, it will be the
%% derived vftable.

%% (Obviously mergeClasses_K is not true for derived vftables.)

%% For destructors:

%% - When optimization is off, only the derived vftable is installed.
%% - When optimization is on, if one vftable is installed, it will be the
%% base vftable.

%% So this rule is clearly wrong in the presence of derived classes.  And
%% even if the base vftable is installed, that doesn't guarantee the base
%% class has no bases.

%% reasonMergeClasses_K(MethodClass, VFTClass) :-
%%     factVFTableWrite(_Insn1, Method, 0, VFTable1),
%%     factConstructor(Method),
%%     forall(factVFTableWrite(_Insn2, Method, 0, VFTable2), VFTable1 = VFTable2),
%%     find(VFTable1, VFTClass),
%%     find(Method, MethodClass),

%%     iso_dif(MethodClass, VFTClass),

%%     logtraceln('~@~Q.', [not(find(MethodClass, VFTClass)),
%%                          reasonMergeClasses_K(MethodClass, VFTClass)]).

% Implement: Because they share a method and neither of them have base classes.  This may be
% needed to ensure that we actually merge the classes.

% Implement: Two object instances constructed with different constructors that both destruct
% using the same real destructor must be the same class, because there can only be one real
% destructor per class.

% --------------------------------------------------------------------------------------------
:- table reasonNOTMergeClasses/2 as incremental.

:- table reasonNOTMergeClasses_A/2 as incremental.
%:- table reasonNOTMergeClasses_B/2 as incremental.
:- table reasonNOTMergeClasses_C/2 as incremental.
%:- table reasonNOTMergeClasses_D/2 as incremental.

% trigger
%:- table reasonNOTMergeClasses_E/6 as incremental.
:- table reasonNOTMergeClasses_F/2 as incremental.
:- table reasonNOTMergeClasses_G/2 as incremental.
%:- table reasonNOTMergeClasses_H/2 as incremental.
:- table reasonNOTMergeClasses_I/2 as incremental.
:- table reasonNOTMergeClasses_J/2 as incremental.
:- table reasonNOTMergeClasses_K/2 as incremental.
:- table reasonNOTMergeClasses_L/2 as incremental.

% trigger
%:- table reasonNOTMergeClasses_M/4 as incremental.
% trigger
%:- table reasonNOTMergeClasses_N/4 as incremental.

:- table reasonNOTMergeClasses_O/2 as incremental.
:- table reasonNOTMergeClasses_P/2 as incremental.
:- table reasonNOTMergeClasses_Q/2 as incremental.
:- table reasonNOTMergeClasses_Qhelper/2 as incremental.
:- table reasonNOTMergeClasses_R/2 as incremental.

reasonNOTMergeClasses(M1,M2) :-
    reasonNOTMergeClasses_A(M1,M2).
reasonNOTMergeClasses(M1,M2) :-
    reasonNOTMergeClasses_new(M1,M2).

reasonNOTMergeClasses_new(M1,M2) :-
    %logwarnln('Recomputing reasonNOTMergeClasses...'),
    or([reasonNOTMergeClasses_J(M1,M2),
        %reasonNOTMergeClasses_B(M1,M2),
        reasonNOTMergeClasses_C(M1,M2),
        %reasonNOTMergeClasses_D(M1,M2),
        % _E is now handled in trigger.pl
        %reasonNOTMergeClasses_E(M1,M2),
        reasonNOTMergeClasses_F(M1,M2),
        reasonNOTMergeClasses_G(M1,M2),
        %reasonNOTMergeClasses_H(M1,M2),
        reasonNOTMergeClasses_I(M1,M2),
        reasonNOTMergeClasses_K(M1,M2),
        reasonNOTMergeClasses_L(M1,M2),
        % _M is now handled in trigger.pl
        %reasonNOTMergeClasses_M(M1,M2),
        % _N is now handled in trigger.pl
        %reasonNOTMergeClasses_N(M1,M2),
        reasonNOTMergeClasses_O(M1,M2),
        reasonNOTMergeClasses_P(M1,M2),
        % _Q is now handled in trigger.pl
        %reasonNOTMergeClasses_Q(M1,M2)
        reasonNOTMergeClasses_R(M1,M2)
      ]).

% Because it's already true.
reasonNOTMergeClasses_A(Class1, Class2) :-
    dynFactNOTMergeClasses(Class1, Class2).

% Classes can't be their own bases.
% PAPER: Merging-5
% PAPER: XXX Should be a sanity check?
% XXX: Isn't this a special case of reasonNOTMergeClasses_J?
%% reasonNOTMergeClasses_B(DerivedClass, BaseClass) :-
%%     factDerivedClass(DerivedClass, BaseClass, _ObjectOffset),
%%     % Debugging
%%     logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(DerivedClass, BaseClass)),
%%                          reasonNOTMergeClasses_B(DerivedClass, BaseClass)]).

% Any method on both base and derived is not on the derived class.  They don't have to be
% virtual methods.
% PAPER: Merging-6
% ED_PAPER_INTERESTING
reasonNOTMergeClasses_C_asymmetric(DerivedClass, MethodClass) :-
    factDerivedClass(DerivedClass, BaseClass, _ObjectOffset),
    factClassCallsMethod(DerivedClass, Method),
    factClassCallsMethod(BaseClass, Method),
    find(Method, MethodClass),
    iso_dif(DerivedClass, MethodClass),

    % Turns out that deleting destructors is a common case where multiple implementations are
    % at the same address, and without the guard, the rule results in methods be forced into
    % the wrong classes.  See the case of 0x403659 in Lite/poly, where the vector deleting
    % destructor for std::out_of_range appears in it's PARENT virtual function table of
    % std::logic_error.   So this fix works, but technically for the wrong reasons.
    % not(factDeletingDestructor(Method)),

    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(DerivedClass, MethodClass)),
                         reasonNOTMergeClasses_C_asymmetric(Method, BaseClass,
                                                            DerivedClass, MethodClass)]).

% Handle the complicated asymmetry of reasonNOTMergeClasses_C_asymmetric, so that we always
% return Class1 < Class2.
reasonNOTMergeClasses_C(Class1, Class2) :-
    ((reasonNOTMergeClasses_C_asymmetric(Class1, Class2), Class1 < Class2);
     (reasonNOTMergeClasses_C_asymmetric(Class2, Class1), Class1 < Class2)),

    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1, Class2)),
                         reasonNOTMergeClasses_C(Class1, Class2)]).

% Any two constructors that write _different_ vftables into the same offets in their objects
% cannot be the same class.
% PAPER: Merging-7
% ED_PAPER_INTERESTING
reasonNOTMergeClasses_E(Class1, Class2, Insn1, Method1, 0, VFTable1) :-
    false,
    % Two VFTables are written into the zero object offset in two different methods.  The
    % sterotypical case is of course two compeltely unrelated classes.  This rule applies
    % equally to constructors and destructors.  There were problems in Lite/oo with 0x402766 (a
    % deleting destructor) and 0x40247e (a vbase destructor) when this rule was applied to
    % arbitrary offsets.  It's a little unclear whether the better fix would be to permit
    % arbitrary offsets and then filter the destructor specific case as an exception.  The case
    % is related to the counter example blocked by checking for the opposite VFTableWrites.
    factVFTableWrite(Insn1, Method1, 0, VFTable1),
    factVFTableWrite(_Insn2, Method2, 0, VFTable2),
    iso_dif(VFTable1, VFTable2),
    find(Method1, Class1),
    find(Method2, Class2),
    % Those methods cannot be on the same class.
    iso_dif(Class1, Class2),
    % <Outdated>This rule handles symmetry correctly, so adding this constraint causes the rule
    % to fire twice, but reduces the number of NOTMergeClass facts created by this
    % rule.</Outdated>
    % Because this is called from a trigger rule, the above comment is no longer true.
    % <Outdated>Class1 < Class2,</Outdated>
    % iso_dif(Method1, Method2),
    % But one counter example that we need to protect against is the inlining of base class
    % VFTable writes.  The intention here is very similar to factVFTableOverwrite, but without
    % the complications of caring which value overwrote which other value.
    not((factVFTableWrite(_Insn3, Method1, 0, VFTable2))),
    not((factVFTableWrite(_Insn4, Method2, 0, VFTable1))),
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1, Class2)),
                         reasonNOTMergeClasses_E(Class1, Class2)]).

% The constructors are certain to not be on the exact same class.  The reasoning is the inverse
% of the "classes can't inherit from the same class twice" rules above.  If that rule is
% correct, so is this one.
% PAPER: Merging-8
% ED_PAPER_INTERESTING
reasonNOTMergeClasses_F(Class1, Class2) :-
    factDerivedClass(DerivedClass, Class1, ObjectOffset1),
    factDerivedClass(DerivedClass, Class2, ObjectOffset2),
    % This rule handles symmetry correctly, so adding this constraint causes the rule to fire
    % twice, but reduces the number of NOTMergeClass facts created by this rule.
    Class1 < Class2,
    iso_dif(ObjectOffset1, ObjectOffset2),
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1, Class2)),
                         reasonNOTMergeClasses_F(DerivedClass, ObjectOffset1,
                                                 ObjectOffset2, Class1, Class2)]).

% The constructors are certain to not be on the exact same class.  The reasoning is that one
% class is inside the other.  These rules are little suspect because they probably really
% indicate that the classes should have been merged earlier (before the conclusion was reached
% that one was inside the other), but these rules are valid regardless, and should prevent us
% from generating more nonsense on the decision branch where we concluded that one class was
% inside the other.  Hopefully we'll backtrack to a better solution.
% PAPER: Merging-9
reasonNOTMergeClasses_G(Class1, Class2) :-
    factObjectInObject(A, B, _Offset),
    % Handle the asymmetry of ObjectinObject so that this rule always returns Class1 < Class2.
    sort_tuple((A, B), (Class1, Class2)),
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1, Class2)),
                         reasonNOTMergeClasses_G(Class1, Class2)]).

% PAPER: Merging-9
%% reasonNOTMergeClasses_H(Class1, Class2) :-
%%     find(_Constructor1, Class1),
%%     find(_Constructor2, Class2),
%%     factObjectInObject(Class2, Class1, _Offset),
%%     % Debugging
%%     not(dynFactNOTMergeClasses(Class1, Class2)),
%%     logtraceln('~Q.', reasonNOTMergeClasses_H(Class1, Class2)).

% Because RTTI tells us that they're different classes.
% XXX PAPER: RTTI
reasonNOTMergeClasses_I(Class1, Class2) :-
    rTTIEnabled,
    rTTIValid,
    rTTITDA2Class(TDA1, Class1),
    rTTITDA2Class(TDA2, Class2),
    iso_dif(TDA1, TDA2),
    % This shouldn't be needed unless rTTITDA2Class() is misbehaving!
    % This rule handles symmetry correctly, so adding this constraint causes the rule to fire
    % twice, but reduces the number of NOTMergeClass facts created by this rule.
    Class1 < Class2,
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1, Class2)),
                         reasonNOTMergeClasses_I(TDA1, TDA2, Class1, Class2)]).

% PAPER: Merging-13
% ED_PAPER_INTERESTING
reasonNOTMergeClasses_J(Class1, Class2) :-
    reasonClassRelationship(A, B),
    % Handle asymmtery in reasonClassRelationship, so we always return Class1 < Class2.
    sort_tuple((A, B), (Class1, Class2)),
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1, Class2)),
                         reasonNOTMergeClasses_J(Class1, Class2)]).

% Because symbols tell us so.
% PAPER: XXX?
reasonNOTMergeClasses_K(Class1, Class2) :-
    symbolClass(Method1, _MangledName1, ClassName1, _MethodName1),
    symbolClass(Method2, _MangledName2, ClassName2, _MethodName2),
    iso_dif(Method1, Method2),
    iso_dif(ClassName1, ClassName2),
    find(Method1, Class1),
    find(Method2, Class2),

    % This rule handles symmetry correctly, so adding this constraint causes the rule to fire
    % twice, but reduces the number of NOTMergeClass facts created by this rule.
    Class1 < Class2,
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1, Class2)),
                         reasonNOTMergeClasses_K(Class1, Class2)]).

% Because both classes already have a real destructor.
% PAPER: Merging-14
% PAPER: XXX Shouldn't this be a sanity check?
reasonNOTMergeClasses_L(Class1, Class2) :-
    factRealDestructor(RealDestructor1),
    factRealDestructor(RealDestructor2),
    iso_dif(RealDestructor1, RealDestructor2),
    find(RealDestructor1, Class1),
    find(RealDestructor2, Class2),
    % This rule handles symmetry correctly, so adding this constraint causes the rule to fire
    % twice, but reduces the number of NOTMergeClass facts created by this rule.
    Class1 < Class2,
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1, Class2)),
                         reasonNOTMergeClasses_L(Class1, Class2)]).

% Because the sizes are incomaptible.
% PAPER: Class size constraints
% Called by trigger.pl
reasonNOTMergeClasses_M(Class1, Class2, GTESize, LTESize) :-
    factClassSizeGTE(Class1, GTESize),
    factClassSizeLTE(Class2, LTESize),
    % This rule handles symmetry correctly, so adding this constraint causes the rule to fire
    % twice, but reduces the number of NOTMergeClass facts created by this rule.
    Class1 < Class2,
    LTESize < GTESize,
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1, Class2)),
                         reasonNOTMergeClasses_M(Class1, Class2, GTESize, LTESize)]).

% Because the sizes are incompatible.
% PAPER: Class size constraints
% Called by trigger.pl
% Cory notes: To reduce the number of number of these that are generated needlessly, we might
% want to add a contraint requiring that there be a reason to think that the classes were
% candidates for a merge in the first place.  The current rule simply looks at sizes and
% nothing else.  As a result this is the largest source of factNOTMergeClass facts.
reasonNOTMergeClasses_N(Class1, Class2, GTESize, LTESize) :-
    factClassSizeLTE(Class1, LTESize),
    factClassSizeGTE(Class2, GTESize),
    % This rule handles symmetry correctly, so adding this constraint causes the rule to fire
    % twice, but reduces the number of NOTMergeClass facts created by this rule.
    Class1 < Class2,
    GTESize > LTESize,
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1, Class2)),
                         reasonNOTMergeClasses_N(Class1, Class2, GTESize, LTESize)]).

% Because the method accesses members that aren't there.
% PAPER: Merging-15
% ED_PAPER_INTERESTING
% Cory notes that this doesn't fire in the ooex test suite.   Is it implied by _N?
reasonNOTMergeClasses_O(Class1Sorted, Class2Sorted) :-
    % There's a class where we know the maximum size.
    factClassSizeLTE(Class1, Size1),
    % That calls a method (not really needed but avoids worthless conclusions?)
    factClassCallsMethod(Class1, Method),
    find(Method, Class2),
    iso_dif(Class1, Class2),
    % Handle symmetry
    sort_tuple((Class1, Class2), (Class1Sorted, Class2Sorted)),
    % The method accesses a member too large for the class.
    validMethodMemberAccess(_Insn, Method, MemberOffset, MemberSize),
    Size2 is MemberSize + MemberOffset,
    Size2 > Size1,
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1Sorted, Class2Sorted)),
                         reasonNOTMergeClasses_O(Size1, Size2, Class1Sorted, Class2Sorted)]).

% Because we call a constructor or destructor on part of our object.
% PAPER: ??? NEW!
% The reasoning is here is basically that we can't contain ourselves, but passing an offset to
% ourself would imply exactly that.  It's not obvious that the merger is blocked by any other
% rule at present.
reasonNOTMergeClasses_P(Class1Sorted, Class2Sorted) :-
    validFuncOffset(_Insn, Caller, Method, Offset),
    Offset > 0,
    find(Method, Class1),
    find(Caller, Class2),
    iso_dif(Class1, Class2),
    factMethod(Caller),
    factMethod(Method),
    iso_dif(Method, Caller),
    (factConstructor(Method);
     (factDeletingDestructor(Method), not(factRealDestructor(Caller)));
     factRealDestructor(Method)),
    % Handle symmetry
    sort_tuple((Class1, Class2), (Class1Sorted, Class2Sorted)),
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1Sorted, Class2Sorted)), reasonNOTMergeClasses_P(Caller, Method, Class1Sorted, Class2Sorted)]).

% This helper is separated out because it should never need to be recomputed.
reasonNOTMergeClasses_Qhelper(MethodWithSymbol, OtherMethod, ClassName) :-
    % There is a method whose symbol tells us it is on ClassName
    symbolClass(MethodWithSymbol, _MangledName1, ClassName, _MethodName1),

    % type_info is known to not obey this...
    ExceptionClasses=['type_info'],
    not(member(ClassName, ExceptionClasses)),

    % There is another method who does not have a symbol that identifies it as on ClassName
    % ejs 9/2/2020 We could use find/2 here but by using factMethod/1 this table will almost never be recomputed
    factMethod(OtherMethod),
    not(symbolClass(OtherMethod, _MangledName2, ClassName, _MethodName2)).

% If one method in a class has a symbol, all other methods in the class must also have a symbol
% for the same class.  This is tabled separately so that it can call find/2 and be recomputed
% when that changes.
reasonNOTMergeClasses_Q(Class1Sorted, Class2Sorted, Method1, Method2) :-
    reasonNOTMergeClasses_Qhelper(Method1, Method2, ClassName),

    find(Method1, Class1),
    find(Method2, Class2),

    % Handle symmetry
    sort_tuple((Class1, Class2), (Class1Sorted, Class2Sorted)),
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1Sorted, Class2Sorted)),
                         reasonNOTMergeClasses_Q(Class1Sorted, Class2Sorted, ClassName)]).

% If a derived class calls a method, and that method installs the derived class' vftable, then
% the called method cannot be on the base class.
reasonNOTMergeClasses_R(Class1Sorted, Class2Sorted) :-
    % A derived class calls a method
    factClassCallsMethod(DerivedClass, CalledMethod),
    not(purecall(CalledMethod)), % Never merge purecall methods into classes.
    factDerivedClass(DerivedClass, BaseClass, Offset),
    find(CalledMethod, CalledClass),

    % The CalledMethod installs a VFTable on the derived class
    find(DerivedVFTable, DerivedClass),
    factVFTableWrite(_Insn, CalledMethod, Offset, DerivedVFTable),

    % Handle symmetry
    sort_tuple((BaseClass, CalledClass), (Class1Sorted, Class2Sorted)),
    % Debugging
    logtraceln('~@~Q.', [not(dynFactNOTMergeClasses(Class1Sorted, Class2Sorted)),
                         reasonNOTMergeClasses_R(Class1Sorted, Class2Sorted, DerivedClass, BaseClass, Offset)]).

reasonNOTMergeClassesSet(Constructor, Set) :-
    factConstructor(Constructor),
    setof(Method, reasonNOTMergeClasses(Constructor, Method), Set).

% ============================================================================================
% Shared Implementations
% ============================================================================================

% Sometimes multiple functions share the same implementation (address).  This appears to be
% some kind of compiler optimization the occurs when the compiler detects that multiple bits of
% generated code are indentical.  This happens most frequently with deleting destructors but
% also occasionally with other code.  It's unclear if it's always generated code, or whether it
% could happen with user implemented functions as well.  Most of the rule amounts to a specific
% case where a method is "assigned" to two classes.
:- table reasonSharedImplementation/2 as incremental.
reasonSharedImplementation(Method, Class1) :-
    % There are two classes
    factConstructor(Constructor1),
    factConstructor(Constructor2),
    iso_dif(Constructor1, Constructor2),
    factVFTableWrite(_Insn1, Constructor1, _Offset1, VFTable1),
    factVFTableWrite(_Insn2, Constructor2, _Offset2, VFTable2),
    iso_dif(VFTable1, VFTable2),
    factVFTableEntry(VFTable1, _, Entry1),
    factVFTableEntry(VFTable2, _, Entry2),
    % Now that we have thunk data, the real question is:  Do Entry1 and Entry2 differ?
    dethunk(Entry1, Method),
    dethunk(Entry2, Method),
    % Limiting this rule to deleting destructors is a cheap proxy for generated code. :-(
    factDeletingDestructor(Method),
    find(Constructor1, Class1),
    find(Constructor2, Class2),
    iso_dif(Class1, Class2),
    dynFactNOTMergeClasses(Class1, Class2).

% ============================================================================================
% Member assignment
% ============================================================================================

% In this new approach, we'll collect evidence later.

% --------------------------------------------------------------------------------------------
% Tabling this causes failures...
:- table certainMemberOnClass/3 as incremental.

certainMemberOnClass(Class, Offset, Size) :-
    find(Method, Class),
    factMethod(Method),
    validMethodMemberAccess(_Insn, Method, Offset, Size).

certainMemberOnClassSet(Class, Set) :-
    setof(Offset, Size^certainMemberOnClass(Class, Offset, Size), Set).

% --------------------------------------------------------------------------------------------
:- table certainMemberNOTOnExactClass/3 as incremental.

% The member is certain to be NOT on the exact class specified.  This rule is FLAWED!  The
% reasoning is supposed to be that the member is not on the exact class because it is within
% the memory range allocaed to and embedded object or base class (including multiple
% inhertiance).  The flaw in the logic is that it does not account for virtual inheritance
% correctly.  Specfically, the reasonMinimumPossibleClassSize(InnerClass, InnerSize)
% unification fails to reduce InnerSize by the size of the shared virtual grandparent class.
% Currently this results in a fairly rare bug, but it manifests in OOEX8 as an incorrect
% assignment of a class member.  It is believed that we will need virtual base pointer table
% facts to correctly resolve this situation, and we do not currently.
certainMemberNOTOnExactClass(Class, Offset, Size) :-
    certainMemberOnClass(Class, Offset, Size),
    factObjectInObject(Class, InnerClass, InnerOffset),
    Offset >= InnerOffset,
    reasonMinimumPossibleClassSize(InnerClass, InnerSize),
    EndOfInnerObject is InnerOffset + InnerSize,
    Offset < EndOfInnerObject.

% --------------------------------------------------------------------------------------------
:- table certainMemberOnExactClass/3 as incremental.

certainMemberOnExactClass(Class, Offset, Size) :-
    certainMemberOnClass(Class, Offset, Size),
    % Exclude members that are actually on the embedded objects or base classes.
    not(certainMemberNOTOnExactClass(Class, Offset, Size)).

certainMemberOnExactClassSet(Class, Set) :-
    setof(Offset, Size^certainMemberOnExactClass(Class, Offset, Size), Set).

% --------------------------------------------------------------------------------------------

% ============================================================================================
% Rules for class size reasoning.
% ============================================================================================

% --------------------------------------------------------------------------------------------
% The given class is certain to be of this size or greater.  This is the allocation size,
% including any padding, alignment, etc.  It also includes the size of any base classes (since
% they're part of the class).
:- table reasonClassSizeGTE/2 as incremental.

:- table reasonClassSizeGTE_A/2 as incremental.
:- table reasonClassSizeGTE_B/2 as incremental.
:- table reasonClassSizeGTE_C/2 as incremental.
:- table reasonClassSizeGTE_D/2 as incremental.
:- table reasonClassSizeGTE_E/2 as incremental.
:- table reasonClassSizeGTE_F/2 as incremental.
:- table reasonClassSizeGTE_G/2 as incremental.

reasonClassSizeGTE(Class, Size) :-
    %logwarnln('Recomputing reasonClassSizeGTE...'),
    or([reasonClassSizeGTE_A(Class, Size),
        reasonClassSizeGTE_B(Class, Size),
        reasonClassSizeGTE_C(Class, Size),
        reasonClassSizeGTE_D(Class, Size),
        reasonClassSizeGTE_E(Class, Size),
        reasonClassSizeGTE_F(Class, Size),
        reasonClassSizeGTE_G(Class, Size)
      ]).

% Because it is already known to be true.
% PAPER: NA
reasonClassSizeGTE_A(Class, Size) :-
    factClassSizeGTE(Class, Size).

% Because all classes must have a non-negative size.
% PAPER: CSize-0
reasonClassSizeGTE_B(Class, Size) :-
    % Constrain this rule to proven methods/vftables, so we don't go assigning class sizes to
    % methods that aren't even really methods.
    (factMethod(Element); factVFTable(Element)),
    find(Element, Class),
    Size = 0,
    % Debugging
    logtraceln('~@~Q.', [not((factClassSizeGTE(Class, ExistingSize), ExistingSize >= Size)),
                         reasonClassSizeGTE_B(Class, Size)]).

% Because a derived class is always greater than or equal to the size of it's base class.
% Actually, this rule should sum the sizes of all base classes that are known to be different
% from each other -- but that's a bit trickier.
% PAPER: CSize-1
reasonClassSizeGTE_C(Class, Size) :-
    reasonClassRelationship(Class, BaseClass),
    factClassSizeGTE(BaseClass, Size),
    % Debugging
    logtraceln('~@~Q.', [not((factClassSizeGTE(Class, ExistingSize), ExistingSize >= Size)),
                         reasonClassSizeGTE_C(BaseClass, Class, Size)]).

% The given class (associated with the constructor) is certain to be of this exact size.  The
% reasoning is that we're able to track an allocation site with a known size to the constructor
% associated with the class.  There's a small bit of ambiguity about what the compiler will
% generate for arrays of objects and other unusual cases, but this rule is a good start.
% PAPER: CSize-2
% ED_PAPER_INTERESTING
reasonClassSizeGTE_D(Class, Size) :-
    factConstructor(Constructor),
    thisPtrUsage(_, Function, ThisPtr, Constructor),
    thisPtrAllocation(_, Function, ThisPtr, type_Heap, Size),
    % We sometimes get bad (zero) class sizes in allocations.  This should really be fixed in
    % the fact exporter, so that we don't have to deal with it here.
    Size \= 0,
    find(Constructor, Class),
    % ejs 1/5/21: This rule only applies if we know there are no base classes using some of the
    % allocated object's space.
    factClassHasNoBase(Class),
    % Debugging
    logtraceln('~@~Q.', [not((factClassSizeGTE(Class, ExistingSize), ExistingSize >= Size)),
                         reasonClassSizeGTE_D(Class, Size)]).

% The given class is certain to be of this size or greater.  The reasoning for this rule is
% that if we're certain that there's a member at a given offset and size, then the object must
% be larger enough to contain that access.
% PAPER: CSize-3
reasonClassSizeGTE_E(Class, Size) :-
    validMethodMemberAccess(_Insn, Method, MemberOffset, MemberSize),
    findMethod(Method, Class),
    Size is MemberOffset + MemberSize,
    % Debugging
    logtraceln('~@~Q.', [not((factClassSizeGTE(Class, ExistingSize), ExistingSize >= Size)),
                         reasonClassSizeGTE_E(Class, Size)]).

% The given class is certain to be of this size or greater.  The reasoning for this rule is the
% if we're certain that there's a member at a given offset, and that member is certain to be an
% instance of a certain class (either inherited or embedded) the the enclosing class must be
% large enough to accomodate the minimize size of the contained object instance
% PAPER: CSize-4
reasonClassSizeGTE_F(Class, Size) :-
    %% find(_Method, Class),
    factObjectInObject(Class, InnerClass, Offset),
    % Even though Class and InnerClass shouldn't be the same, if they were permitting that in
    % this rule will introduce an endless loop preventing us from reaching sanity checks that
    % would detect the condition, so we need to prtect against it here as well.
    iso_dif(Class, InnerClass),
    factClassSizeGTE(InnerClass, InnerClassSize),
    Size is Offset + InnerClassSize,
    % Debugging
    logtraceln('~@~Q.', [not((factClassSizeGTE(Class, ExistingSize), ExistingSize >= Size)),
                         reasonClassSizeGTE_F(InnerClass, InnerClassSize,
                                              Offset, Class, Size)]).

% Because a virtual function table is installed at a given offset in the object.
% PAPER: CSize-5
reasonClassSizeGTE_G(Class, Size) :-
    factVFTableWrite(_Insn, Method, ObjectOffset, _VFTable),
    find(Method, Class),
    Size is ObjectOffset + 4,
    % Debugging
    logtraceln('~@~Q.', [not((factClassSizeGTE(Class, ExistingSize), ExistingSize >= Size)),
                         reasonClassSizeGTE_G(Class, Size)]).

reasonMinimumPossibleClassSize(Class, Size) :-
    setof(S, factClassSizeGTE(Class, S), Set),
    max_list(Set, Size),
    % This predicate is not tabled, so this log message will be emitted many times.
    % logtraceln('~Q.', reasonMinimumPossibleClassSize(Class, Size)),
    true.

% --------------------------------------------------------------------------------------------
:- table reasonClassSizeLTE/2 as incremental.

% The given class is certain to be of this size or smaller.

:- table reasonClassSizeLTE_A/2 as incremental.
:- table reasonClassSizeLTE_B/2 as incremental.
:- table reasonClassSizeLTE_C/2 as incremental.
:- table reasonClassSizeLTE_D/2 as incremental.

reasonClassSizeLTE(Class, Size) :-
    %logwarnln('Recomputing reasonClassSizeLTE...'),
    or([reasonClassSizeLTE_A(Class, Size),
        reasonClassSizeLTE_B(Class, Size),
        reasonClassSizeLTE_C(Class, Size),
        reasonClassSizeLTE_D(Class, Size)
      ]).

% Because it is already known to be true.
% PAPER: NA
reasonClassSizeLTE_A(Class, Size) :-
    factClassSizeLTE(Class, Size).

% PAPER: CSize-0
reasonClassSizeLTE_B(Class, 0x0fffffff) :-
    factConstructor(Constructor),
    find(Constructor, Class).

% The given class (associated with the constructor) is certain to be of this exact size.  The
% reasoning is that we're able to track an allocation site with a known size to the constructor
% associated with the class.  There's a small bit of ambiguity about what the compiler will
% generate for arrays of objects and other unusual cases, but this rule is a good start.
% PAPER: CSize-2
reasonClassSizeLTE_C(Class, Size) :-
    factConstructor(Constructor),
    find(Constructor, Class),
    thisPtrUsage(_, Function, ThisPtr, Constructor),
    thisPtrAllocation(_, Function, ThisPtr, type_Heap, Size),
    % We sometimes get bad (zero) class sizes in allocations.  This should really be fixed in
    % the fact exporter, so that we don't have to deal with it here.
    Size \= 0,
    logtraceln('~@~Q.', [not((factClassSizeLTE(Class, ExistingSize), ExistingSize =< Size)),
                         reasonClassSizeLTE_C(ThisPtr, Class, Size)]).

% The given class is certain to be of this size or smaller.  The reasoning is that a base class
% must always be smaller than or equal in size to it's derived classes.
% PAPER: CSize-1
reasonClassSizeLTE_D(Class, Size) :-
    reasonClassRelationship(DerivedClass, Class),
    factClassSizeLTE(DerivedClass, Size),
    logtraceln('~@~Q.', [not((factClassSizeLTE(Class, ExistingSize), ExistingSize =< Size)),
                         reasonClassSizeLTE_D(DerivedClass, Class, Size)]).

reasonMaximumPossibleClassSize(Class, Size) :-
    setof(S, factClassSizeLTE(Class, S), Set),
    min_list(Set, Size).

% --------------------------------------------------------------------------------------------
% These rules are intended to make it easier to report the size constraints on a specific
% class.  In most rules it's easier to accumulate a set of non-revocable assertions about the
% minimum and maximum sizes of the classes, but humans like to know just the most recent or
% significant constraint.   Use list_min and list_max to make that prettier.

%% Local Variables:
%% mode: prolog
%% End:
