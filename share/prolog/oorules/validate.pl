% ============================================================================================
% Ground truth validation rules.
% ============================================================================================

:- dynamic groundTruth/9.
:- dynamic finalClass/6.
:- dynamic finalVFTable/5.
:- dynamic finalEmbeddedObject/4.
:- dynamic finalInheritance/5.
:- dynamic finalMemberAccess/4.
:- dynamic finalMember/4.
:- dynamic finalMethodProperty/3.
:- dynamic finalResolvedVirtualCall/3.
:- import maplist/2 from swi.
:- import member/2 from lists.

validateResults :-
    % Write a newline so that our output messages don't get mixed up with XSB's ":-" prompt
    writeln(''),
    validVFTables(ValidVFTableSet),
    validMethods(ValidMethodSet),
    finalVFTables(FinalVFTableSet),
    finalMethods(FinalMethodSet),
    maplistm(correctVFTable, ValidVFTableSet),
    maplistm(missingVFTable, ValidVFTableSet),
    maplistm(extraVFTable, FinalVFTableSet),
    %maplist(validateVFTableMethodAssignments, VFTableSet),

    maplist(correctConstructorProperty, ValidMethodSet),
    maplist(missingConstructorProperty, ValidMethodSet),
    maplist(extraConstructorProperty, FinalMethodSet),

    maplist(correctRealDestructorProperty, ValidMethodSet),
    maplist(missingRealDestructorProperty, ValidMethodSet),
    maplist(extraRealDestructorProperty, FinalMethodSet),

    maplist(correctDeletingDestructorProperty, ValidMethodSet),
    maplist(missingDeletingDestructorProperty, ValidMethodSet),
    maplist(extraDeletingDestructorProperty, FinalMethodSet),

    maplist(correctAnyDestructorProperty, ValidMethodSet),
    maplist(missingAnyDestructorProperty, ValidMethodSet),
    maplist(extraAnyDestructorProperty, FinalMethodSet),

    maplist(correctVirtualProperty, ValidMethodSet),
    maplist(missingVirtualProperty, ValidMethodSet),
    maplist(extraVirtualProperty, FinalMethodSet),

    % Report correct method assignments.
    groundAssignedMethods(GroundAssignedMethodSet),
    maplist(correctAssignedMethod, GroundAssignedMethodSet),
    % Report missing method assignments.
    maplist(missingAssignedMethod, GroundAssignedMethodSet),
    % Report extra method assignments.
    finalAssignedMethods(FinalAssignedMethodSet),
    maplist(extraAssignedMethod, FinalAssignedMethodSet).

addressName(Address, NameOrNone) :-
    groundTruth(Address, _Class, Name, _Type, _OtherType, _Linked, _Scope, _Virtual, _Convention)
    -> NameOrNone=Name; NameOrNone=0.

addressClass(Address, ClassOrNone) :-
    groundTruth(Address, Class, _Name, _Type, _OtherType,_Linked, _Scope, _Virtual, _Convention)
    -> ClassOrNone=Class; ClassOrNone=0.

% --------------------------------------------------------------------------------------------
validVFTable(VFTable) :-
    groundTruth(VFTable, _Class, _Func, table, vftable, linked, _Scope, _Virtual, _Convention).

validVFTables(VFTableSet) :-
    setof([VFTable], validVFTable(VFTable), VFTableSet), !.
validVFTables([]).

finalVFTableShort(VFTable) :-
    finalVFTable(VFTable, _Min, _Max, _RTTI, _Mangled).

finalVFTables(VFTableSet) :-
    setof([VFTable], finalVFTableShort(VFTable), VFTableSet), !.
finalVFTables([]).

% --------------------------------------------------------------------------------------------
correctVFTable(VFTable) :-
    groundTruth(VFTable, Class, _Func, table, vftable, linked, _Scope, _Virtual, _Convention),
    finalVFTable(VFTable, _Min, _Max, _RTTI, _Mangled),
    write('Correct vftable: '), writeHex(VFTable),
    write(' Class='), writeln(Class)
    % We want no backtracking and no failure.
    ; true.

missingVFTable(VFTable) :-
    groundTruth(VFTable, Class, _Func, table, vftable, linked, _Scope, _Virtual, _Convention),
    not(finalVFTable(VFTable, _Min, _Max, _RTTI, _Mangled)),
    write('Missing vftable: '), writeHex(VFTable),
    write(' Class='), writeln(Class)
    % We want no backtracking and no failure.
    ; true.

extraVFTable(VFTable) :-
    finalVFTable(VFTable, _Min, _Max, _RTTI, Mangled),
    not(groundTruth(VFTable, _Class, _Func, table, vftable, linked, _Scope, _Virtual, _Convention)),
    write('Extra vftable: '), writeHex(VFTable),
    write(' Mangled='), writeln(Mangled)
    % We want no backtracking and no failure.
    ; true.

% --------------------------------------------------------------------------------------------

groundAssignedMethod(Method, Class) :-
    groundTruth(Method, Class, _Func, method, _MType, linked, _Scope, _Virtual, _Convention).

groundAssignedMethods(Set) :-
    setof([Method, Class], groundAssignedMethod(Method, Class), Set), !.
groundAssignedMethods([]).


finalAssignedMethod(Method, Class) :-
    finalClass(ID, _VFTable, _Min, _Max, _RealDestructor, Methods),
    member(Method, Methods),
    groundTruth(ID, Class, _Func, method, _MType, linked, _Scope, _Virtual, _Convention).

finalAssignedMethods(Set) :-
    setof([Method, Class], finalAssignedMethod(Method, Class), Set), !.
finalAssignedMethods([]).

correctAssignedMethod(GroundMethodClassPair) :-
    % Calling this every time seems very inefficient.  Maybe table or redesign?
    finalAssignedMethods(FinalAssignedMethods),
    % The real rule is to simply compare the lists.
    member(GroundMethodClassPair, FinalAssignedMethods),
    basics:ith(1, GroundMethodClassPair, Method),
    basics:ith(2, GroundMethodClassPair, Class),
    addressName(Method, MName),
    write('Correct method assignment: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

extraAssignedMethod(FinalMethodClassPair) :-
    % Calling this every time seems very inefficient.  Maybe table or redesign?
    groundAssignedMethods(GroundAssignedMethods),
    % The real rule is to simply compare the lists.
    not(member(FinalMethodClassPair, GroundAssignedMethods)),
    basics:ith(1, FinalMethodClassPair, Method),
    basics:ith(2, FinalMethodClassPair, Class),
    addressName(Method, MName),
    write('Extra method assignment: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

missingAssignedMethod(GroundMethodClassPair) :-
    % Calling this every time seems very inefficient.  Maybe table or redesign?
    finalAssignedMethods(FinalAssignedMethods),
    % The real rule is to simply compare the lists.
    not(member(GroundMethodClassPair, FinalAssignedMethods)),
    basics:ith(1, GroundMethodClassPair, Method),
    basics:ith(2, GroundMethodClassPair, Class),
    addressName(Method, MName),
    write('Missing method assignment: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

% --------------------------------------------------------------------------------------------
validMethod(Method) :-
    groundTruth(Method, _Class, _Func, method, _MType,linked, _Scope, _Virtual, _Convention).

validMethods(MethodSet) :-
    setof(Method, validMethod(Method), MethodSet), !.
validMethods([]).

finalMethod(Method) :-
    finalMethodProperty(Method, _, _).
finalMethod(Method) :-
    finalClass(_ID, _VFTable, _Min, _Max, _RealDestructor, Methods),
    member(Method, Methods).

finalMethods(MethodSet) :-
    setof(Method, finalMethod(Method), MethodSet), !.
finalMethods([]).

% --------------------------------------------------------------------------------------------
correctConstructorProperty(Method) :-
    groundTruth(Method, Class, _Func, method, constructor, _Linkage, _Scope, _Virtual, _Convention),
    finalMethodProperty(Method, constructor, certain),
    write('Correct constructor property: '), writeHex(Method),
    write(' Class='), writeln(Class)
    % We want no backtracking and no failure.
    ; true.

missingConstructorProperty(Method) :-
    groundTruth(Method, Class, _Func, method, constructor, _Linkage, _Scope, _Virtual, _Convention),
    not(finalMethodProperty(Method, constructor, certain)),
    write('Missing constructor property: '), writeHex(Method),
    write(' Class='), writeln(Class)
    % We want no backtracking and no failure.
    ; true.

extraConstructorProperty(Method) :-
    finalMethodProperty(Method, constructor, certain),
    not(groundTruth(Method, _Class, _Func, method, constructor, _Linkage, _Scope, _Virtual, _Convention)),
    addressName(Method, MName),
    addressClass(Method, Class),
    write('Extra constructor property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

correctDeletingDestructorProperty(Method) :-
    groundTruth(Method, Class, MName, method, deletingDestructor, _Linkage, _Scope, _Virtual, _Convention),
    finalMethodProperty(Method, deletingDestructor, certain),
    write('Correct deleting destructor property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

missingDeletingDestructorProperty(Method) :-
    groundTruth(Method, Class, MName, method, deletingDestructor, _Linkage, _Scope, _Virtual, _Convention),
    not(finalMethodProperty(Method, deletingDestructor, certain)),
    write('Missing deleting destructor property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

extraDeletingDestructorProperty(Method) :-
    finalMethodProperty(Method, deletingDestructor, certain),
    not(groundTruth(Method, _Class, _Func, method, deletingDestructor, _Linkage, _Scope, _Virtual, _Convention)),
    addressName(Method, MName),
    addressClass(Method, Class),
    write('Extra deleting destructor property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

correctAnyDestructorProperty(Method) :-
    (groundTruth(Method, Class, MName, method, deletingDestructor, _Linkage, _Scope, _Virtual, _Convention);
     groundTruth(Method, Class, MName, method, realDestructor, _Linkage, _Scope, _Virtual, _Convention)),
    (finalMethodProperty(Method, deletingDestructor, certain);
     finalMethodProperty(Method, realDestructor, certain)),
    write('Correct any destructor property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

missingAnyDestructorProperty(Method) :-
    (groundTruth(Method, Class, MName, method, deletingDestructor, _Linkage, _Scope, _Virtual, _Convention);
     groundTruth(Method, Class, MName, method, realDestructor, _Linkage, _Scope, _Virtual, _Convention)),
    not((finalMethodProperty(Method, deletingDestructor, certain);
         finalMethodProperty(Method, realDestructor, certain))),
    write('Missing any destructor property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

extraAnyDestructorProperty(Method) :-
    (finalMethodProperty(Method, deletingDestructor, certain);
     finalMethodProperty(Method, realDestructor, certain)),
    not((groundTruth(Method, Class, MName, method, deletingDestructor, _Linkage, _Scope, _Virtual, _Convention);
         groundTruth(Method, Class, MName, method, realDestructor, _Linkage, _Scope, _Virtual, _Convention))),
    addressName(Method, MName),
    addressClass(Method, Class),
    write('Extra any destructor property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

correctVirtualProperty(Method) :-
    groundTruth(Method, Class, MName, method, _Type, _Linkage, _Scope, virtual, _Convention),
    finalMethodProperty(Method, virtual, certain),
    write('Correct virtual property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

missingVirtualProperty(Method) :-
    groundTruth(Method, Class, MName, method, _Type, _Linkage, _Scope, virtual, _Convention),
    not(finalMethodProperty(Method, virtual, certain)),
    write('Missing virtual property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

extraVirtualProperty(Method) :-
    finalMethodProperty(Method, virtual, certain),
    not(groundTruth(Method, _Class, _Func, method, _Type, _Linkage, _Scope, virtual, _Convention)),
    addressName(Method, MName),
    addressClass(Method, Class),
    write('Extra virtual property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.

correctRealDestructorProperty(Method) :-
    groundTruth(Method, Class, _MName, method, realDestructor, _Linkage, _Scope, _Virtual, _Convention),
    finalMethodProperty(Method, realDestructor, certain),
    write('Correct real destructor property: '), writeHex(Method),
    write(' Class='), writeln(Class)
    % We want no backtracking and no failure.
    ; true.

missingRealDestructorProperty(Method) :-
    groundTruth(Method, Class, _MName, method, realDestructor, _Linkage, _Scope, _Virtual, _Convention),
    not(finalMethodProperty(Method, realDestructor, certain)),
    write('Missing real destructor property: '), writeHex(Method),
    write(' Class='), writeln(Class)
    % We want no backtracking and no failure.
    ; true.

extraRealDestructorProperty(Method) :-
    finalMethodProperty(Method, realDestructor, certain),
    not(groundTruth(Method, _Class, _Func, method, realDestructor, _Linkage, _Scope, _Virtual, _Convention)),
    addressName(Method, MName),
    addressClass(Method, Class),
    write('Extra real destructor property: '), writeHex(Method),
    write(' Class='), write(Class),
    write(' Method='), writeln(MName)
    % We want no backtracking and no failure.
    ; true.


/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
