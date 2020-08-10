% ============================================================================================
% Ground truth validation rules.
% ============================================================================================

:- use_module(library(apply), [maplist/2]).
:- use_module(library(lists), [member/2]).

:- ensure_loaded(util).
:- ensure_loaded(logging).
:- ensure_loaded(results).
:- ensure_loaded(report).

:- dynamic groundTruth/9.

loadAndValidateResults(ResultsFile, GroundFile) :-
    loadResults(ResultsFile),
    loadPredicates(GroundFile),
    validateResults.

validateResults :-
    % Write a newline so that our output messages don't get mixed up with the prompt?
    loginfoln('Begining vlidation...'),
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
    maplist(extraAssignedMethod, FinalAssignedMethodSet),
    loginfoln('Validation complete.').

addressName(Address, NameOrNone) :-
    groundTruth(Address, _Class, Name, _Type, _OtherType, _Linked, _Scope, _Virt, _Conv)
    -> NameOrNone=Name; NameOrNone=0.

addressClass(Address, ClassOrNone) :-
    groundTruth(Address, Class, _Name, _Type, _OtherType, _Linked, _Scope, _Virt, _Conv)
    -> ClassOrNone=Class; ClassOrNone=0.

% --------------------------------------------------------------------------------------------
validVFTable(VFTable) :-
    groundTruth(VFTable, _Class, _Func, table, vftable, linked, _Scope, _Virt, _Conv).

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
    (groundTruth(VFTable, Class, _Unused, table, vftable, linked, _Scope, _Virt, _Conv),
     finalVFTable(VFTable, _Min, _Max, _RTTI, _Mangled)) ->
        loginfoln('~Q.', correctVFTable(VFTable, Class)); true.

missingVFTable(VFTable) :-
    (groundTruth(VFTable, Class, _Unused, table, vftable, linked, _Scope, _Virt, _Conv),
     not(finalVFTable(VFTable, _Min, _Max, _RTTI, _Mangled))) ->
        logerrorln('~Q.', missingVFTable(VFTable, Class)); true.

extraVFTable(VFTable) :-
    (finalVFTable(VFTable, _Min, _Max, _RTTI, Mangled),
     not(groundTruth(VFTable, _Class, _Func, table, vftable, linked, _Scope, _Virt, _Conv))) ->
        logerrorln('~Q.', extraVFTable(VFTable, Mangled)); true.

% --------------------------------------------------------------------------------------------

groundAssignedMethod(Method, Class) :-
    groundTruth(Method, Class, _Func, method, _MType, linked, _Scope, _Virt, _Conv).

groundAssignedMethods(Set) :-
    setof([Method, Class], groundAssignedMethod(Method, Class), Set), !.
groundAssignedMethods([]).


finalAssignedMethod(Method, Class) :-
    finalClass(ID, _VFTable, _Min, _Max, _RealDestructor, Methods),
    member(Method, Methods),
    groundTruth(ID, Class, _Func, method, _MType, linked, _Scope, _Virt, _Conv).

finalAssignedMethods(Set) :-
    setof([Method, Class], finalAssignedMethod(Method, Class), Set), !.
finalAssignedMethods([]).

correctAssignedMethod(GroundMethodClassPair) :-
    % Calling this every time seems very inefficient.  Maybe table or redesign?
    (finalAssignedMethods(FinalAssignedMethods),
     % The real rule is to simply compare the lists.
     member(GroundMethodClassPair, FinalAssignedMethods),
     nth1(1, GroundMethodClassPair, Method),
     nth1(2, GroundMethodClassPair, Class),
     addressName(Method, MName)) ->
        loginfoln('~Q.', correctMethodAssignment(Method, Class, MName)); true.

extraAssignedMethod(FinalMethodClassPair) :-
    % Calling this every time seems very inefficient.  Maybe table or redesign?
    (groundAssignedMethods(GroundAssignedMethods),
     % The real rule is to simply compare the lists.
     not(member(FinalMethodClassPair, GroundAssignedMethods)),
     nth1(1, FinalMethodClassPair, Method),
     nth1(2, FinalMethodClassPair, Class),
     addressName(Method, MName)) ->
        logerrorln('~Q.', extraMethodAssignment(Method, Class, MName)); true.

missingAssignedMethod(GroundMethodClassPair) :-
    % Calling this every time seems very inefficient.  Maybe table or redesign?
    (finalAssignedMethods(FinalAssignedMethods),
     % The real rule is to simply compare the lists.
     not(member(GroundMethodClassPair, FinalAssignedMethods)),
     nth1(1, GroundMethodClassPair, Method),
     nth1(2, GroundMethodClassPair, Class),
     addressName(Method, MName)) ->
        logerrorln('~Q.', missingMethodAssignment(Method, Class, MName)); true.

% --------------------------------------------------------------------------------------------
validMethod(Method) :-
    groundTruth(Method, _Class, _Func, method, _MType,linked, _Scope, _Virt, _Conv).

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
    (groundTruth(Method, Class, MName, method, constructor, _Link, _Scope, _Virt, _Conv),
     finalMethodProperty(Method, constructor, certain)) ->
        loginfoln('~Q.', correctConstructorProperty(Method, Class, MName)); true.

missingConstructorProperty(Method) :-
    (groundTruth(Method, Class, MName, method, constructor, _Link, _Scope, _Virt, _Conv),
     not(finalMethodProperty(Method, constructor, certain))) ->
        logerrorln('~Q.', missingConstructorProperty(Method, Class, MName)); true.

extraConstructorProperty(Method) :-
    (finalMethodProperty(Method, constructor, certain),
     not(groundTruth(Method, _Class, _Func, method, constructor, _Link, _Scope, _Virt, _Conv)),
     addressClass(Method, Class),
     addressName(Method, MName)) ->
        logerrorln('~Q.', extraConstructorProperty(Method, Class, MName)); true.

correctDeletingDestructorProperty(Method) :-
    (groundTruth(Method, Class, MName, method, deletingDestructor, _Link, _Scope, _Virt, _Conv),
     finalMethodProperty(Method, deletingDestructor, certain)) ->
        loginfoln('~Q.', correctDeletingDestructorProperty(Method, Class, MName)); true.

missingDeletingDestructorProperty(Method) :-
    (groundTruth(Method, Class, MName, method, deletingDestructor, _Link, _Scope, _Virt, _Conv),
     not(finalMethodProperty(Method, deletingDestructor, certain))) ->
        logerrorln('~Q.', missingDeletingDestructorProperty(Method, Class, MName)); true.

extraDeletingDestructorProperty(Method) :-
    (finalMethodProperty(Method, deletingDestructor, certain),
     not(groundTruth(Method, _Class, _Func, method, deletingDestructor, _Link, _Scope, _Virt, _Conv)),
     addressName(Method, MName),
     addressClass(Method, Class)) ->
        logerrorln('~Q.', extraDeletingDestructorProperty(Method, Class, MName)); true.

correctAnyDestructorProperty(Method) :-
    ((groundTruth(Method, Class, MName, method, deletingDestructor, _Link, _Scope, _Virt, _Conv);
      groundTruth(Method, Class, MName, method, realDestructor, _Link, _Scope, _Virt, _Conv)),
     (finalMethodProperty(Method, deletingDestructor, certain);
      finalMethodProperty(Method, realDestructor, certain))) ->
        loginfoln('~Q.', correctAnyDestructorProperty(Method, Class, MName)); true.

missingAnyDestructorProperty(Method) :-
    ((groundTruth(Method, Class, MName, method, deletingDestructor, _Link, _Scope, _Virt, _Conv);
      groundTruth(Method, Class, MName, method, realDestructor, _Link, _Scope, _Virt, _Conv)),
     not((finalMethodProperty(Method, deletingDestructor, certain);
          finalMethodProperty(Method, realDestructor, certain)))) ->
        logerrorln('~Q.', missingAnyDestructorProperty(Method, Class, MName)); true.

extraAnyDestructorProperty(Method) :-
    ((finalMethodProperty(Method, deletingDestructor, certain);
      finalMethodProperty(Method, realDestructor, certain)),
     not((groundTruth(Method, _Class1, _Func, method, deletingDestructor, _Link1, _Scope1, _Virt1, _Conv1);
          groundTruth(Method, _Class2, _Func, method, realDestructor, _Link2, _Scope2, _Virt2, _Conv2))),
     addressName(Method, MName),
     addressClass(Method, Class)) ->
        logerrorln('~Q.', extraAnyDestructorProperty(Method, Class, MName)); true.

correctVirtualProperty(Method) :-
    (groundTruth(Method, Class, MName, method, _Type, _Link, _Scope, virtual, _Conv),
     finalMethodProperty(Method, virtual, certain)) ->
        loginfoln('~Q.', correctVirtualProperty(Method, Class, MName)); true.

missingVirtualProperty(Method) :-
    (groundTruth(Method, Class, MName, method, _Type, _Link, _Scope, virtual, _Conv),
     not(finalMethodProperty(Method, virtual, certain))) ->
        logerrorln('~Q.', missingVirtualProperty(Method, Class, MName)); true.

extraVirtualProperty(Method) :-
    (finalMethodProperty(Method, virtual, certain),
     not(groundTruth(Method, _Class, _Func, method, _Type, _Link, _Scope, virtual, _Conv)),
     addressName(Method, MName),
     addressClass(Method, Class)) ->
        logerrorln('~Q.', extraVirtualProperty(Method, Class, MName)); true.

correctRealDestructorProperty(Method) :-
    (groundTruth(Method, Class, MName, method, realDestructor, _Link, _Scope, _Virt, _Conv),
     finalMethodProperty(Method, realDestructor, certain)) ->
        loginfoln('~Q.', correctRealDestructorProperty(Method, Class, MName)); true.

missingRealDestructorProperty(Method) :-
    (groundTruth(Method, Class, MName, method, realDestructor, _Link, _Scope, _Virt, _Conv),
     not(finalMethodProperty(Method, realDestructor, certain))) ->
        logerrorln('~Q.', missingRealDestructorProperty(Method, Class, MName)); true.

extraRealDestructorProperty(Method) :-
    (finalMethodProperty(Method, realDestructor, certain),
     not(groundTruth(Method, _Class, _Func, method, realDestructor, _Link, _Scope, _Virt, _Conv)),
     addressName(Method, MName),
     addressClass(Method, Class)) ->
        logerrorln('~Q.', extraRealDestructorProperty(Method, Class, MName)); true.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
