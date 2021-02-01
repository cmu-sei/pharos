% ============================================================================================
% Triggers.
% ============================================================================================

:- use_module(library(apply), [maplist/3]).
:- use_module(library(lists), [member/2]).

% New facts that may explicitly trigger some expensive rules.
:- dynamic trigger_fact/1.

% Called by try_assert_real/1

trigger_hook(factConstructor(A)) :-
    !,
    assertz(trigger_fact(factConstructor(A))).

trigger_hook(factVFTableEntry(A,B,C)) :-
    !,
    assertz(trigger_fact(factVFTableEntry(A,B,C))).

trigger_hook(factVFTableWrite(A,B,C,D)) :-
    !,
    assertz(trigger_fact(factVFTableWrite(A,B,C,D))).

trigger_hook(factClassSizeLTE(A,B)) :-
    !,
    assertz(trigger_fact(factClassSizeLTE(A,B))).

trigger_hook(factClassSizeGTE(A,B)) :-
    !,
    assertz(trigger_fact(factClassSizeGTE(A,B))).

trigger_hook(factClassCallsMethod(A,B)) :-
    !,
    assertz(trigger_fact(factClassCallsMethod(A,B))).

trigger_hook(factNOTMergeClasses(A,B)) :-
    !,
    assertz(trigger_fact(factNOTMergeClasses(A,B))).

trigger_hook(findint(A,B)) :-
    !,
    assertz(trigger_fact(findint(A,B))).

trigger_hook(_X).

% MethodInVFTable, which is a helper for guessMergeClassesB
dispatchTrigger(factVFTableEntry(VFTable, Offset, Entry), Out) :-
    setof((VFTable, Offset, Method),
          (reasonMethodInVFTable(VFTable, Offset, Method, Entry),
           not(factMethodInVFTable(VFTable, Offset, Method)),
           loginfoln('Concluding ~Q.', factMethodInVFTable(VFTable, Offset, Method))),
          TupleSets),
    maplist(try_assert_builder(factMethodInVFTable), TupleSets, ActionSets),
    Out = all(ActionSets).

% HasUnknownBase_C
% factVFTableEntry: VFTable could be AncestorVFTable or DerivedVFTable
dispatchTrigger(factVFTableEntry(VFTable, _Offset, Entry), Out) :-
    setof(DerivedClass,
          AncestorVFTable^DerivedVFTable^Entry^((AncestorVFTable=VFTable;DerivedVFTable=VFTable),
                                                 reasonClassHasUnknownBase_C1(DerivedClass, AncestorVFTable, DerivedVFTable, Entry),
                                                 not(factClassHasUnknownBase(Class)),
                                                 not(factClassHasNoBase(Class)),
                                                 loginfoln('Concluding ~Q.', factClassHasUnknownBase_C(Class))),
          ClassSets),
    maplist(try_assert_builder(factClassHasUnknownBase), ClassSets, ActionSets),
    Out = all(ActionSets).

% find: (FindMethod, FindClass) could be (Method, AncestorClass) or (AncestorConstructor, AncestorClass)
dispatchTrigger(findint(FindMethod, FindClass), Out) :-
    setof(DerivedClass,
          Method^AncestorConstructor^AncestorClass^AncestorVFTable^((FindMethod=Method; FindMethod=AncestorConstructor),
                                                                                                     FindClass=AncestorClass,
                                                                                                     reasonClassHasUnknownBase_C2(DerivedClass, Method, AncestorConstructor, AncestorClass, AncestorVFTable),
                                                                                                     not(factClassHasUnknownBase(Class)),
                                                                                                     not(factClassHasNoBase(Class)),
                                                                                                     loginfoln('Concluding ~Q.', factClassHasUnknownBase_C(Class))),
          ClassSets),
    maplist(try_assert_builder(factClassHasUnknownBase), ClassSets, ActionSets),
    Out = all(ActionSets).

% find: (FindMethod, FindClass) could be (DerivedConstructor, DerivedClass)
dispatchTrigger(findint(DerivedConstructor, DerivedClass), Out) :-
    setof(DerivedClass,
          DerivedVFTable^(reasonClassHasUnknownBase_C3(DerivedClass, DerivedConstructor, DerivedVFTable),
            not(factClassHasUnknownBase(Class)),
            not(factClassHasNoBase(Class)),
            loginfoln('Concluding ~Q.', factClassHasUnknownBase_C(Class))),
          ClassSets),
    maplist(try_assert_builder(factClassHasUnknownBase), ClassSets, ActionSets),
    Out = all(ActionSets).

% factConstructor: Constructor could be AncestorConstructor (C2)
dispatchTrigger(factConstructor(AncestorConstructor), Out) :-
    setof(DerivedClass,
          Method^AncestorClass^AncestorVFTable^(reasonClassHasUnknownBase_C2(DerivedClass, Method, AncestorConstructor, AncestorClass, AncestorVFTable),
           not(factClassHasUnknownBase(Class)),
           not(factClassHasNoBase(Class)),
           loginfoln('Concluding ~Q.', factClassHasUnknownBase_C(Class))),
          ClassSets),
    maplist(try_assert_builder(factClassHasUnknownBase), ClassSets, ActionSets),
    Out = all(ActionSets).

% factConstructor: Constructor could be DerivedConstructor (C3)
dispatchTrigger(factConstructor(DerivedConstructor), Out) :-
    setof(DerivedClass,
          DerivedVFTable^(reasonClassHasUnknownBase_C3(DerivedClass, DerivedConstructor, DerivedVFTable),
           not(factClassHasUnknownBase(Class)),
           not(factClassHasNoBase(Class)),
           loginfoln('Concluding ~Q.', factClassHasUnknownBase_C(Class))),
          ClassSets),
    maplist(try_assert_builder(factClassHasUnknownBase), ClassSets, ActionSets),
    Out = all(ActionSets).

% factVFTableWrite: (Constructor, VFTable) could be (AncestorConstructor, AncestorVFTable)
dispatchTrigger(factVFTableWrite(_Insn, AncestorConstructor, _Offset, AncestorVFTable), Out) :-
    setof(DerivedClass,
          Method^AncestorClass^(reasonClassHasUnknownBase_C2(DerivedClass, Method, AncestorConstructor, AncestorClass, AncestorVFTable),
            not(factClassHasUnknownBase(Class)),
            not(factClassHasNoBase(Class)),
            loginfoln('Concluding ~Q.', factClassHasUnknownBase_C(Class))),
          ClassSets),
    maplist(try_assert_builder(factClassHasUnknownBase), ClassSets, ActionSets),
    Out = all(ActionSets).

% factVFTableWrite: (Constructor, VFTable) could be (DerivedConstructor, DerivedVFTable)
dispatchTrigger(factVFTableWrite(_Insn, DerivedConstructor, _Offset, DerivedVFTable), Out) :-
    setof(DerivedClass,
          (reasonClassHasUnknownBase_C3(DerivedClass, DerivedConstructor, DerivedVFTable),
           not(factClassHasUnknownBase(Class)),
           not(factClassHasNoBase(Class)),
           loginfoln('Concluding ~Q.', factClassHasUnknownBase_C(Class))),
          ClassSets),
    maplist(try_assert_builder(factClassHasUnknownBase), ClassSets, ActionSets),
    Out = all(ActionSets).

% End HasUnknownBase_C rules

% HasUnknownBase_E
dispatchTrigger(factClassCallsMethod(Class, Method), Out) :-
    setof(Class,
          MethodClass^(reasonClassHasUnknownBase_E(Class, Method, MethodClass),
           not(factClassHasUnknownBase(Class)),
           not(factClassHasNoBase(Class)),
           loginfoln('Concluding ~Q.', factClassHasUnknownBase(Class))),
          ClassSets),
    maplist(try_assert_builder(factClassHasUnknownBase), ClassSets, ActionSets),
    Out = all(ActionSets).
dispatchTrigger(factNOTMergeClasses(Class, MethodClass), Out) :-
    setof(Class,
          Method^(reasonClassHasUnknownBase_E(Class, Method, MethodClass),
           not(factClassHasUnknownBase(Class)),
           not(factClassHasNoBase(Class)),
           loginfoln('Concluding ~Q.', factClassHasUnknownBase(Class))),
          ClassSets),
    maplist(try_assert_builder(factClassHasUnknownBase), ClassSets, ActionSets),
    Out = all(ActionSets).
% End

dispatchTrigger(factVFTableWrite(A,Method1,C,D), Out) :-
    find(Method1, Class1),
    setof((Class1, Class2),
          (reasonNOTMergeClasses_E(Class1, Class2, A, Method1, C, D),
           iso_dif(Class1, Class2),
           not(dynFactNOTMergeClasses(Class1, Class2)),
           loginfoln('Concluding ~Q.', factNOTMergeClasses(Class1, Class2))),
          ClassSets),
    maplist(try_assert_builder(factNOTMergeClasses), ClassSets, ActionSets),
    Out = all(ActionSets).

dispatchTrigger(factClassSizeLTE(Class1,LTESize), Out) :-
    setof((Class1, Class2),
          GTESize1^GTESize2^((reasonNOTMergeClasses_M(Class1, Class2, GTESize1, LTESize);
                              reasonNOTMergeClasses_N(Class1, Class2, GTESize2, LTESize)),
                             iso_dif(Class1, Class2),
                             not(dynFactNOTMergeClasses(Class1, Class2)),
                             loginfoln('Concluding ~Q.', factNOTMergeClasses(Class1, Class2))),
          ClassSets),
    maplist(try_assert_builder(factNOTMergeClasses), ClassSets, ActionSets),
    Out = all(ActionSets).

dispatchTrigger(factClassSizeGTE(Class1,GTESize), Out) :-
    setof((Class1, Class2),
          LTESize1^LTESize2^((reasonNOTMergeClasses_M(Class1, Class2, GTESize, LTESize1);
                              reasonNOTMergeClasses_N(Class1, Class2, GTESize, LTESize2)),
                             iso_dif(Class1, Class2),
                             not(dynFactNOTMergeClasses(Class1, Class2)),
                             loginfoln('Concluding ~Q.', factNOTMergeClasses(Class1, Class2))),
          ClassSets),
    maplist(try_assert_builder(factNOTMergeClasses), ClassSets, ActionSets),
    Out = all(ActionSets).

% reasonNOTMergeClasses_Q
dispatchTrigger(findint(Method, _Class), Out) :-
    setof((Class1, Class2),
          OtherMethod^((reasonNOTMergeClasses_Q(Class1, Class2, Method, OtherMethod);
                        reasonNOTMergeClasses_Q(Class1, Class2, OtherMethod, Method)),
                       iso_dif(Class1, Class2),
                       not(dynFactNOTMergeClasses(Class1, Class2)),
                       loginfoln('Concluding ~Q.', factNOTMergeClasses(Class1, Class2))),
          ClassSets),
    maplist(try_assert_builder(factNOTMergeClasses), ClassSets, ActionSets),
    Out = all(ActionSets).

concludeTrigger(Out) :-
    reportFirstSeen('concludeTrigger'),
    setof(X,
          % Limit ourselves to 100K facts at once.  See
          % https://github.com/cmu-sei/pharos/issues/114
          atmost(
              (retract(trigger_fact(X)),
               logtraceln('Processing trigger fact... ~Q', X)),
              100000),
          Facts),
    !,

    (setof(OutTemp,
          Fact^OutTemp^(member(Fact, Facts), dispatchTrigger(Fact, OutTemp)),
          ActionList)
     ->
         % If we generated any actions, take them
         Out = all(ActionList)
     ;
         % If we didn't take any actions, recurse. If we don't do this, concludeTrigger will
         % fail and the next conclusion rule will be evaluated even if there are more trigger
         % facts to be considered.  This can lead to upstream problem errors.
         concludeTrigger(Out)).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
