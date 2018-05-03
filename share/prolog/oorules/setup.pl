% Copyright 2017 Carnegie Mellon University.

% ============================================================================================
% Inputs facts.
% ============================================================================================

% Facts produced by the C++ component are all optional.  These facts are never asserted or
% change in any way during execution.

% For use with timed_call
debug_callback :- statistics, (statistics(summarize_idg) ; true).

:- dynamic guessingDisabled/0 as opaque.
:- dynamic method/1 as incremental.
:- index(funcOffset/4, [1,2,3,4]).
:- dynamic funcOffset/4.
:- index(thisCallMethod/3, [1,2,3]).
:- dynamic thisCallMethod/3.
:- index(methodMemberAccess/4, [1,2,3,4]).
:- dynamic methodMemberAccess/4.
:- dynamic returnsSelf/1.
:- dynamic noCallsBefore/1.
:- dynamic noCallsAfter/1.
:- dynamic uninitializedReads/1.
:- index(possibleVFTableWrite/4, [1,2,3,4]).
:- dynamic possibleVFTableWrite/4.
%:- index(possibleVFTableEntry/3, [1,2,3]).
%:- dynamic possibleVFTableEntry/3.
:- index(possibleVBTableWrite/4, [1,2,3,4]).
:- dynamic possibleVBTableWrite/4.
%:- index(possibleVBTableEntry/3, [1,2,3]).
%:- dynamic possibleVBTableEntry/3.
:- index(possibleVirtualFunctionCall/5, [1,2,3,4,5]).
:- dynamic possibleVirtualFunctionCall/5.
:- index(rTTICompleteObjectLocator/6, [1,2,3,4,5,6]).
:- dynamic rTTICompleteObjectLocator/6.
:- index(rTTITypeDescriptor/3, [1,2,3]).
:- dynamic rTTITypeDescriptor/3.
:- index(rTTIClassHierarchyDescriptor/3, [1,2,3]).
:- dynamic rTTIClassHierarchyDescriptor/3.
:- index(rTTIBaseClassDescriptor/7, [1,2,3,4,5,6,7]).
:- dynamic rTTIBaseClassDescriptor/7.
:- index(thisPtrAllocation/5, [1,2,3,4,5]).
:- dynamic thisPtrAllocation/5.
:- index(thisPtrUsage/4, [1,2,3,4]).
:- dynamic thisPtrUsage/4.
:- index(thisPtrOffset/3, [1,2,3]).
:- dynamic thisPtrOffset/3.
:- dynamic purecall/1.
:- index(insnCallsDelete/3, [1,2,3]).
:- dynamic insnCallsDelete/3.
:- index(symbolGlobalObject/3, [1,2,3]).
:- dynamic symbolGlobalObject/3.
:- index(symbolClass/3, [1,2,3]).
:- dynamic symbolClass/3.
:- index(symbolProperty/2, [1,2]).
:- dynamic symbolProperty/2.
:- index(thunk/2, [1,2]).
:- dynamic thunk/2.

:- index(funcParameter/3, [1,2,3]).
:- dynamic funcParameter/3.
:- index(funcReturn/3, [1,2,3]).
:- dynamic funcReturn/3.
:- index(callingConvention/2, [1,2]).
:- dynamic callConvention/2.
:- index(callTarget/3, [1,2,3]).
:- dynamic callTarget/3.
:- index(callParameter/4, [1,2,3,4]).
:- dynamic callParameter/4.
:- index(callReturn/4, [1,2,3,4]).
:- dynamic callReturn/4.

% For Debugging, not for rules!
%:- index(termDebug/2, [1,2]).
%:- dynamic termDebug/2 as incremental.

% ============================================================================================
% Dynamically asserted facts.
% ============================================================================================

% These facts are asserted and retracted dynamically as the analysis executes.

:- dynamic factMethod/1 as incremental.
:- dynamic factNOTMethod/1 as incremental.
:- dynamic factConstructor/1 as incremental.
:- dynamic factNOTConstructor/1 as incremental.
:- dynamic factRealDestructor/1 as incremental.
:- dynamic factNOTRealDestructor/1 as incremental.
:- dynamic factDeletingDestructor/1 as incremental.
:- dynamic factNOTDeletingDestructor/1 as incremental.

:- index(factVirtualFunctionCall/5, [1,2,3,4,5]).
:- dynamic factVirtualFunctionCall/5 as incremental.
:- index(factNOTVirtualFunctionCall/5, [1,2,3,4,5]).
:- dynamic factNOTVirtualFunctionCall/5 as incremental.
:- dynamic factVFTable/1 as incremental.
:- dynamic factNOTVFTable/1 as incremental.
:- index(factVFTableWrite/4, [1,2,3,4]).
:- dynamic factVFTableWrite/4 as incremental.
:- index(factVFTableOverwrite/3, [1,2,3]).
:- dynamic factVFTableOverwrite/3 as incremental.
:- index(factVFTableEntry/3, [1,2,3]).
:- dynamic factVFTableEntry/3 as incremental.
:- index(factNOTVFTableEntry/3, [1,2,3]).
:- dynamic factNOTVFTableEntry/3 as incremental.
:- index(factVFTableSizeGTE/2, [1,2]).
:- dynamic factVFTableSizeGTE/2 as incremental.
:- index(factVFTableSizeLTE/2, [1,2]).
:- dynamic factVFTableSizeLTE/2 as incremental.

:- dynamic factVBTable/1 as incremental.
:- dynamic factNOTVBTable/1 as incremental.
:- index(factVBTableWrite/4, [1,2,3,4]).
:- dynamic factVBTableWrite/4 as incremental.
:- index(factVBTableEntry/3, [1,2,3]).
:- dynamic factVBTableEntry/3 as incremental.
:- index(factNOTVBTableEntry/3, [1,2,3]).
:- dynamic factNOTVBTableEntry/3 as incremental.

:- index(factObjectInObject/3, [1,2,3]).
:- dynamic factObjectInObject/3 as incremental.
:- index(factDerivedClass/3, [1,2,3, 1+3]).
:- dynamic factDerivedClass/3 as incremental.
:- index(factNOTDerivedClass/3, [1,2,3, 1+3]).
:- dynamic factNOTDerivedClass/3 as incremental.
:- index(factEmbeddedObject/3, [1,2,3]).
:- dynamic factEmbeddedObject/3 as incremental.
:- index(factNOTEmbeddedObject/3, [1,2,3]).
:- dynamic factNOTEmbeddedObject/3 as incremental.
:- index(factClassSizeGTE/2, [1,2]).
:- dynamic factClassSizeGTE/2 as incremental.
:- index(factClassSizeLTE/2, [1,2]).
:- dynamic factClassSizeLTE/2 as incremental.
:- dynamic factClassHasNoBase/1 as incremental.
:- dynamic factClassHasUnknownBase/1 as incremental.
:- index(factMergeClasses/2, [1,2]).
:- dynamic factMergeClasses/2 as incremental.
:- index(factNOTMergeClasses/2, [1,2]).
:- dynamic factNOTMergeClasses/2 as incremental.
:- index(factClassCallsMethod/2, [1,2]).
:- dynamic factClassCallsMethod/2 as incremental.

% ============================================================================================
% Dynamically rewritten facts involving classes.
% ============================================================================================

% Because class identifiers change during analysis, these facts tell use which of the
% dyanmically asserted facts must be rewritten whenever a class identifier for a specific class
% changes.  See fixupClasses() in this file for the details of the rewriting.

classArgs(factEmbeddedObject/3, 1).
classArgs(factEmbeddedObject/3, 2).
classArgs(factObjectInObject/3, 1).
classArgs(factObjectInObject/3, 2).
classArgs(factDerivedClass/3, 1).
classArgs(factDerivedClass/3, 2).
classArgs(factNOTDerivedClass/3, 1).
classArgs(factNOTDerivedClass/3, 2).
classArgs(factClassHasNoBase/1, 1).
classArgs(factNOTMergeClasses/2, 1).
classArgs(factNOTMergeClasses/2, 2).
classArgs(factClassCallsMethod/2, 1).
classArgs(factClassSizeGTE/2, 1).
classArgs(factClassSizeLTE/2, 1).

% ============================================================================================
% Guessed fact markers.
% ============================================================================================

% These are markers for which facts were determined by guessing rather than reasoning.  They
% cannot be used for determining which facts are certain to be true and which are not because
% once you've made a guess, there are many subsequent facts that are concluded on the basis of
% the guessed fact that will NOT be marked in this way.  But we can use these facts for feature
% such as measuring how many guesses were required to reach the final solution (and what types
% of guesses they were).  This could be statisically interseting in addition to provided
% details about where our logic was mostly likely to have initially introduce incorrect
% conclusions.
%
% Cory has been conflicted on whether these facts have any significant value and whether they
% should be consistently used or completely discarded.  The most recent conclusion was to get
% them back up to being consistently used and see if we can't develop more useful
% infrastructure around them.

:- dynamic guessedMethod/1 as incremental.
:- dynamic guessedNOTMethod/1 as incremental.
:- dynamic guessedConstructor/1 as incremental.
:- dynamic guessedNOTConstructor/1 as incremental.
:- dynamic guessedRealDestructor/1 as incremental.
:- dynamic guessedNOTRealDestructor/1 as incremental.
:- dynamic guessedDeletingDestructor/1 as incremental.
:- dynamic guessedNOTDeletingDestructor/1 as incremental.
:- dynamic guessedVirtualFunctionCall/5 as incremental.
:- dynamic guessedNOTVirtualFunctionCall/5 as incremental.
:- dynamic guessedVFTable/1 as incremental.
:- dynamic guessedNOTVFTable/1 as incremental.
%:- dynamic guessedVFTableWrite/4. % Only concluded!
%:- dynamic guessedVFTableOverwrite/3. % Only concluded!
:- dynamic guessedVFTableEntry/3 as incremental.
:- dynamic guessedNOTVFTableEntry/3 as incremental.
:- dynamic guessedVBTable/1 as incremental.
:- dynamic guessedNOTVBTable/1 as incremental.
:- dynamic guessedVBTableWrite/4 as incremental.
%:- dynamic guessedVBTableEntry/3 as incremental. % Only concluded!
%:- dynamic guessedNOTVBTableEntry/3 as incremental. % Only concluded!
%:- dynamic guesssedObjectInObject/3. % Only concluded!
:- dynamic guessedDerivedClass/3 as incremental.
:- dynamic guessedNOTDerivedClass/3 as incremental.
:- dynamic guessedEmbeddedObject/3 as incremental.
:- dynamic guessedNOTEmbeddedObject/3 as incremental.
%:- dynamic guessedClassSizeGTE/2. % Only concluded.
%:- dynamic guessedlassSizeLTE/2. % Only concluded.
:- dynamic guessedClassHasNoBase/1 as incremental.
:- dynamic guessedClassHasUnknownBase/1 as incremental.
:- dynamic guessedMergeClasses/2 as incremental.
:- dynamic guessedNOTMergeClasses/2 as incremental.
%:- dynamic factClassCallsMethod/2. % Only concluded.

% ============================================================================================
% Assorted declarations.
% ============================================================================================

:- import member/2 from lists.
:- import incr_assert/1, incr_asserta/1, incr_retract/1 from increval.

:- import gpp_options from parse.
:- assert(gpp_options('-P -m -nostdinc')).

% Replacing xpp_on with xpp_dump in the following line will cause all our prolog rules to be
% placed into a monolothic file, setup.pl_gpp.
:- compiler_options([xpp_on]).

%:- import error_writeln/1 from standard.
%:- dynamic default_user_error_handler/1.
%default_user_error_handler(X) :-
%    machine:xsb_backtrace(B),
%    error_handler:print_backtrace(B),
%    error_writeln(['Aborting due to error: ', X]),halt(1).

% Can I put this somewhere else?
:- index(findint/2, [1, 2, 1+2]).
:- dynamic findint/2 as incremental.

% ============================================================================================
% Other modules.
% ============================================================================================

#include "util.pl"
#include "initial.pl"
#include "rtti.pl"
#include "rules.pl"
#include "guess.pl"
#include "forward.pl"
#include "insanity.pl"
#include "complete.pl"
#include "final.pl"
#include "softcut.pl"
#include "class.pl"

:- debug_ctl(profile, on).
:- debug_ctl(prompt, off).
:- debug_ctl(hide, [rootint/2]).

% ============================================================================================
% Solving main engine.
% ============================================================================================

% Numfacts keeps track of the number of currently recorded facts so we can show the user some
% progress.  Super fancy.
:- dynamic numfacts/1.
:- assert(numfacts(0)).
delta_numfacts(D) :- retract(numfacts(Y)), Z is Y+D, assert(numfacts(Z)).

try_assert(X) :- X, !.
try_assert(X) :- try_assert_real(X).
try_assert_real(X) :- delta_numfacts(1), incr_asserta(X).
try_assert_real(X) :-
    %logtrace('Retracting '), logtrace(X), logtraceln('...'),
    delta_numfacts(-1),
    incr_retract(X),
    fail.

try_retract(X) :- not(X), !.
try_retract(X) :- try_retract_real(X).
try_retract_real(X) :- delta_numfacts(-1), incr_retract(X).
try_retract_real(X) :-
    %logtrace('Asserting '), logtrace(X), logtraceln('...'),
    delta_numfacts(1),
    incr_asserta(X),
    fail.

% This predicate looks for arguments that are defined in classArgs as representing classes.  It
% then looks for any argument that is equal to 'From', and modifies it to 'To' instead.  The
% idea is that this will be used to keep the dynamic database always referring to the latest
% representative for each class.
fixupClasses(From, To, OldTerm, NewTerm) :-
    classArgs(Pred/Arity, Index),
    functor(OldTerm, Pred, Arity),

    % The OldTerm must already be asserted, since we're going to end up retracting it.
    OldTerm,

    %debug('Considering class fact '), debug(Pred), debug('/'), debug(Arity),
    %debug(' index '), debug(Index),
    %debug(' from '), debug(From), debug(' to '), debug(To),
    %debug(' in predicate '), debugln(OldTerm),

    % Ensure that the From argument is in the correct location for this replacement?
    arg(Index, OldTerm, From),

    %debug('Fixing up '), debug(Pred), debug('/'), debug(Arity),
    %debug(' index '), debug(Index),
    %debug(' from '), debug(From), debug(' to '), debug(To),
    %debug(' in predicate '), debugln(OldTerm),

    % Now we'll break it apart.
    OldTerm =.. OldTermElements,
    ListIndex is Index + 1,

    % Report what the terms list looks like before replacement
    %debug('Fixing up position '), debug(ListIndex), debug(' in old elements: '), debugln(OldTermElements),

    % Replace From in OldTermElements at ListIndex offset, with To, and return NewTermElements.
    replace_ith(OldTermElements, ListIndex, From, To, NewTermElements),

    % Report what the terms list looks like after replacement
    %debug('Fixing up position '), debug(ListIndex),
    %debug(' resulted in new elements: '), debugln(NewTermElements),

    % Combine NetTermElements back into a predicate that we can assert.
    NewTerm =.. NewTermElements.

debugClasses :-
    classArgs(Pred/Arity, Index),
    functor(OldTerm, Pred, Arity),
    OldTerm,
    arg(Index, OldTerm, From),
    find(From, From2),
    (From = From2 -> fail;
     (logerror(From), logerror(' should be a class representative in '),
      logerror(OldTerm), logerror(' argument '), logerror(Index),
      logerror(' but '), logerror(From2), logerrorln(' is the rep.'))).

% This is a helper predicate used by mergeClasses(M1, M2).  The messages are logged at the
% debug level, because there's quite a lot of them, but this is a fairly important set of
% messages, and it might really belong at the info level.
mergeClassBuilder((OldTerm,NewTerm), Out) :-
    Out =
    (logdebug('Retracting '), logdebug(OldTerm),
     logdebug(' and asserting '), logdebug(NewTerm), logdebugln(' ...'),
     try_retract(OldTerm),
     try_assert(NewTerm)).

% Explicitly merge two methods.  Only called from reasonAMergeClasses and tryAMergeClasses.
mergeClasses(M1, M2) :-
    factMergeClasses(M1, M2),
    iso_dif(M1, M2),
    makeIfNecessary(M1),
    makeIfNecessary(M2),
    find(M1, S1),
    find(M2, S2),
    S1 \= S2,
    union(M1, M2),
    find(M1, NewRep),
    (NewRep=S1 -> OldRep=S2; OldRep=S1),

    loginfo('Merging class '), loginfo(OldRep), loginfo(' into '), loginfo(NewRep), loginfoln(' ...'),

    setof((OldTerm, NewTerm),
          fixupClasses(OldRep, NewRep, OldTerm, NewTerm),
          Set),

    maplist(mergeClassBuilder, Set, Actions),
    %debugln(Actions),

    all(Actions),

    debug_store(unionfind).

% Merge all classes that there are facts for.
mergeClassesRepeatedly :-
    % Fact saying that we _should_ merge classes survive from one query to another.
    factMergeClasses(M1, M2),
    % If we should merge, then actually do the merge, and if that succeeds, try again.
    mergeClasses(M1, M2) -> mergeClassesRepeatedly;
    % But if we failed to merge a class, we're done, but we always succeed and never fail.
    true.

% It does not appear that the ordering of the reasoning rules is too important because we'll
% eventually complete all reasoning before going to to guessing.  On the other hand, reasoning
% in the correct order should spend less time evaluating rules that don't accomplish anything.

reasonForward :-
    once((concludeMethod(Out);
          concludeVFTableOverwrite(Out);
          concludeVirtualFunctionCall(Out);
          concludeConstructor(Out);
          concludeNOTConstructor(Out);
          concludeVFTable(Out);
          concludeVFTableWrite(Out);
          concludeVFTableEntry(Out);
          concludeNOTVFTableEntry(Out);
          concludeVFTableSizeGTE(Out);
          concludeVFTableSizeLTE(Out);
          concludeVBTable(Out);
          concludeVBTableWrite(Out);
          concludeVBTableEntry(Out);
          concludeObjectInObject(Out);
          concludeDerivedClass(Out);
          concludeNOTDerivedClass(Out);
          concludeEmbeddedObject(Out);
          concludeNOTEmbeddedObject(Out);
          concludeDeletingDestructor(Out);
          concludeRealDestructor(Out);
          concludeNOTRealDestructor(Out);
          concludeClassSizeGTE(Out);
          concludeClassSizeLTE(Out);
          concludeClassHasNoBase(Out);
          concludeClassHasUnknownBase(Out);
          concludeMergeClasses(Out);
          concludeNOTMergeClasses(Out);
          concludeClassCallsMethod(Out)
        )),

    % At this point we have reasoned and produced a fact to assert.  We will not backtrack into
    % the reasoning because of once/1.

    % Go ahead and try_assert the fact.
    call(Out).

% If we can reason forward once, commit so we don't backtrack and try to pass without reasoning forward.
reasonForwardAsManyTimesAsPossible :-
    %if_(reasonForward,
    %    (reasonForwardAsManyTimesAsPossible),
    %    debugln('Done with reasonForwardAsManyTimesAsPossible')).
    if_(reasonForward, (reasonForwardAsManyTimesAsPossible), true).

%% reasonForwardAtLeastOnce :-
%%     reasonForward, !, reasonForwardAsManyTimesAsPossible.

countFacts(Total) :- numfacts(Total).

% Go forward: Make a guess, reason forward, and then sanity check
reasoningLoop :-
    (debuggingEnabled -> once((debugClasses; true)); true),
    guess,
    countFacts(N),
    progress(N),
    sanityChecks,
    reasonForwardAsManyTimesAsPossible,
    if_(sanityChecks,
        loginfoln('Constraint checks succeeded, guess accepted!'),
        (logwarnln('Constraint checks failed, retracting guess!'), fail)
       ),
    reasoningLoop.

% The only way to terminate the reasoningLoop is if we are complete.
reasoningLoop :-
    true.
%    checkCompleteness.

% --------------------------------------------------------------------------------------------
% The performance of our code is highly dependent on the ordering of these guesses.  Making bad
% guesses early causes lots of backtracking which preforms poorly.  The current ordering is not
% well justified, but rather a hodge-podge of experimental results and gut feelings.  Cory has
% no idea how to reason through this properly, so he's just going to take some notes.
guess :-

        % These three guesses are first on the principle that guesing them has lots of
        % consequences, and that they're probably not wrong, so there's little harm in guessing
        % them first.
    or([guessVirtualFunctionCall,
        guessVFTable,
        guessVBTable,
        guessDerivedClass,
        % ejs: guessEmbeddedObject is redundant!
        %guessEmbeddedObject,

        % Guess that methods really are methods.  Currently the ordering for this rule was
        % pretty random --  in time to guessing VFTable entries?
        guessMethod,

        % Perhaps both of these should be guessed at once?  They're so closely related that we
        % might get better results from requiring both or none...  But how to do that?  These area
        % guessed before constructors in particular because the prevent some bas constructor
        % guesses.
        guessDeletingDestructor,
        guessRealDestructor,

        % Constructors are very important guesses that can sometimes be reasoned soundly in the
        % presence of virtual function tables, but we often have to guess when there are not
        % tables.
        guessConstructor,

        % This is a fairly solid rule that used to be forward reasoning until it was found to
        % be incorrect in certain rare cases.  It has to be before ClassHasNoBase because it
        % will cause confusion about embedded object versus inheritance if it's after.
        guessNOTMergeClasses,

        % This is a very important (and very speculative) guess that's required to make a lot of
        % forward progress. :-( It's a very likely source of backtracking.  Its relationship with
        % guessing constructors is very unclear.  We probably need to have a fairly complete set of
        % constructors to derive base class relationships which prevent bad no-base guesses.
        guessClassHasNoBase,

        % Guess some less likely constructors after having finished reasoning through the likely
        % implications of the inheritance of the more likely constuctor guesses.
        guessUnlikelyConstructor,

        % This guess was move to almost last because in the case of overlapping VFTables, there's a
        % lot of bad guesses that are very confusing.  Alternatively, we could choose not to make
        % guesses that do not overlap with _possible_ tables initially, and then later make more
        % speculative guesses that do.  These guesses probably don't drive a lot of logic
        % currently, but could drive more later (we're currently lacking good rules limiting the
        % relationships between virtual methods).
        guessVFTableEntry,

        % This shuold probably be the very last guess because a lot of it is pretty arbitrary.
        % Alternatively we could break the different ways of proposing guesses into different rules
        % and make higher confidence guesses earlier and lower confidence guesses later.  Right
        % now, that's handled by clause ordering within this one rule, which precludes us from
        % splitting it up.
        guessMergeClasses,

        % Only after we've merged all the methods into the classes should we take wild guesses
        % at real destructors.
        guessFinalDeletingDestructor
        % RealDestructorChange! (uncomment next line and add comma above)
        %guessFinalRealDestructor
      ]).

% Actually check to see if the solution is complete.
checkCompleteness :-
    loginfo('Checking for completeness...'),
    not(completeClassHasNoSpecificBase),
    loginfoln('passed').

% Solve when guessing is disabled
solve :-
    guessingDisabled,
    (!,
    loginfoln('Reasoning about object oriented constructs based on known facts ...'),
    reasonForwardAsManyTimesAsPossible,
    sanityChecks,
    loginfoln('No plausible guesses remain, finalizing answer.');
    logfatalln('No complete solution was found!')).

% Solve when guessing is enabled
solve :-
    !,
    (
    loginfoln('Reasoning about object oriented constructs based on known facts ...'),
    reasonForwardAsManyTimesAsPossible,
    loginfoln('Making new hypothetical guesses ...'),
    reasoningLoop,
    loginfoln('No plausible guesses remain, finalizing answer.');
    logfatalln('No complete solution was found!')).

solve(X) :-
    load_dyn(X),
    solve.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
