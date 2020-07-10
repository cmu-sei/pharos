% Copyright 2017 Carnegie Mellon University.
% ============================================================================================
% Rules for testing whether a solution is complete...
% ============================================================================================

% Classes must either have a specific base, or have no base at all.
% PAPER: AmbiguousBase
completeClassHasNoSpecificBase :-
    factConstructor(Constructor),
    find(Constructor, Class),
    not(factClassHasNoBase(Class)),
    not(factDerivedClass(Class, _BaseClass, _ObjectOffset)),
    logwarnln('Solution is incomplete.'),
    logwarn('completeClassHasNoSpecificBase failed:'),
    logwarn(' Ctor='), logwarn(Class),
    logwarnln('').

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
