% This file is intended to implement "checks" -- Things that we want to test for and report on
% that don't actually affect the reasoning.  The most obvious example would be things that
% should never happen, and that there was no need to check for in the rules as a consequence.
% In fact, adding these clauses in a reasoning rule might produce unexpected results and
% obscure the real problem (unexpected conditions).

checkAssumptions :-
    check.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
