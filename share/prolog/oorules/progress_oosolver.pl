% Copyright 2017 Carnegie Mellon University.

% Call back into the progress predicate exposed by libpharos.
progress(X) :-
  % If we're logging at INFO or above, also print the number of facts periodically.
  loginfo('There are '), loginfo(X), loginfoln(' known facts.'),
  oosolver:progress(X).

log(Importance, Message) :-
  pharos:log(Importance, Message).

logln(Importance, Message) :-
  pharos:logln(Importance, Message).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
