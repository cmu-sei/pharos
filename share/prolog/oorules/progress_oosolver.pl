% Copyright 2017 Carnegie Mellon University.

% Call back into the progress predicate exposed by libpharos.
progress(X) :-
    % If we're logging at INFO or above, also print the number of facts periodically.
    loginfo('There are '), loginfo(X), loginfoln(' known facts.'),
    oosolver:progress(X).

% These map Pharos log levels to ROSE log levels.  Everywhere else in Prolog, we should use the
% Pharops log levels.  The mapping to ROSE levels had occur somewhere, and this seemed like the
% cleanest place to do it.
pharos_level_to_rose_level('FATAL', 'FATAL').
pharos_level_to_rose_level('ERROR', 'ERROR').
pharos_level_to_rose_level('WARN', 'WARN').
pharos_level_to_rose_level('INFO', 'INFO').
pharos_level_to_rose_level('DEBUG', 'WHERE').
pharos_level_to_rose_level('TRACE', 'TRACE').
pharos_level_to_rose_level('CRAZY', 'DEBUG').

log(Importance, Message) :-
    pharos_level_to_rose_level(Importance, RoseImportance),
    pharos:log(RoseImportance, Message).

logln(Importance, Message) :-
    pharos_level_to_rose_level(Importance, RoseImportance),
    pharos:logln(RoseImportance, Message).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
