% SWI

:- set_prolog_flag(optimise, true).

% Web stat stuff

:- multifile
     webstat:stat_series/2,
     webstat:stat_value/2,
     webstat:stat_disabled/1.

% Mallinfo is too expensive on really large programs.
webstat:stat_disabled(mallinfo).

webstat:stat_series(numfacts,
                    _{label: 'Pharos #facts',
                      active:true
                     }).
webstat:stat_series(guesses,
                    _{label: 'Pharos #guesses',
                      active: true
                     }).
webstat:stat_series(reasonForwardSteps,
                    _{label: 'Pharos #reasoningForward steps',
                      active: true
                     }).

webstat:stat_value(numfacts, Value) :-
     get_flag(numfacts, Value).
webstat:stat_value(guesses, Value) :-
     get_flag(guesses, Value).
webstat:stat_value(reasonForwardSteps, Value) :-
     get_flag(reasonForwardSteps, Value).

% Syntax

goal_expansion(not(X), \+(X)).
% the predicate provides a check whether this simplification is correct.
goal_expansion(iso_dif(X,Y), X \= Y).

:- noprofile(('$tabling':start_tabling/3,
              '$tabling':reeval/3,
              '$tabling':try_reeval/3,
              '$tabling':reeval_paths/2,
              '$tabling':reeval_heads/3,
              '$tabling':reeval_node/1,
              '$tabling':create_table/4,
              '$tabling':run_leader/6,
              '$tabling':activate/4,
              '$tabling':delim/4,

              system:(\+)/1,
              system:'$meta_call'/1,
              system:'$meta_call'/3,
              system:reset/3,

              osetof/3,
              or/1,
              or/2
             )).

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
