% ============================================================================================
% Compile-time tracing based on log level
% ============================================================================================

% The goal of this file is to enable compile-time transformations so we
% can leave very expensive debugging statements in the code without
% incurring a runtime cost.  Because SWI compiles at load time, you can
% just set the logLevel parameter as normal.

% XXX: Right now this module only looks for traceAtLevel/2 calls, but
% we should also teach it to remove log/2 calls.  This is a little
% more complicated because we also have to consider calls to
% logwarn/etc. too.

:- include('logging').

:- use_module(library(apply), [maplist/3]).

transform_trace_statements(X, Y) :-
    is_list(X),
    maplist(transform_trace_statements, X, Y).

transform_trace_statements(X, O) :-
    compound(X),
    X =.. [traceAtLevel, L, G],
    % We don't want to match the default implementation of traceAtLevel!
    nonvar(G),
    (logLevelEnabled(L) -> O=G; O=true).


transform_trace_statements(X, Y) :-
    compound(X),
    X =.. [P|A],
    transform_trace_statements(A, B),
    Y =.. [P|B].

transform_trace_statements(X, Y) :-
    Y = X.

term_expansion(X, Y) :-
    once(transform_trace_statements(X, Y)).

%% Local Variables:
%% mode: prolog
%% End:
