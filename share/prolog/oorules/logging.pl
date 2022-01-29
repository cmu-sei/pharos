% ============================================================================================
% Debugging and printing.
% ============================================================================================

% Identical to ~p (print) and ~q (writeq), except integers are output in hex
:- format_predicate('P', format_write_hex(_, _)).
:- format_predicate('Q', format_write_hex_quoted(_, _)).

% The behavior of the ~@ format argument changed in SWIPL after 8.5.6.  Prior to that, the
% bindings created by ~@ persisted throughout the rest of the argument list.  It was then
% changed to discard the bindings after evaluation.  Here we override that such that the
% bindings are not discarded.
:- format_predicate('@', format_apply_goal(_, _)).

:- dynamic(logLevel/1).
:- use_module(library(option), [merge_options/3]).

% Convenience methods, since it's easier to type the lowercase predicate name.
logfatal(X) :- baselog('FATAL', X).
logerror(X) :- baselog('ERROR', X).
logwarn(X)  :- baselog('WARN', X).
loginfo(X)  :- baselog('INFO', X).
logdebug(X) :- baselog('DEBUG', X).
logtrace(X) :- baselog('TRACE', X).
logcrazy(X) :- baselog('CRAZY', X).

logfatal(Fmt, Args) :- fmtlog('FATAL', Fmt, Args).
logerror(Fmt, Args) :- fmtlog('ERROR', Fmt, Args).
logwarn(Fmt, Args)  :- fmtlog('WARN', Fmt, Args).
loginfo(Fmt, Args)  :- fmtlog('INFO', Fmt, Args).
logdebug(Fmt, Args) :- fmtlog('DEBUG', Fmt, Args).
logtrace(Fmt, Args) :- fmtlog('TRACE', Fmt, Args).
logcrazy(Fmt, Args) :- fmtlog('CRAZY', Fmt, Args).

logfatalln(X) :- baselogln('FATAL', X).
logerrorln(X) :- baselogln('ERROR', X).
logwarnln(X)  :- baselogln('WARN', X).
loginfoln(X)  :- baselogln('INFO', X).
logdebugln(X) :- baselogln('DEBUG', X).
logtraceln(X) :- baselogln('TRACE', X).
logcrazyln(X) :- baselogln('CRAZY', X).

logfatalln(Fmt, Args) :- fmtlogln('FATAL', Fmt, Args).
logerrorln(Fmt, Args) :- fmtlogln('ERROR', Fmt, Args).
logwarnln(Fmt, Args)  :- fmtlogln('WARN', Fmt, Args).
loginfoln(Fmt, Args)  :- fmtlogln('INFO', Fmt, Args).
logdebugln(Fmt, Args) :- fmtlogln('DEBUG', Fmt, Args).
logtraceln(Fmt, Args) :- fmtlogln('TRACE', Fmt, Args).
logcrazyln(Fmt, Args) :- fmtlogln('CRAZY', Fmt, Args).

% Associate log level strings with numbers.  Perhaps we should alter the C++ API?
numericLogLevel('FATAL', 1).
numericLogLevel('ERROR', 2).
numericLogLevel('WARN', 3).
numericLogLevel('INFO', 4).
numericLogLevel('DEBUG', 5).
numericLogLevel('TRACE', 6).
numericLogLevel('CRAZY', 7).

baselog(Level, X) :-
    fmtlog(Level, '~P', [X]).
baselogln(Level, X) :-
    fmtlog(Level, '~P~n', [X]).

fmtlog(Level, Fmt, Args) :-
    format(atom(Repr), Fmt, Args) -> log(Level, Repr) ; true.
fmtlogln(Level, Fmt, Args) :-
    format(atom(Repr), Fmt, Args) -> logln(Level, Repr) ; true.

% This is a default implementation of traceAtLevel which should never be used because the code
% in goal_expansion/2 below should replace it at load time.
traceAtLevel(_, _) :- throw(system_error).

logLevelEnabled(S) :-
    numericLogLevel(S, OtherLogLevel),
    logLevel(CurrentLogLevel),
    CurrentLogLevel >= OtherLogLevel.

portray_hex(X, _Options) :-
    integer(X),
    (X < 0 -> (Y is X * -1, format('-0x~16r', Y))
    ; (X > 0 -> format('0x~16r', X))).

writeHex(X, Options) :-
    merge_options([portray_goal(portray_hex)], Options, NewOpts),
    write_term(X, NewOpts).

writeHex(X) :-
    writeHex(X, [spacing(next_argument)]).

writeHexQuoted(X) :-
    writeHex(X, [spacing(next_argument), quoted(true)]).

writelnHex(X) :-
    writeHex(X), nl.

% Write to logfatal, logerror, or logwarn instead...
%errwrite(Fmt, Args) :-
%    format(user_error, Fmt, Args).m
%errwriteln(Fmt, Args) :-
%    format(user_error, Fmt, Args), nl(user_error).

format_write_hex(_, X) :-
    writeHex(X).

format_write_hex_quoted(_, X) :-
    writeHexQuoted(X).

format_apply_goal(_, Goal) :-
    call(Goal).

% Enable compile-time transformations so we can leave very expensive debugging statements in
% the code without incurring a runtime cost.  Because SWI compiles at load time, you can just
% set the logLevel parameter as normal.

%% matches log<Level> and log<Level>ln, returning <Level>
logging_atom(Atom, Level) :-
    sub_atom(Atom, 0, _, _, log),
    ((sub_atom(Atom, _, 2, 0, ln),
      sub_atom(Atom, 3, _, 2, LLevel))
    ; sub_atom(Atom, 3, _, 0, LLevel)),
    upcase_atom(LLevel, Level),
    numericLogLevel(Level, _).

noop(_).

baselogname(log).
baselogname(logln).
baselogname(fmtlog).
baselogname(fmtlogln).

%% Uncomment to check for dangerous logging arguments (that might be lists)
%% goal_expansion(Goal, Layout, _, _) :-
%%     Goal =.. [Name, _Fmt, Args],
%%     var(Args),
%%     logging_atom(Name, _),
%%     format(user_error, "Bad Goal: ~Q~nLocation: ~q~n", [Goal, Layout]),
%%     halt(1).

goal_expansion(Goal, Out) :-
    Goal =.. [Name, Level|_],
    baselogname(Name),
    (logLevelEnabled(Level) -> Out = Goal ; Out = true).

%% The rule at HERE subsumes this rule.  But we think this rule is here to avoid warnings about
%% variables being used only once (e.g., because they were deleting by the expansion).  It's
%% unclear if this is a real concern now that we only use SWI and compiling is always done on
%% demand.
goal_expansion(Goal, Out) :-
    Goal =.. [Name, _Fmt, Args],
    logging_atom(Name, Level),
    (logLevelEnabled(Level) -> Out = Goal ; Out = noop(Args)).

%% HERE
goal_expansion(Goal, Out) :-
    functor(Goal, Name, _),
    logging_atom(Name, Level),
    (logLevelEnabled(Level) -> Out = Goal ; Out = true).

goal_expansion(Goal, Out) :-
    Goal =.. [traceAtLevel, Level, G],
    (logLevelEnabled(Level) -> Out=G; Out=true).

%% Local Variables:
%% mode: prolog
%% End:
