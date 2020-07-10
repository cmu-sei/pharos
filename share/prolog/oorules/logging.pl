% ============================================================================================
% Debugging and printing.
% ============================================================================================

% Convenience methods, since it's easier to type the lowercase predicate name.
logfatal(X) :- log('FATAL', X).
logerror(X) :- log('ERROR', X).
logwarn(X) :- log('WARN', X).
loginfo(X) :- log('INFO', X).
logwhere(X) :- log('WHERE', X).
logdebug(X) :- log('TRACE', X).
logtrace(X) :- log('DEBUG', X).

logfatalln(X) :- logln('FATAL', X).
logerrorln(X) :- logln('ERROR', X).
logwarnln(X) :- logln('WARN', X).
loginfoln(X) :- logln('INFO', X).
logwhereln(X) :- logln('WHERE', X).
logdebugln(X) :- logln('TRACE', X).
logtraceln(X) :- logln('DEBUG', X).

% Associate log level strings with numbers.  Perhaps we should alter the C++ API?
numericLogLevel('FATAL', 1).
numericLogLevel('ERROR', 2).
numericLogLevel('WARN', 3).
numericLogLevel('INFO', 4).
numericLogLevel('WHERE', 5).
numericLogLevel('DEBUG', 6).
numericLogLevel('TRACE', 7).

% This is a default implementation of traceAtLevel which should never be used because the code
% in logging_instrumentation.pl should replace it at compile time.
traceAtLevel(_, _) :- throw(system_error).

logLevelEnabled(S) :-
    numericLogLevel(S, OtherLogLevel),
    logLevel(CurrentLogLevel),
    CurrentLogLevel >= OtherLogLevel.

writeHexList_([X|Rest], Options) :-
    writeHex(X, Options),
    (Rest \= [] -> write(', '), writeHexList_(Rest, Options) ; true).

writeHex(L, Options) :-
    is_list(L), !,
    write('['),
    writeHexList_(L, Options),
    write(']').

writeHex(T, Options) :-
    functor(T, _, Arity), Arity > 0,
    !,
    T =.. [Functor|Arguments],
    write_term(Functor, Options),
    write('('),
    writeHexList_(Arguments, Options),
    write(')').

writeHex(X, Options) :-
    (integer(X), X < 0, iso_dif(X, 0)) ->
        (Y is X * -1,
         format('-0x~16r', [Y]))
    ;
    (integer(X), iso_dif(X, 0)) ->
    format('0x~16r', X)
    ;
    write_term(X, Options).

writeHexTerm(X) :-
    writeHex(X, [quoted(true)]).

writeHex(X) :-
    writeHex(X, []).

writelnHex(X) :-
    writeHex(X),
    writeln('').

errwrite(Term) :-
    write(user_error, Term).
errwriteln(Term) :-
    writeln(user_error, Term).

%% Local Variables:
%% mode: prolog
%% End:
