:- [report].
:- [setup].

:- import error_writeln/1 from standard.

:- dynamic default_user_error_handler/1.
default_user_error_handler(X) :-
    error_writeln(['Aborting due to error: ', X]),halt(1).

run(X) :-
    solve(X),reportResults,halt.
