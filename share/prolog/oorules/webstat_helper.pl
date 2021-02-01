% ============================================================================================
% Debugging code for webstat/webstat_control
% ============================================================================================

:- dynamic haveSeen/1.

reportStage(X) :- var(X), !, throw(instantiation_error(X)).

:- if(current_predicate(ws_control/2)).
% webstat_Control is loaded

reportStage(X) :- getNextY(Y), reportStage(X, Y).
reportStage(X, Y) :- ws_control(perfchart, marking([label=X,y=Y])).

ws_init :- set_flag(webstat_y, 0.5),
           ws_control(window, perfchart),
           sleep(1),
           ws_control(perfchart, [clear,interval(60),start]).
ws_end :- ws_control(perfchart, [stop]).
yDelta(0.3).
getNextY(NextY) :- get_flag(webstat_y, Y),
                   yDelta(YD),
                   Y2 is Y + YD,
                   (Y2 >= 12 -> NextY=0.0; NextY=Y2),
                   set_flag(webstat_y, NextY).


:- else.

reportStage(X) :- loginfoln('Entering stage ~Q.', [X]).
reportStage(X, _) :- reportStage(X).

ws_init.

ws_control(perfchart, _).


:- endif.

reportFirstSeen(X) :- var(X), !, throw(instantiation_error(X)).
reportFirstSeen(X) :- haveSeen(X), !.
reportFirstSeen(X) :- assert(haveSeen(X)), reportStage(X).

%% Local Variables:
%% mode: prolog
%% End:
