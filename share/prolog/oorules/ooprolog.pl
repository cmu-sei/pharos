#!/usr/bin/env swipl

% Copyright 2020 Carnegie Mellon University.
% ============================================================================================
% User-level driver for oorules functionality
% ============================================================================================

:- use_module(library(optparse), [opt_parse/4]).
:- use_module(library(option), [dict_options/2, option/2]).
:- use_module(library(prolog_stack)).

:- dynamic file_search_path/2.
:- multifile file_search_path/2.
:- prolog_load_context(directory, Dir),
   assert(base_directory(Dir)).

:- initialization(main, main).

%% Same as option/2, but fails if the value hasn't been set
check_option(X, O) :-
    option(X, O),
    X =.. [_, Y],
    \+ var(Y).

%% Use path from command-line options to find oorules files
setup_oorules_path(Opts) :-
    check_option(oorulespath(Path), Opts),
    asserta(file_search_path(pharos, Path)).

%% Use path from YAML config to find oorules files
setup_oorules_path(Opts) :-
    yaml_config(Opts), !.

%% Fallback: Try same directory as this file, followed by CWD
setup_oorules_path(_) :-
    base_directory(Dir), !,
    working_directory(CWD, CWD),
    asserta(file_search_path(pharos, CWD)),
    asserta(file_search_path(pharos, Dir)).


:- if(exists_source(library(yaml))).

:- use_module(library(yaml), [yaml_read/2]).

yaml_config(Opts) :-
    check_option(config(Config), Opts),
    handle_yaml_file(Config).

yaml_config(Opts) :-
    getenv('HOME', Home),
    atomic_list_concat([Home, '.pharos.yaml'], '/', Config),
    handle_yaml_file(Config, Opts).

yaml_config(Opts) :-
    base_directory(Dir), !,
    atomic_list_concat([Dir, 'etc', 'pharos.yaml'], '/', Config),
    handle_yaml_file(Config, Opts).

yaml_config(_) :-
    getenv('PHAROS_CONFIG', Config),
    handle_yaml_file(Config).

handle_yaml_file(File, Opts) :-
    prolog_rules_dir_from_yaml(File, Opts, Dir),
    asserta(file_search_path(pharos, Dir)).

prolog_rules_dir_from_yaml(File, Opts, Dir) :-
    exists_file(File),
    yaml_read(File, Dict),
    (( check_option(script(Script), Opts),
       get_dict('application', Dict, Apps),
       get_dict(Script, Apps, App),
       get_dict('pharos', App, Pharos),
       get_dict('prolog_rules_dir', Pharos, Dir));
     ( get_dict('pharos', Dict, Pharos),
       get_dict('prolog_rules_dir', Pharos, Dir))).

:- else.
yaml_config(_) :- false.
:- endif.

exit_failure :-
    halt(1).

main :-
    current_prolog_flag(os_argv, [_Interp|Rest]),
    main(Rest).

main([Script|Args]) :-
    OptsSpec =
    [ [opt(loglevel), longflags(['log-level']), shortflags([l]),
       type(integer), default(3), help('logging level (0-7)')],
      [opt(stacklimit), longflags(['stack-limit']), shortflags(['S']),
       type(integer), default(200_000_000_000), help('stack limit in bytes')],
      [opt(tablespace), longflags(['table-space']), shortflags(['T']),
       type(integer), default(200_000_000_000), help('table space in bytes')],
      [opt(oorulespath), longflags(['library-path']), shortflags(['P']),
       type(atom), help('path to prolog rules')],
      [opt(rtti), longflags([rtti]), shortflags(['R']), type(boolean),
       default(true), help('enable RTTI analysis')],
      [opt(guess), longflags([guess]), shortflags(['G']), type(boolean),
       default(true), help('enable guessing')],
      [opt(halt), longflags([halt]), shortflags(['H']), type(boolean),
       default(true), help('halt after execution')],
      [opt(config), longflags([config]), shortflags(['C']), type(atom),
       help('pharos YAML config file')],

      [opt(facts), longflags([facts]), shortflags(['f']),
       type(atom), help('input facts file')],
      [opt(json), longflags([json]), shortflags(['j']),
       type(atom), help('output path for json file')],
      [opt(results), longflags([results]), shortflags(['r']),
       type(atom), help(['path for result facts',
                         'output when used with --facts',
                         'input when used with --ground'])],
      [opt(ground), longflags([ground]), shortflags(['g']),
       type(atom), help('input path for ground facts file')],
      [opt(help), longflags([help]), shortflags(['h']), type(boolean),
       help('output this message')]
    ],
    opt_parse(OptsSpec, Args, Opts, Positional),
    option(help(Help), Opts),
    (var(Help) ; (opt_help(OptsSpec, HelpMessage), write(user_error, HelpMessage), halt)),
    main([script(Script)|Opts], Positional).

main(_, [H|T]) :-
    format(user_error, 'Unexpected extra arguments: ~q~n', [[H|T]]),
    exit_failure.

main(Opts, []) :-
    check_option(facts(_), Opts),
    check_option(ground(_), Opts),
    format(user_error, 'Cannot use both --facts and --ground options~n', []),
    exit_failure.

main(Opts, []) :-
    setup_oorules_path(Opts), !,
    option(stacklimit(Stacklimit), Opts),
    option(tablespace(Tablespace), Opts),
    option(rtti(RTTI), Opts),
    option(guess(Guess), Opts),
    option(halt(Halt), Opts),
    option(loglevel(Loglevel), Opts),
    set_prolog_flag(stack_limit, Stacklimit),
    set_prolog_flag(table_space, Tablespace),
    assert(logLevel(Loglevel)),
    ignore(check_option(oorulespath(Path), Opts) ->
               asserta(file_search_path(pharos, Path))),
    ignore(RTTI -> assert(rTTIEnabled)),
    (Guess ; assert(guessingDisabled)),
    catch_with_backtrace(
        (check_option(ground(Ground), Opts) -> do_ground(Ground, Opts) ; do_report(Opts)),
        Exception,
        (print_message(error, Exception), (Halt ; break), exit_failure)),
    (Halt; prolog).

do_report(Opts) :-
    check_option(facts(Facts), Opts),
    option(results(Results), Opts),
    ignore(check_option(json(Json), Opts) -> consult(oojson)),
    ignore(var(Results), var(Json),
           format(user_error, 'Cannot determine mode~n', []), exit_failure),
    !,
    consult(report),
    setup_call_cleanup(
        (var(Results) -> open_null_stream(ResultStream) ;
         open(Results, write, ResultStream)),
        with_output_to(ResultStream, psolve_no_halt(Facts)),
        close(ResultStream)),
    (var(Json) ;
     setup_call_cleanup(
         open(Json, write, JsonStream),
         with_output_to(JsonStream, exportJSON),
         close(JsonStream))).

do_report(Opts) :-
    check_option(results(Results), Opts),
    check_option(json(Json), Opts),
    !,
    consult(oojson),
    setup_call_cleanup(
        open(Json, write, JsonStream),
        with_output_to(JsonStream, exportJSON(Results)),
        close(JsonStream)).

do_report(_) :-
    format(user_error, 'Cannot determine mode~n', []), exit_failure.

do_ground(Ground, Opts) :-
    check_option(result(Results), Opts),
    !,
    consult(validate),
    loadAndValidateResults(Results, Ground).

do_ground(_, _) :-
    format(user_error, 'Results necessary for validation~n', []), exit_failure.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */

/* End:               */
