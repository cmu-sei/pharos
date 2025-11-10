#!/usr/bin/env swipl

% Copyright 2020-2021 Carnegie Mellon University.
% ============================================================================================
% User-level driver for oorules functionality
% ============================================================================================

:- use_module(library(optparse), [opt_parse/4, opt_help/2]).
:- use_module(library(option), [dict_options/2, option/2]).
:- use_module(library(lists), [append/3]).
:- use_module(library(prolog_stack)).

:- dynamic file_search_path/2.
:- multifile file_search_path/2.
:- prolog_load_context(directory, Dir),
   assert(base_directory(Dir)).

:- dynamic globalHalt/0 as opaque.
:- dynamic runOptions/1.

:- initialization(main, main).

nohalt :-
    set_prolog_flag(toplevel_goal, prolog).

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

%% Fallback: Try install oorules location, followed by same directory as this file,
%% followed by CWD
setup_oorules_path(_) :-
    base_directory(Dir), !,
    working_directory(CWD, CWD),
    atomic_list_concat([Dir, '../share/pharos/prolog/oorules'], '/', RulesDir),
    absolute_file_name(RulesDir, AbsRulesDir),
    assertz(file_search_path(pharos, AbsRulesDir)),
    assertz(file_search_path(pharos, Dir)),
    assertz(file_search_path(pharos, CWD)).

:- if(exists_source(library(yaml))).

:- use_module(library(yaml), [yaml_read/2]).

yaml_config(Opts) :-
    check_option(config(Config), Opts),
    handle_yaml_file(Config, Opts).

yaml_config(Opts) :-
    getenv('HOME', Home),
    atomic_list_concat([Home, '.pharos.yaml'], '/', Config),
    handle_yaml_file(Config, Opts).

yaml_config(Opts) :-
    base_directory(Dir), !,
    atomic_list_concat([Dir, '../etc', 'pharos.yaml'], '/', Config),
    absolute_file_name(Config, AbsConfig),
    handle_yaml_file(AbsConfig, Opts).

yaml_config(Opts) :-
    getenv('PHAROS_CONFIG', Config),
    handle_yaml_file(Config, Opts).

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
       get_dict('prolog_rules_dir', Pharos, RawDir), !);
     ( get_dict('pharos', Dict, Pharos),
       get_dict('prolog_rules_dir', Pharos, RawDir))),
    (sub_atom(RawDir, 0, 1, _, '/') -> Dir = RawDir ;
     sub_atom(RawDir, 0, 1, _, _) ->
         (base_directory(BaseDir),
          atomic_list_concat([BaseDir, '../share/pharos', RawDir], '/', CDir),
          absolute_file_name(CDir, Dir))).

:- else.
yaml_config(_) :- false.
:- endif.

exit_failure :-
    nl(user_error),
    usage(user_error, 1).

ooprolog_opts_spec(
    [
      [opt(facts), longflags([facts]), shortflags(['f']),
       type(atom), help('input facts file')],
      [opt(json), longflags([json]), shortflags(['j']),
       type(atom), help('output path for json file')],
      [opt(results), longflags([results]), shortflags(['r']),
       type(atom), help(['path for Prolog results',
                         'output when used with --facts',
                         'input when not used with --facts'])],

      [opt(ground), longflags([ground]), shortflags(['g']),
       type(atom), help('input path for ground truth')],
      [opt(rtti), longflags([rtti]), shortflags(['R']), type(boolean),
       default(true), help('enable RTTI analysis')],
      [opt(guess), longflags([guess]), shortflags(['G']), type(boolean),
       default(true), help('enable guessing')],
      [opt(loglevel), longflags(['log-level']), shortflags([l]),
       type(integer), default(3), help('logging level (0-7)')],

      [opt(config), longflags([config]), shortflags(['C']), type(atom),
       help('pharos YAML config file')],
      [opt(stacklimit), longflags(['stack-limit']), shortflags(['S']),
       type(integer), default(200_000_000_000), help('stack limit in bytes')],
      [opt(tablespace), longflags(['table-space']), shortflags(['T']),
       type(integer), default(200_000_000_000), help('table space in bytes')],
      [opt(oorulespath), longflags(['library-path']), shortflags(['P']),
       type(atom), help('path to prolog rules')],
      [opt(halt), longflags([halt]), shortflags(['H']), type(boolean),
       default(true), help('halt after execution')],
      [opt(load_only), longflags([load_only]), shortflags(['L']), type(boolean),
       default(false), help('only load the code')],

      [opt(help), longflags([help]), shortflags(['h']), type(boolean),
       help('output this message')]
    ]).

usage(Stream, Status) :-
    ooprolog_opts_spec(OptsSpec), !,
    opt_help(OptsSpec, HelpMessage),
    with_output_to(
        Stream,
        (writeln('Usage: ooprolog.pl [--facts <file> | --results <file>] [options]'),
         nl,
         writeln('If the --facts option is specified, read the facts and generate the'),
         writeln('results.  Otherwise, if --results option is specified, read previously'),
         writeln('generated results instead.  Remaining options control various aspects'),
         writeln('of the result generation process and create additional outputs.'),
         nl,
         write(user_error, HelpMessage))),
    halt(Status).

set_limit_flag(Flag, Value) :-
    catch(set_prolog_flag(Flag, Value), error(permission_error(limit, Thing, Val), _Context),
          (format(user_error, 'Limiting ~q to ~q is not allowed by SWI Prolog.~n',
                  [Thing, Val]), halt(1))).

parse_options(OptsSpec, Args, Opts, Positional) :-
    %% opt_parse/4 outputs the option help to user_error when an unknown option is passed.  The
    %% setup_call_cleanup/3 below resets user_error to a null stream during the call and
    %% restores it afterward.
    setup_call_cleanup(
        (set_stream(user_error, alias(saved_user_error)),
         open_null_stream(Null),
         set_stream(Null, alias(user_error))),
        catch(opt_parse(OptsSpec, Args, Opts, Positional), E, true),
        (set_stream(saved_user_error, alias(user_error)),
         close(Null))),
    (var(E), ! ;
     ignore((E = error(domain_error(flag_value, Flag), _),
             format(user_error, 'ERROR: Unknown option ''~a''~n', Flag))),
     exit_failure).

run_with_backtrace(X) :-
    catch_with_backtrace(
        X, Exception,
        (print_message(error, Exception), (globalHalt -> halt(1) ; true))).

main :-
    set_prolog_flag(color_term, true),
    current_prolog_flag(argv, Argv),
    source_file(main, Script),
    catch(main([Script|Argv]), E,
          (print_message(error, E), halt(1))).

main([Script|Args]) :-
    ooprolog_opts_spec(OptsSpec), !,
    parse_options(OptsSpec, Args, Opts, Positional),
    option(help(Help), Opts),
    (var(Help), ! ; usage(user_error, 0)),
    main([script(Script)|Opts], Positional).

main(_, [H|T]) :-
    format(user_error, 'ERROR: Unexpected extra arguments: ~q~n', [[H|T]]),
    exit_failure.

main([], []) :-
    usage(user_output, 0).

main(Opts, []) :-
    load(Opts),
    (   option(load_only(true), Opts)
    ->  asserta(runOptions(Opts))
    ;   run(Opts)
    ).

load(Opts) :-
    setup_oorules_path(Opts), !,
    option(stacklimit(Stacklimit), Opts),
    option(tablespace(Tablespace), Opts),
    option(rtti(RTTI), Opts),
    option(guess(Guess), Opts),
    (   option(halt(true), Opts),
        \+ option(load_only(true), Opts)
    ->  assert(globalHalt)
    ;   nohalt
    ),
    option(loglevel(Loglevel), Opts),
    set_limit_flag(stack_limit, Stacklimit),
    set_limit_flag(table_space, Tablespace),
    assert(logLevel(Loglevel)),
    consult([pharos(report), pharos(oojson), pharos(validate)]),
    ignore(check_option(oorulespath(Path), Opts) ->
               asserta(file_search_path(pharos, Path))),
    ignore(RTTI -> assert(rTTIEnabled)),
    (Guess, ! ; assert(guessingDisabled)).

run :-
    runOptions(Opts),
    run(Opts).

run(Opts) :-
    generate_results(Opts),
    generate_json(Opts),
    validate_results(Opts).

%% Generate results when there is a facts file
generate_results(Opts) :-
    check_option(facts(Facts), Opts),
    option(results(Results), Opts), !,
    load_ground(Opts),
    (   current_prolog_flag(break_level, _) % interactive session
    ->  psolve_no_halt(Facts)
    ;   setup_call_cleanup(
            open(Facts, read, FactStream),
            setup_call_cleanup(
                (var(Results) -> open_null_stream(ResultStream) ;
                open(Results, write, ResultStream)),
                with_output_to(ResultStream,
                               run_with_backtrace(psolve_no_halt(stream(FactStream)))),
                close(ResultStream)),
            close(FactStream))
    ).

%% Load results when there isn't a facts file
generate_results(Opts) :-
    check_option(results(Results), Opts), !,
    loadResults(Results).

%% No facts; no results
generate_results(_) :-
    writeln(user_error, 'ERROR: Either a --facts or a --results option is required'),
    exit_failure.

%% Generate JSON when the option exists
generate_json(Opts) :-
    check_option(json(JsonFile), Opts) ->
        run_with_backtrace(exportJSONTo(JsonFile))
    ; true.

load_ground(Opts) :-
    check_option(ground(Ground), Opts) ->
        setup_call_cleanup(
            open(Ground, read, Stream),
            run_with_backtrace(
                loadPredicates(stream(Stream))
                ),
            close(Stream))
    ; true.

%% If there is a ground option, validate results
validate_results(Opts) :-
    check_option(ground(_Ground), Opts) ->
        (load_ground(Opts),
         validateResults)
    ; true.

/* Local Variables:   */
/* mode: prolog       */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
