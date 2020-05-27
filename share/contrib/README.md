# User Contributed API Files #

This directory contains API definitions that have been contributed by
users.  In particular, thanks to @janbbeck for making the initial
contributions.

Contributed API data is not loaded by default, but can be added with
the `--apidb` flag.  For example, to load the contributed API data for
`MFC42.dll`, use `--apidb contrib/mfc42.json`.

You can also load these by default by creating a custom `.pharos.yaml`
file.  To do this, use `--dump-config` on any Pharos tool to dump the
default configuration.  Add `contrib/name.json` to the `apidb` list,
and then save the resulting file as `~/.pharos.yaml`, where `~` is
your home directory.
