// Copyright 2021-2022 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Rose_H
#define Pharos_Rose_H

// This file includes rose.h and sets preprocessor definitions based on its contents
#include <rose.h>

#include "version.hpp"

#define PHAROS_ROSE_Z3_RAW_POINTERS_CHANGE 11'058'0008ul
#if PHAROS_ROSE_Z3_RAW_POINTERS_CHANGE <= PHAROS_ROSE_MINIMUM_VERSION
#  error "This hack is now always true.  Remove the hack and make it permanent."
#endif
#define PHAROS_ROSE_Z3_RAW_POINTERS_HACK (ROSE_VERSION >= PHAROS_ROSE_Z3_RAW_POINTERS_CHANGE)

#define PHAROS_ROSE_MEMOIZATION_CHANGE 11'058'0008ul
#if PHAROS_ROSE_MEMOIZATION_CHANGE <= PHAROS_ROSE_MINIMUM_VERSION
#  error "This hack is now always true.  Remove the hack and make it permanent."
#endif
#define PHAROS_ROSE_MEMOIZATION_HACK (ROSE_VERSION >= PHAROS_ROSE_MEMOIZATION_CHANGE)

#define PHAROS_ROSE_VARIABLE_ID_CHANGE 11'058'0006ul
#if PHAROS_ROSE_VARIABLE_ID_CHANGE <= PHAROS_ROSE_MINIMUM_VERSION
#  error "This hack is now always true.  Remove the hack and make it permanent."
#endif
#define PHAROS_ROSE_VARIABLE_ID_HACK (ROSE_VERSION >= PHAROS_ROSE_VARIABLE_ID_CHANGE)

#define PHAROS_ROSE_NUMERIC_EXTENSION_CHANGE 11'087'0001ul
#if PHAROS_ROSE_NUMERIC_EXTENSION_CHANGE <= PHAROS_ROSE_MINIMUM_VERSION
#  error "This hack is now always false.  Remove the hack as it is no longer necessary."
#endif
#define PHAROS_ROSE_NUMERIC_EXTENSION_HACK (ROSE_VERSION < PHAROS_ROSE_NUMERIC_EXTENSION_CHANGE)

#define PHAROS_ROSE_SYMBOLIC_SEMANTICS_RENAME 11'087'0003ul
#if PHAROS_ROSE_SYMBOLIC_SEMANTICS_RENAME <= PHAROS_ROSE_MINIMUM_VERSION
#  error "This hack is now always true.  Remove the hack and make it permanent."
#endif
#define PHAROS_ROSE_SYMBOLIC_EXTENSION_HACK (ROSE_VERSION >= PHAROS_ROSE_SYMBOLIC_SEMANTICS_RENAME)

#define PHAROS_ROSE_REGISTERDICTIONARY_PTR_CHANGE 11'096'0005ul
#if PHAROS_ROSE_SYMBOLIC_SEMANTICS_RENAME <= PHAROS_ROSE_MINIMUM_VERSION
#  error "This hack is now always true.  Remove the hack and make it permanent."
#endif
#define PHAROS_ROSE_REGISTERDICTIONARY_PTR_HACK (ROSE_VERSION >= PHAROS_ROSE_REGISTERDICTIONARY_PTR_CHANGE)

#endif // Pharos_Rose_H
