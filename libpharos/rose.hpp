// Copyright 2021 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Rose_H
#define Pharos_Rose_H

// This file includes rose.h and sets preprocessor definitions based on its contents
#include <rose.h>

#include "version.hpp"

#define PHAROS_ROSE_Z3_RAW_POINTERS_CHANGE 110580008ul
#if PHAROS_ROSE_Z3_RAW_POINTERS_CHANGE < PHAROS_ROSE_MINIMUM_VERSION
#  error "The need for this rose version hack no longer exists."
#endif
#define PHAROS_ROSE_Z3_RAW_POINTERS_HACK (ROSE_VERSION >= PHAROS_ROSE_Z3_RAW_POINTERS_CHANGE)

#define PHAROS_ROSE_MEMOIZATION_CHANGE 110580008ul
#if PHAROS_ROSE_MEMOIZATION_CHANGE < PHAROS_ROSE_MINIMUM_VERSION
#  error "The need for this rose version hack no longer exists."
#endif
#define PHAROS_ROSE_MEMOIZATION_HACK (ROSE_VERSION >= PHAROS_ROSE_MEMOIZATION_CHANGE)

#endif // Pharos_Rose_H
