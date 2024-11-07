// Copyright 2021-2024 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Rose_H
#define Pharos_Rose_H

// This file includes rose.h and sets preprocessor definitions based on its contents
#include <rose.h>

#include "version.hpp"

#define PHAROS_ROSE_ADDRESSINTERVAL_CHANGE 11'145'0029ul
#if PHAROS_ROSE_ADDRESSINTERVAL_CHANGE <= PHAROS_ROSE_MINIMUM_VERSION
#  error "This hack is now always true.  Remove the hack and make it permanent."
#endif
#define PHAROS_ROSE_ADDRESSINTERVAL_HACK (ROSE_VERSION >= PHAROS_ROSE_ADDRESSINTERVAL_CHANGE)

#define PHAROS_ROSE_RVA_CHANGE 11'145'0029ul
#if PHAROS_ROSE_RVA_CHANGE <= PHAROS_ROSE_MINIMUM_VERSION
#  error "This hack is now always true.  Remove the hack and make it permanent."
#endif
#define PHAROS_ROSE_RVA_HACK (ROSE_VERSION >= PHAROS_ROSE_RVA_CHANGE)

#define PHAROS_ROSE_UNPARSE_CHANGE 11'145'0167ul
#if PHAROS_ROSE_UNPARSE_CHANGE <= PHAROS_ROSE_MINIMUM_VERSION
#  error "This hack is now always true.  Remove the hack and make it permanent."
#endif
#define PHAROS_ROSE_UNPARSE_HACK (ROSE_VERSION >= PHAROS_ROSE_UNPARSE_CHANGE)

#define PHAROS_ROSE_UNPARSE_BROKEN 11'145'0158ul
#if PHAROS_ROSE_UNPARSE_CHANGE <= PHAROS_ROSE_MINIMUM_VERSION
#  error "This warning should be removed."
#elif ((ROSE_VERSION >= PHAROS_ROSE_UNPARSE_BROKEN) \
       && (ROSE_VERSION < PHAROS_ROSE_UNPARSE_CHANGE))
#  error "Rose versions 0.11.145.158 through 0.11.145.166 are broken.  Please compile against a different version of Rose."
#endif

#endif // Pharos_Rose_H
