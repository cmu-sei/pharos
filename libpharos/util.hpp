// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Utility_H
#define Pharos_Utility_H

#include <string>
#include <rose.h>

// This file should be as minimal as possible to reduce circular inclusion pain.  If something
// you want to add here requires additional ROSE headers, try adding it to misc instead.  If it
// requires data types we've created, try adding it to one of the other files.

#define LEND std::endl

// For marking parameters and functions as unused (and supressing the warnings).
#define UNUSED __attribute__((unused))

// Return the default word size on the architecture.  This is hopefully the beginning of a more
// rational way of handling 32-bit and 64-bit code.  It will at least mark places where we need
// to think harder about this in the future.  Cory now realizes that these should probably be
// on the global descriptor set so that there can be different answers for each file analyzed.
inline size_t get_arch_bits() { return 32; }
inline size_t get_arch_bytes() { return 4; }

// A helper function for the mess that is stack delta constants (More at the implementation).
bool filter_stack(rose_addr_t addr);

// Convert an SgUnsignedCharList into a hex C++ string.
std::string MyHex(const SgUnsignedCharList& data);
std::string get_file_contents(const char *filename);
uint64_t parse_number(const std::string& str);
std::string to_lower(const std::string& input);
std::string md5_hash(const std::string& input);
std::string to_hex(const std::string& input);
std::string addr_str(rose_addr_t addr);

// Are we on a color terminal?
bool color_terminal();

// This was a function created by Wes in several different classes.  It would have a nicer
// interface if it returned a string and the user could choose to print it to std::cout, but
// that's not how it was originally implemented. :-(
void dump_hex(char *buff, size_t len);

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
