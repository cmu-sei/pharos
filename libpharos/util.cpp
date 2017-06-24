// Copyright 2015-2017 Carnegie Mellon University.  See LICENSE file for terms.

#include <cerrno>
#include <locale>
#include <stdio.h>
#include <stdlib.h>

#include "md5.hpp"
#include "util.hpp"
#include "options.hpp"

// Causes problem for sawyer/Message.h. :-(  For color_terminal() code.
#include <curses.h>
#include <term.h>

namespace pharos {

// Return true if we're on a color terminal, and false if not.
bool color_terminal() {
  bool color = false;
  if (isatty(global_logging_fileno)) {
    int erret = 0;
    if (setupterm(NULL,global_logging_fileno,&erret) != ERR) {
      color = tigetnum((char *)"colors") > 0;
      restartterm(NULL,global_logging_fileno,NULL);
    }
  }
  return color;
}

// Parse hexadecimal numbers
uint64_t parse_number(const std::string& str) {
  std::size_t pos;
  uint64_t retval =  std::stoull(str, &pos, 16);
  if (pos != str.size()) {
    auto loc = std::find_if_not(std::begin(str) + pos, std::end(str),
                                [](char c){ return std::isblank(c);});
    if (loc == std::end(str)) {
      throw std::invalid_argument("Invalid hexadecimal string");
    }
  }
  return retval;
}

// I'm rather shocked that std::string doesn't already provide this.
std::string to_lower(std::string input) {
  boost::algorithm::to_lower(input);
  return input;
}

// Read an entire file into a string.
// Initialy wanted for tokenizing a config file.
std::string get_file_contents(const char *filename) {
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  if (in) {
    std::string contents;
    in.seekg(0, std::ios::end);
    contents.resize(in.tellg());
    in.seekg(0, std::ios::beg);
    in.read(&contents[0], contents.size());
    in.close();
    return (contents);
  }
  throw(errno);
}

// Compute the md5 hash of the bytes in a given string.
std::string get_string_md5(const std::string& str) {
  return MD5(str).finalize().str();
}

// md5 of file contents
std::string get_file_md5(const std::string& fname) {
  return MD5::from_file(fname).str();
}


// Convert a string of binary bytes to an ASCII hexadecimal representation. Thanks to
// StackOverflow.com. :-)
std::string to_hex(const std::string& input)
{
  static const char* const lut = "0123456789ABCDEF";
  size_t len = input.length();

  std::string output;
  output.reserve(2 * len);
  for (size_t i = 0; i < len; ++i) {
    const unsigned char c = input[i];
    output.push_back(lut[c >> 4]);
    output.push_back(lut[c & 15]);
  }
  return output;
}

// Not the interface to this  that Cory would have chosen, but one thing at a time.
void dump_hex(char *buff, size_t len) {
  for (size_t a = 0; a < len; a++) {
    char b[50];
    sprintf(b,"%.2x",(uint8_t)buff[a]);
    std::cout << b;
  }
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
