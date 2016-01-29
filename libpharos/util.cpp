// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

#include <cerrno>
#include <locale>
#include <stdio.h>
#include <stdlib.h>

#include <boost/format.hpp>

// For md5hash()
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>

#include <rose.h>

#include "util.hpp"

// Causes problem for sawyer/Message.h. :-(  For color_terminal() code.
#include <curses.h>
#include <term.h>

// Convert an SgUnsignedCharList into a hex C++ string.  This should perhaps be in misc because
// it uses the ROSE SgUnsignedCharList type.  Then we could make util.cpp be only for things
// that do NOT require ROSE includes.
std::string MyHex(const SgUnsignedCharList& data) {
  char buffer[8];
  std::string result = "";

  size_t n = data.size();
  for (size_t i = 0; i < n; i++) {
    sprintf(buffer, "%02X", data[i]);
    result += buffer;
  }
  return result;
}

// Return true if we're on a color terminal, and false if not.
bool color_terminal() {
  bool color = false;
  int fd = fileno(stdout);
  if (isatty(fd)) {
    int erret = 0;
    if (setupterm(NULL,fd,&erret) != ERR) {
      color = tigetnum((char *)"colors") > 0;
      restartterm(NULL,fd,NULL);
    }
  }
  return color;
}

// Here's a helper function for cleaning up the mess that is stack delta constants.  Because we
// chose to initialize ESP to zero rather than a variable, it's hard to tell what's a stack
// delta and what's a constant address.  The purpose of putting this code here is much like the
// functions above for architecture.  It gives us some specific text to search for to find
// places where we're obviously touching this bit of brokenness.  See also get_stack_const() in
// semantics.hpp.
bool filter_stack(rose_addr_t addr) {
  if (addr > 0x0000FFFF && addr < 0x80000000) return true;
  return false;
}

// This is a horrible hack and should be improved.  Mostly because I have no idea how it
// behaves in exceptional conditons.  But I don't care right now.
uint64_t parse_number(const std::string& str) {
  uint64_t result;
  std::stringstream b;
  b << std::hex << str;
  b >> result;
  return result;
}

// I'm rather shocked that std::string doesn't already provide this.
std::string to_lower(const std::string& input) {
  std::locale loc;
  std::string lowered;
  for (size_t o = 0; o < input.length(); o++)
    lowered += tolower(input[o], loc);
  return lowered;
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

// Compute the md5 hash of a given string.
std::string md5_hash(const std::string& str) {
  // Calculate the MD5 over the bytes
  CryptoPP::Weak::MD5 md5hash;
  byte digest [CryptoPP::Weak::MD5::DIGESTSIZE];
  md5hash.CalculateDigest(digest, (const byte *)str.c_str(), str.length());

  CryptoPP::HexEncoder encoder;
  std::string output;
  encoder.Attach(new CryptoPP::StringSink(output));
  encoder.Put(digest, sizeof(digest));
  encoder.MessageEnd();

  return output;
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

// Cory is trying to enforce some consistency in how we print addresses so that we can control
// the format by changing only one (or at least just a few) places in the code.  There's no
// implicit claim that boost::format("0x%08X") is the "correct" answer, just that there should
// be some consistency, amnd that the whole std::hex / std::dec thing sucks...
std::string addr_str(rose_addr_t addr) {
  return boost::str(boost::format("0x%08X") % addr);
}

// Not the interface to this  that Cory would have chosen, but one thing at a time.
void dump_hex(char *buff, size_t len) {
  for (size_t a = 0; a < len; a++) {
    char b[50];
    sprintf(b,"%.2x",(uint8_t)buff[a]);
    std::cout << b;
  }
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
