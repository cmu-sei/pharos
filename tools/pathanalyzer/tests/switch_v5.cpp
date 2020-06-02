// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include "test.hpp"

int main() {
  path_start();

  char c = CHAR_RAND;
  volatile int x = 1;

  // When presented with lots of non-contiguous cases that have a
  // small number of code blocks, Microsoft Visual Studio (but
  // apparently not GCC) will generate two tables for a switch, with
  // one containing offsets into the other.  Let's try to trigger that
  // behavior.

  switch (c) {
   case 'b':
   case 'd':
   case 'h':
   case 'k':
   case 's':
   case 'w':
   case 'B':
   case 'D':
   case 'H':
   case 'K':
   case 'S':
   case 'W':
   case '1':
   case '3':
   case '%':
   case '.':
   case ',':
    x = 5;
    break;
   case 'c':
   case 'e':
   case 'g':
   case 'i':
   case 't':
   case 'C':
   case 'E':
   case 'G':
   case 'I':
   case 'T':
   case '2':
   case '4':
   case '@':
   case '~':
   case ':':
    x = 3;
    // fallthru
   case 'a':
   case 'l':
   case 'n':
   case 'p':
   case 'u':
   case 'z':
   case 'A':
   case 'L':
   case 'N':
   case 'P':
   case 'U':
   case 'Z':
   case '5':
   case '8':
   case '*':
   case '^':
   case '[':
   case '(':
   case '{':
    x = x + 2;
    break;
   case 'f':
   case 'x':
   case 'm':
   case 'o':
   case 'r':
   case 'F':
   case 'X':
   case 'M':
   case 'O':
   case '6':
   case '0':
   case '#':
   case ')':
   case ']':
   case '}':
    x = 7;
    break;
   case 'j':
   case 'q':
   case 'y':
   case 'v':
   case 'J':
   case 'Q':
   case 'Y':
   case 'V':
   case '7':
   case '9':
   case ';':
   case '$':
    x = 9;
    break;
   default:
    x = 13;
    break;
  }

  if (x == 7) {
    path_goal();
  }
  // All answers are odd.
  else if (x == 4) {
    path_nongoal();
  }
}
